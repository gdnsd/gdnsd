/* Copyright © 2019 Brandon L Black <blblack@gmail.com>
 *
 * This file is part of gdnsd.
 *
 * gdnsd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * gdnsd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gdnsd.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// All of the actual functional code in this file is obviously heavily derived
// from the example code from haproxy at the bottom of:
// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

#include <config.h>
#include "proxy.h"

#include <gdnsd/compiler.h>
#include <gdnsd/log.h>
#include <gdnsd/net.h>

#include <stddef.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

static const char proxy_v2sig[12] = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

F_NONNULL
static size_t parse_proxy_v1(char* v1, const size_t dlen, gdnsd_anysin_t* sa)
{
    gdnsd_assert(dlen >= 8U);
    gdnsd_assert(!memcmp(v1, "PROXY ", 6));

    char* end = memchr(v1, '\r', dlen - 1U);
    if (unlikely(!end || end[1] != '\n' || (end - v1) < 16)) {
        log_debug("Proxy v1 parse from %s failed: no CRLF found or line too short", logf_anysin(sa));
        return 0;
    }
    *end = '\0'; // terminate whole string

    const char* proto = &v1[6]; // just after "PROXY "
    if (unlikely(memcmp(proto, "TCP4 ", 5U) && memcmp(proto, "TCP6 ", 5U))) {
        log_debug("Proxy v1 parse from %s failed: protocol must be TCP4 or TCP6", logf_anysin(sa));
        return 0;
    }

    char* srcaddr = &v1[11]; // just after "TCPx "
    char* dstaddr = strchr(srcaddr, ' ');
    if (unlikely(!dstaddr || dstaddr >= end)) {
        log_debug("Proxy v1 parse from %s failed: cannot find dest addr", logf_anysin(sa));
        return 0;
    }
    *dstaddr = '\0'; // terminate srcaddr
    dstaddr++;
    char* srcport = strchr(dstaddr, ' ');
    if (unlikely(!srcport || srcport >= end)) {
        log_debug("Proxy v1 parse from %s failed: cannot find source port", logf_anysin(sa));
        return 0;
    }
    *srcport = '\0'; // terminate dstaddr
    srcport++;
    char* dstport = strchr(srcport, ' ');
    if (unlikely(!dstport || dstport >= end)) {
        log_debug("Proxy v1 parse from %s failed: cannot find dest port", logf_anysin(sa));
        return 0;
    }
    *dstport = '\0'; // terminate srcport

    const int addr_err = gdnsd_anysin_getaddrinfo(srcaddr, srcport, sa);
    if (unlikely(addr_err)) {
        log_debug("Proxy v1 parse from %s: getaddrinfo('%s', '%s') failed: %s",
                  logf_anysin(sa), srcaddr, srcport, gai_strerror(addr_err));
        return 0;
    }

    gdnsd_assert(end >= v1);
    const size_t skip_read = (size_t)(end + 2 - v1); // skip header through CRLF
    gdnsd_assert(skip_read);
    gdnsd_assert(skip_read <= sizeof(proxy_hdr_t));
    return skip_read;
}

size_t proxy_parse(gdnsd_anysin_t* sa, proxy_hdr_t* hdrp, size_t dlen)
{
    size_t skip_read = 0;

    if (dlen >= 16U && likely(memcmp(hdrp->v2.sig, proxy_v2sig, 12) == 0)
            && likely((hdrp->v2.ver_cmd & 0xF0) == 0x20)) {
        skip_read = 16U + ntohs(hdrp->v2.len);
        if (unlikely(dlen < skip_read)) {
            log_debug("Proxy v2 parse from %s failed: len %zu < size %zu (too much TLV data and/or non-atomic PROXY?)",
                      logf_anysin(sa), dlen, skip_read);
            return 0;
        }

        const uint8_t cmd = hdrp->v2.ver_cmd & 0xF;
        if (likely(cmd == 0x01)) { // cmd: PROXY
            gdnsd_anysin_t* a = sa;
            memset(a, 0, sizeof(*a));
            if (hdrp->v2.fam == 0x11 && skip_read >= (16U + 12U)) { // TCPv4
                a->sin4.sin_family = AF_INET;
                a->sin4.sin_addr.s_addr = hdrp->v2.ipv4.src_addr;
                a->sin4.sin_port = hdrp->v2.ipv4.src_port;
                a->len = sizeof(struct sockaddr_in);
            } else if (hdrp->v2.fam == 0x21 && skip_read >= (16U + 36U)) { // TCPv6
                a->sin6.sin6_family = AF_INET6;
                memcpy(&a->sin6.sin6_addr, hdrp->v2.ipv6.src_addr, 16U);
                a->sin6.sin6_port = hdrp->v2.ipv6.src_port;
                a->len = sizeof(struct sockaddr_in6);
            } else {
                log_debug("Proxy v2 parse from %s failed: family %hhu total header len %zu",
                          logf_anysin(sa), hdrp->v2.fam, skip_read);
                return 0;
            }
        } else if (cmd != 0x00) { // cmd not LOCAL
            log_debug("Proxy v2 parse from %s failed: unknown command %hhu",
                      logf_anysin(sa), cmd);
            return 0;
        }
    } else if (dlen >= 8U && likely(memcmp(hdrp->v1.line, "PROXY ", 6) == 0)) {
        return parse_proxy_v1(hdrp->v1.line, dlen, sa);
    } else {
        log_debug("Proxy parse from %s failed: not v1 or v2", logf_anysin(sa));
        return 0;
    }

    return skip_read;
}
