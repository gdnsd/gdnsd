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

typedef union {
    struct {
        char line[108];
    } v1;
    struct {
        uint8_t sig[12];
        uint8_t ver_cmd;
        uint8_t fam;
        uint16_t len;
        union {
            struct {
                uint32_t src_addr;
                // cppcheck-suppress unusedStructMember
                uint32_t dst_addr;
                uint16_t src_port;
                // cppcheck-suppress unusedStructMember
                uint16_t dst_port;
            } ipv4;
            struct {
                uint8_t  src_addr[16];
                // cppcheck-suppress unusedStructMember
                uint8_t  dst_addr[16];
                uint16_t src_port;
                // cppcheck-suppress unusedStructMember
                uint16_t dst_port;
            } ipv6;
        };
        // TLVs are unbounded up to ~64K of data, but we're not going to
        // support more than a reasonable small limit for now.  We have to
        // declare something here that covers them so that the initial MSG_PEEK
        // covers the entirety of the PROXY message and gaurantees that the
        // consuming recv of the skip_read bytes at the bottom will be
        // successful.
        // cppcheck-suppress unusedStructMember
        uint8_t tlvs[384];
    } v2;
} proxy_hdr_t;

F_NONNULL
static int parse_proxy_v1(char* v1, const size_t pktlen, gdnsd_anysin_t* asin)
{
    gdnsd_assert(pktlen >= 8U);
    gdnsd_assert(pktlen <= sizeof(proxy_hdr_t));
    gdnsd_assert(!memcmp(v1, "PROXY ", 6));

    char* end = memchr(v1, '\r', pktlen - 1U);
    if (unlikely(!end || end[1] != '\n' || (end - v1) < 16)) {
        log_debug("Proxy v1 parse from %s failed: no CRLF found or line too short", logf_anysin(asin));
        return -1;
    }
    *end = '\0'; // terminate whole string

    const char* proto = &v1[6]; // just after "PROXY "
    if (unlikely(memcmp(proto, "TCP4 ", 5U) && memcmp(proto, "TCP6 ", 5U))) {
        log_debug("Proxy v1 parse from %s failed: protocol must be TCP4 or TCP6", logf_anysin(asin));
        return -1;
    }

    char* srcaddr = &v1[11]; // just after "TCPx "
    char* dstaddr = strchr(srcaddr, ' ');
    if (unlikely(!dstaddr || dstaddr >= end)) {
        log_debug("Proxy v1 parse from %s failed: cannot find dest addr", logf_anysin(asin));
        return -1;
    }
    *dstaddr = '\0'; // terminate srcaddr
    dstaddr++;
    char* srcport = strchr(dstaddr, ' ');
    if (unlikely(!srcport || srcport >= end)) {
        log_debug("Proxy v1 parse from %s failed: cannot find source port", logf_anysin(asin));
        return -1;
    }
    *srcport = '\0'; // terminate dstaddr
    srcport++;
    char* dstport = strchr(srcport, ' ');
    if (unlikely(!dstport || dstport >= end)) {
        log_debug("Proxy v1 parse from %s failed: cannot find dest port", logf_anysin(asin));
        return -1;
    }
    *dstport = '\0'; // terminate srcport

    const int addr_err = gdnsd_anysin_getaddrinfo(srcaddr, srcport, asin);
    if (unlikely(addr_err)) {
        log_debug("Proxy v1 parse from %s: getaddrinfo('%s', '%s') failed: %s",
                  logf_anysin(asin), srcaddr, srcport, gai_strerror(addr_err));
        return -1;
    }

    gdnsd_assert(end >= v1);
    const size_t skip_read = (size_t)(end + 2 - v1); // skip header through CRLF
    gdnsd_assert(skip_read <= sizeof(proxy_hdr_t));
    return (int)skip_read;
}

// retval:
// -1: failed
// 0: success
// 1: recv would block, go back to eventloop
int parse_proxy(int fd, gdnsd_anysin_t* asin)
{
    size_t skip_read = 0;
    proxy_hdr_t hdr;

    const ssize_t recvrv = recv(fd, &hdr, sizeof(hdr), MSG_PEEK);
    if (unlikely(recvrv < 1)) {
        if (unlikely(!recvrv || (recvrv < 0 && !ERRNO_WOULDBLOCK))) {
            log_debug("Proxy proto recv from %s failed: %s",
                      logf_anysin(asin),
                      (recvrv < 0) ? logf_errno() : "unexpected EOF");
            return -1;
        }
        return 1;
    }
    const size_t pktlen = (size_t)recvrv;

    if (pktlen >= 16U && likely(memcmp(&hdr.v2.sig, proxy_v2sig, 12) == 0)
            && likely((hdr.v2.ver_cmd & 0xF0) == 0x20)) {
        skip_read = 16U + ntohs(hdr.v2.len);
        if (unlikely(pktlen < skip_read)) {
            log_debug("Proxy v2 parse from %s failed: len %zu < size %zu (too much TLV data?)",
                      logf_anysin(asin), pktlen, skip_read);
            return -1;
        }

        const uint8_t cmd = hdr.v2.ver_cmd & 0xF;
        if (likely(cmd == 0x01)) { // cmd: PROXY
            gdnsd_anysin_t* a = asin;
            if (hdr.v2.fam == 0x11 && skip_read >= (16U + 12U)) { // TCPv4
                memset(a, 0, sizeof(*a));
                a->sin.sin_family = AF_INET;
                a->sin.sin_addr.s_addr = hdr.v2.ipv4.src_addr;
                a->sin.sin_port = hdr.v2.ipv4.src_port;
            } else if (hdr.v2.fam == 0x21 && skip_read >= (16U + 36U)) { // TCPv6
                memset(a, 0, sizeof(*a));
                a->sin6.sin6_family = AF_INET6;
                memcpy(&a->sin6.sin6_addr, hdr.v2.ipv6.src_addr, 16U);
                a->sin6.sin6_port = hdr.v2.ipv6.src_port;
            } else {
                log_debug("Proxy v2 parse from %s failed: family %hhu total header len %zu",
                          logf_anysin(asin), hdr.v2.fam, skip_read);
                return -1;
            }
        } else if (cmd != 0x00) { // cmd not LOCAL
            log_debug("Proxy v2 parse from %s failed: unknown command %hhu",
                      logf_anysin(asin), cmd);
            return -1;
        }
    } else if (pktlen >= 8U && likely(memcmp(hdr.v1.line, "PROXY ", 6) == 0)) {
        const int v1rv = parse_proxy_v1(hdr.v1.line, pktlen, asin);
        if (v1rv < 0)
            return -1;
        skip_read = (size_t)v1rv;
    } else {
        log_debug("Proxy parse from %s failed: not v1 or v2", logf_anysin(asin));
        return -1;
    }

    // consume the proxy header part of the bytes we MSG_PEEKed at earlier, should not fail
    const ssize_t skiprv = recv(fd, &hdr, skip_read, 0);
    if (unlikely(skiprv != (ssize_t)skip_read)) {
        log_debug("Proxy header discard of %zu bytes failed with retval %zi", skip_read, skiprv);
        return -1;
    }

    return 0;
}
