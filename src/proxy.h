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

#ifndef GDNSD_PROXY_H
#define GDNSD_PROXY_H

#include <gdnsd/net.h>

#include <inttypes.h>
#include <stddef.h>

// We need this for alignment / structure defs in dnsio_tcp
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
    } v2;
} proxy_hdr_t;

// retval:
// 0: failure
// 1+: PROXY header was this many bytes (<= dlen), please skip past them
// Note this mutates "sa", overwriting it with the client IP:port info
// supplied by the PROXY protocol.
size_t proxy_parse(gdnsd_anysin_t* sa, proxy_hdr_t* hdrp, size_t dlen);

#endif
