/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
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

#ifndef GDNSD_NET_H
#define GDNSD_NET_H

// For sockaddr structs
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdbool.h>

#include <gdnsd/compiler.h>

/* Socket union type */
// note anonymous union here, which gcc has supported
//  forever, and is now becoming standard in C11
typedef struct {
    union {
        struct sockaddr_in6 sin6;
        struct sockaddr_in  sin;
        struct sockaddr     sa;
    };
    socklen_t len;
} anysin_t;

#define ANYSIN_MAXLEN sizeof(struct sockaddr_in6)

// transforms addr_txt + port_txt -> result using getaddrinfo(), setting result->len
// input text fields must be numeric, not hostnames or port names.
// caller must allocate result to sizeof(anysin_t)
// port can be NULL, in which case the proto-specific port field will be zero
// retval is retval from getaddrinfo() itself (if non-zero, error occurred and
//   string representation is available from gai_strerror()).
// result is unaffected if an error occurs.
int gdnsd_anysin_getaddrinfo(const char* addr_txt, const char* port_txt, anysin_t* result);

// As above, but for parsing the address and port from a single string of the form addr:port,
//   where :port is optional, and addr may be surround by [] (to help with ipv6 [::1]:53 issues).
// Port defaults to unsigned arg "def_port" if not specified in the input string.
int gdnsd_anysin_fromstr(const char* addr_port_text, const unsigned def_port, anysin_t* result);

// Check if the sockaddr is the V4 or V6 ANY-address (0.0.0.0, or ::)
bool gdnsd_anysin_is_anyaddr(const anysin_t* asin);

// Plugins should use these to get protocol numbers, since
//  many platforms require filesystem access outside of the
//  runtime chroot() for them.
F_PURE
int gdnsd_getproto_udp(void);
F_PURE
int gdnsd_getproto_tcp(void);

// Whether IPv6 TCP sockets can be instantiated at all (good check
//   for runtime IPv6 support in the kernel)
F_PURE
bool gdnsd_tcp_v6_ok(void);

#endif // GDNSD_NET_H
