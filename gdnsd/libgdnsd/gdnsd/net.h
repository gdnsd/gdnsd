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

#include <stdbool.h>
#include <gdnsd/dmn.h>
#include <gdnsd/compiler.h>

// back-compat for moving some network stuff down to libdmn:
typedef dmn_anysin_t anysin_t;
#define ANYSIN_MAXLEN DMN_ANYSIN_MAXLEN
#define gdnsd_anysin_getaddrinfo(__a,__p,__r) dmn_anysin_getaddrinfo((__a),(__p),(__r),true)
#define gdnsd_anysin_fromstr(__a,__d,__r) dmn_anysin_fromstr((__a),(__d),(__r),true)
#define gdnsd_anysin_is_anyaddr dmn_anysin_is_anyaddr

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
