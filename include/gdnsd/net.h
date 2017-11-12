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

#include <gdnsd/compiler.h>
#include <gdnsd/dmn.h>

#include <stdbool.h>

// We always use numeric_only=true in gdnsd
#define gdnsd_anysin_getaddrinfo(__a,__p,__r) dmn_anysin_getaddrinfo((__a),(__p),(__r),true)
#define gdnsd_anysin_fromstr(__a,__d,__r) dmn_anysin_fromstr((__a),(__d),(__r),true)

#if EAGAIN == EWOULDBLOCK
#  define ERRNO_WOULDBLOCK (errno == EAGAIN)
#else
#  define ERRNO_WOULDBLOCK (errno == EAGAIN || errno == EWOULDBLOCK)
#endif

#pragma GCC visibility push(default)

// Plugins should use these to get protocol numbers
F_PURE
int gdnsd_getproto_udp(void);
F_PURE
int gdnsd_getproto_tcp(void);

// Whether SO_REUSEPORT seems to be a runtime-valid sockopt
F_PURE
bool gdnsd_reuseport_ok(void);

#pragma GCC visibility pop

#endif // GDNSD_NET_H
