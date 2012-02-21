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

#ifndef _GDNSD_MISC_H
#define _GDNSD_MISC_H

#include <gdnsd-compiler.h>
#include <inttypes.h>

// Returns the invocation's data root path (chroot path
//   in the chroot case), e.g. "/usr/local/gdnsd".
// Within this directory, the following paths are fixed:
//   /etc/config        - main config file
//   /etc/zones/        - directory for zonefiles
//   /var/run/gdnsd.pid - daemon pidfile
// After a certain point in the startup process,
F_PURE
const char* gdnsd_get_rootdir(void);

// returns a new string (malloc-based) which is
//   the path concatenation of "suffix" onto the rootdir.
// Suffix must be a hardcoded constant which starts with "/"
//   and does not end with "/".
F_MALLOC F_WUNUSED F_NONNULL
char* gdnsd_make_rootdir_path(const char* suffix);

// As above, but takes second suffix as well, which has
//  no explicit rules, mostly for user-derived input.
// e.g.:
//  gdnsd_make_rootdir_path2("/etc/zones", zone_name);
F_MALLOC F_WUNUSED F_NONNULL
char* gdnsd_make_rootdir_path2(const char* suffix, const char* suffix2);

// After gdnsd_make_rootdir_path[2](), if suffix was based on
//   user input, pass it through here to check for validity.
// If the pathname does not exist, or exits the rootdir via
//   ".." and/or symlinks, this will return NULL.
// Always frees the original input, and a non-NULL return
//   value is a fresh malloc allocation.
F_MALLOC F_WUNUSED F_NONNULL
char* gdnsd_valid_rootpath(char* path_in);

// Returns a newly-malloc'd string which is path_in with
//   the leading rootdir stripped out.  Does not alter
//   path_in.  Code must be sure that the rootdir
//   is a prefix before using, e.g. by using the
//   functions above...
F_MALLOC F_WUNUSED F_NONNULL
char* gdnsd_strip_rootdir(const char* path_in);

// PRNG:
// gdnsd_rand_init() allocates an opaque PRNG state which can
//   be later free()'d when no longer required.
typedef struct _gdnsd_rstate_t gdnsd_rstate_t;
gdnsd_rstate_t* gdnsd_rand_init(void);

// gdnsd_rand_get32(rs) returns uint32_t random numbers
// gdnsd_rand_get64(rs) returns uint64_t random numbers
// You can reduce the ranges via the modulo operator, provided that
//  your modulo values are never too large relative to the overall
//  size. Very large modulos could introduce significant bias in the
//  results.  Of course, perfect power-of-two modulos have no bias.
// In the common case of dynamic modulo values in code, the maximum
//  bias is proportional the maximum modulo your code uses, and the
//  bias can be significant for _get32() cases.
// Examples: max_modulo vs _get32() -> bias
//  2^20 -> 0.02%
//  2^24 -> 0.4%
//  2^28 -> 6.25%
//  2^29 -> 12.5%
//  2^30 -> 25%
//  2^32-1 -> 50%
// Whereas _get64() will have a bias < 0.00000003% for any modulo
//  that's 2^32 or smaller.
uint32_t gdnsd_rand_get32(gdnsd_rstate_t* rs);
uint64_t gdnsd_rand_get64(gdnsd_rstate_t* rs);

#endif // _GDNSD_MISC_H
