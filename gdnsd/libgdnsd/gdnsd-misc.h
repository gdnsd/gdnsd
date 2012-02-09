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

// Returns directory path set above, always /-terminated.
F_PURE
const char* gdnsd_get_cfdir(void);

// Ensure filename fn is absolute, prepending directory absdir if not.
// Returns new storage the caller owns regardless.
F_NONNULL
char* gdnsd_make_abs_fn(const char* absdir, const char* fn);

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
