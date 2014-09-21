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

#ifndef GDNSD_MISC_H
#define GDNSD_MISC_H

#include <gdnsd/compiler.h>
#include <inttypes.h>
#include <stdbool.h>
#include <pthread.h>
#include <dirent.h>

extern const char gdnsd_lcmap[256];

// downcase an array of bytes of known length
F_NONNULL
static inline void gdnsd_downcase_bytes(char* bytes, unsigned len) {
    for(unsigned i = 0; i < len; i++)
        bytes[i] = gdnsd_lcmap[(uint8_t)bytes[i]];
}

// downcase an asciiz string
F_NONNULL
static inline void gdnsd_downcase_str(char* str) {
    while(*str) {
        *str = gdnsd_lcmap[(uint8_t)*str];
        str++;
    }
}

// allocate a new string, concatenating s1 + s2.
// retval is the new string
// if s2_offs is not NULL, *s2_offs will be set
//   to the offset of the copy of s2 within the retval.
F_MALLOC F_NONNULLX(1,2) F_WUNUSED
char* gdnsd_str_combine(const char* s1, const char* s2, const char** s2_offs);

// allocate a new string and concatenate all "count" strings
//   from the args list into it.
F_MALLOC F_NONNULL F_WUNUSED
char* gdnsd_str_combine_n(const unsigned count, ...);

// set thread name (via pthread_setname_np or similar)
void gdnsd_thread_setname(const char* n);

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
F_NONNULL
uint32_t gdnsd_rand_get32(gdnsd_rstate_t* rs);
F_NONNULL
uint64_t gdnsd_rand_get64(gdnsd_rstate_t* rs);

// Returns true if running on Linux with a kernel version >= x.y.z
// Returns false for non-Linux systems, or Linux kernels older than specified.
bool gdnsd_linux_min_version(const unsigned x, const unsigned y, const unsigned z);

// Jenkins lookup2
uint32_t gdnsd_lookup2(const char *k, uint32_t len);

// Get system/filesystem-specific dirent buffer size for readdir_r() safely
//   (dirname is just for error output)
F_NONNULL
size_t gdnsd_dirent_bufsize(DIR* d V_UNUSED, const char* dirname);

#endif // GDNSD_MISC_H
