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
#include <gdnsd/dmn.h>
#include <inttypes.h>
#include <stdbool.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/types.h>

extern const char gdnsd_lcmap[256];

// downcase an array of bytes of known length
F_NONNULL F_UNUSED
static void gdnsd_downcase_bytes(char* bytes, unsigned len) {
    for(unsigned i = 0; i < len; i++)
        bytes[i] = gdnsd_lcmap[(uint8_t)bytes[i]];
}

// downcase an asciiz string
F_NONNULL F_UNUSED
static void gdnsd_downcase_str(char* str) {
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


/***************
 * This Public-Domain JLKISS64 PRNG implementation is from:
 * http://www.cs.ucl.ac.uk/staff/d.jones/GoodPracticeRNG.pdf
 * I've made cosmetic modifications (style, C99)
 *  and given it a state pointer for threading, and renamed
 *  it into the gdnsd API namespace so it can be swapped out
 *  easily later.
 * I've also wrapped everything up such that there's one
 *  global PRNG initialized at startup from decent sources,
 *  which is mutex-protected and used to set seeds for later
 *  runtime per-thread/plugin PRNG initializations, and provided
 *  a buffer to use one iteration of jlkiss64 to generate
 *  2x numbers in 32-bit space.
 * This seems at least as fast as jkiss32 for the 32-bit
 *  results on modern 64-bit CPUs, has much longer periods
 *  and is more resilient in general, and it gives us the
 *  option to burn a little extra CPU on 64-bit PRNG results when
 *  warranted.
 ***************/

// PRNG:
// gdnsd_rand_init() allocates an opaque PRNG state which can
//   be later free()'d when no longer required.
typedef struct _gdnsd_rstate_t {
    uint64_t x;
    uint64_t y;
    uint32_t z1;
    uint32_t c1;
    uint32_t z2;
    uint32_t c2;
    uint32_t buf32;
    bool buf32_ok;
} gdnsd_rstate_t;

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

F_NONNULL F_UNUSED
static uint64_t gdnsd_rand_get64(gdnsd_rstate_t* rs) {
    dmn_assert(rs);

    uint64_t t;

    rs->x = 1490024343005336237ULL * rs->x + 123456789;
    rs->y ^= rs->y << 21;
    rs->y ^= rs->y >> 17;
    rs->y ^= rs->y << 30;
    t = 4294584393ULL * rs->z1 + rs->c1;
    rs->c1 = t >> 32; rs->z1 = t;
    t = 4246477509ULL * rs->z2 + rs->c2;
    rs->c2 = t >> 32; rs->z2 = t;
    return rs->x + rs->y + rs->z1 + ((uint64_t)rs->z2 << 32);
}

F_NONNULL F_UNUSED
static uint32_t gdnsd_rand_get32(gdnsd_rstate_t* rs) {
    dmn_assert(rs);

    if(rs->buf32_ok) {
       rs->buf32_ok = false;
       return rs->buf32;
    }
    else {
       rs->buf32_ok = true;
       uint64_t new = gdnsd_rand_get64(rs);
       rs->buf32 = (uint32_t)new;
       new >>= 32;
       return (uint32_t)new;
    }
}

// Returns true if running on Linux with a kernel version >= x.y.z
// Returns false for non-Linux systems, or Linux kernels older than specified.
bool gdnsd_linux_min_version(const unsigned x, const unsigned y, const unsigned z);

// gdnsd_lookup2 is lookup2() by Bob Jenkins,
//   from http://www.burtleburtle.net/bob/c/lookup2.c,
//   which is in the public domain.
// It's just been reformatted/styled to match my code.

#define mix(a,b,c) { \
    a -= b; a -= c; a ^= (c>>13); \
    b -= c; b -= a; b ^= (a<<8);  \
    c -= a; c -= b; c ^= (b>>13); \
    a -= b; a -= c; a ^= (c>>12); \
    b -= c; b -= a; b ^= (a<<16); \
    c -= a; c -= b; c ^= (b>>5);  \
    a -= b; a -= c; a ^= (c>>3);  \
    b -= c; b -= a; b ^= (a<<10); \
    c -= a; c -= b; c ^= (b>>15); \
}

F_PURE F_UNUSED
static uint32_t gdnsd_lookup2(const char *k, uint32_t len) {
    dmn_assert(k || !len);

    const uint32_t orig_len = len;

    uint32_t a = 0x9e3779b9;
    uint32_t b = 0x9e3779b9;
    uint32_t c = 0xdeadbeef;

    while(len >= 12) {
        a += (k[0] + ((uint32_t)k[1]  << 8)
                   + ((uint32_t)k[2]  << 16)
                   + ((uint32_t)k[3]  << 24));
        b += (k[4] + ((uint32_t)k[5]  << 8)
                   + ((uint32_t)k[6]  << 16)
                   + ((uint32_t)k[7]  << 24));
        c += (k[8] + ((uint32_t)k[9]  << 8)
                   + ((uint32_t)k[10] << 16)
                   + ((uint32_t)k[11] << 24));
        mix(a,b,c);
        k += 12; len -= 12;
    }

    c += orig_len;

    switch(len) {
        case 11: c += ((uint32_t)k[10] << 24);
        case 10: c += ((uint32_t)k[9]  << 16);
        case 9 : c += ((uint32_t)k[8]  << 8);
        case 8 : b += ((uint32_t)k[7]  << 24);
        case 7 : b += ((uint32_t)k[6]  << 16);
        case 6 : b += ((uint32_t)k[5]  << 8);
        case 5 : b += k[4];
        case 4 : a += ((uint32_t)k[3]  << 24);
        case 3 : a += ((uint32_t)k[2]  << 16);
        case 2 : a += ((uint32_t)k[1]  << 8);
        case 1 : a += k[0];
    }

    mix(a,b,c);
    return c;
}

// Get system/filesystem-specific dirent buffer size for readdir_r() safely
//   (dirname is just for error output)
F_NONNULL
size_t gdnsd_dirent_bufsize(DIR* d V_UNUSED, const char* dirname);

// Register a child process that exists for the life of the daemon, so that
//   the core can SIGTERM and reap it on clean shutdown.
void gdnsd_register_child_pid(pid_t child);

#endif // GDNSD_MISC_H
