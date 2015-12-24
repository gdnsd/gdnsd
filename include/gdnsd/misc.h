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

typedef struct _gdnsd_rstate32_t {
    uint32_t x;
    uint32_t y;
    uint32_t z;
    uint32_t w;
    uint32_t c;
} gdnsd_rstate32_t;

typedef struct _gdnsd_rstate64_t {
    uint64_t x;
    uint64_t y;
    uint32_t z1;
    uint32_t c1;
    uint32_t z2;
    uint32_t c2;
} gdnsd_rstate64_t;

#pragma GCC visibility push(default)

// Get system/filesystem-specific dirent buffer size for readdir_r() safely
//   (dirname is just for error output)
F_NONNULL
size_t gdnsd_dirent_bufsize(DIR* d V_UNUSED, const char* dirname);

// Register a child process that exists for the life of the daemon, so that
//   the core can SIGTERM and reap it on clean shutdown.
void gdnsd_register_child_pid(pid_t child);

// allocate a new string, concatenating s1 + s2.
// retval is the new string
// if s2_offs is not NULL, *s2_offs will be set
//   to the offset of the copy of s2 within the retval.
F_MALLOC F_NONNULLX(1,2)
char* gdnsd_str_combine(const char* s1, const char* s2, const char** s2_offs);

// allocate a new string and concatenate all "count" strings
//   from the args list into it.
F_MALLOC F_NONNULL
char* gdnsd_str_combine_n(const unsigned count, ...);

// set thread name (via pthread_setname_np or similar)
void gdnsd_thread_setname(const char* n);

// Returns true if running on Linux with a kernel version >= x.y.z
// Returns false for non-Linux systems, or Linux kernels older than specified.
bool gdnsd_linux_min_version(const unsigned x, const unsigned y, const unsigned z);

// State initializers for gdnsd_randXX_get() below
gdnsd_rstate32_t* gdnsd_rand32_init(void);
gdnsd_rstate64_t* gdnsd_rand64_init(void);

// scale an unsigned by a double in the range [0.0 - 1.0]
//   and get the ceiling of the result.  Cannot overflow.
F_UNUSED F_CONST
unsigned gdnsd_uscale_ceil(unsigned v, double s);

#pragma GCC visibility pop

// downcase an array of bytes of known length
F_NONNULL F_UNUSED
static void gdnsd_downcase_bytes(char* bytes, unsigned len) {
    for(unsigned i = 0; i < len; i++)
        if(unlikely((bytes[i] < 0x5B) && (bytes[i] > 0x40)))
            bytes[i] |= 0x20;
}

// downcase an asciiz string
F_NONNULL F_UNUSED
static void gdnsd_downcase_str(char* str) {
    while(*str) {
        if(unlikely((*str < 0x5B) && (*str > 0x40)))
            *str |= 0x20;
        str++;
    }
}

/***************
 * These are Public-Domain JKISS32/JLKISS64 PRNG implementations
 *   which I initially got from David Jones' RNG paper here:
 *   http://www.cs.ucl.ac.uk/staff/d.jones/GoodPracticeRNG.pdf
 *   ... and then incorporated some usage/optimization hints from
 *   https://github.com/bhickey/librng
 * The actual algorithms ultimately came from George Marsaglia.
 * I've made cosmetic modifications (style, C99) and given them a
 *  state pointer for threading, and renamed them into the gdnsd API
 *  namespace so they can be swapped out easily later.
 * I've also wrapped everything up such that there's one
 *  global PRNG initialized at startup from decent sources,
 *  which is mutex-protected and used to set seeds for later
 *  runtime per-thread/plugin PRNG initializations.
 ***************/

/* Note there are separate 64-bit and 32-bit interfaces here.
 * Both have periods sufficient for this software in general,
 *   given an analysis of high end per-thread DNS query rates and
 *   daemon uptimes, etc.  The 32-bit one is faster and should
 *   be used by default.
 * The 64-bit one is supplied for cases (such as plugin_weighted)
 *   where the result is being used in an integer modulo operation
 *   with unpredictable mod values which could be large enough to
 *   induce bias with the 32-bit one.
 * For "gdnsd_rand32_get() % N":
 *     maxN -> bias
 *     ----    ----
 *     2^24 -> 0.39%
 *     2^28 -> 6.25%
 *     2^29 -> 12.5%
 *     2^30 -> 25%
 * ... whereas rand64_get() will have an almost immeasurably small
 *   bias for modvals up to 2^32.
 */

// This is JLKISS64
F_NONNULL F_UNUSED
static uint64_t gdnsd_rand64_get(gdnsd_rstate64_t* rs) {
    dmn_assert(rs);

    rs->x = 1490024343005336237ULL * rs->x + 123456789;

    uint64_t y = rs->y;
    y ^= y << 21;
    y ^= y >> 17;
    y ^= y << 30;
    rs->y = y;

    uint64_t t = 4294584393ULL * rs->z1 + rs->c1;
    rs->c1 = t >> 32;
    rs->z1 = t;

    t = 4246477509ULL * rs->z2 + rs->c2;
    rs->c2 = t >> 32;
    rs->z2 = t;

    return rs->x + y + rs->z1 + ((uint64_t)rs->z2 << 32);
}

// This is JKISS32
F_NONNULL F_UNUSED
static uint32_t gdnsd_rand32_get(gdnsd_rstate32_t* rs) {
    dmn_assert(rs);

    uint32_t y = rs->y;
    y ^= y << 5;
    y ^= y >> 7;
    y ^= y << 22;
    rs->y = y;

    // Note local mods to how t is handled (results are the same)
    uint32_t t = rs->z + rs->w + rs->c;
    rs->z = rs->w;
    rs->c = (t & 1U << 31) >> 31;
    rs->w = t & 2147483647;

    rs->x += 1411392427;

    return rs->x + y + rs->w;
}

/***************
 * End PRNG Stuff
 ***************/

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
static uint32_t gdnsd_lookup2(const uint8_t *k, uint32_t len) {
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
        default: break;
    }

    mix(a,b,c);
    return c;
}

#endif // GDNSD_MISC_H
