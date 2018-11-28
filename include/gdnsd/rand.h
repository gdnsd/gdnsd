/* Copyright © 2018 Brandon L Black <blblack@gmail.com>
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

#ifndef GDNSD_RAND_H
#define GDNSD_RAND_H

#include <gdnsd/compiler.h>
#include <gdnsd/log.h>
#include <gdnsd/alloc.h>

#include <inttypes.h>

#include <sodium.h>

/***************
 * These are Public-Domain JKISS32/JLKISS64 PRNG implementations
 *   which I initially got from David Jones' RNG paper here:
 *   http://www.cs.ucl.ac.uk/staff/d.jones/GoodPracticeRNG.pdf
 *   ... and then incorporated some usage/optimization hints from
 *   https://github.com/bhickey/librng
 * The actual algorithms ultimately came from George Marsaglia.
 * I've made cosmetic modifications (style, C99) and given them a
 *  state pointer for threading, and renamed them into the gdnsd API
 *  namespace so they can be swapped out easily later, and given them
 *  initialization from quality libsodium sources.
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

typedef struct _gdnsd_rstate64_t {
    uint64_t x;
    uint64_t y;
    uint32_t z1;
    uint32_t c1;
    uint32_t z2;
    uint32_t c2;
} gdnsd_rstate64_t;

typedef struct _gdnsd_rstate32_t {
    uint32_t x;
    uint32_t y;
    uint32_t z;
    uint32_t w;
    uint32_t c;
} gdnsd_rstate32_t;

F_RETNN F_UNUSED
static gdnsd_rstate64_t* gdnsd_rand64_init(void)
{
    if (sodium_init() < 0)
        log_fatal("Could not initialize libsodium: %s", logf_errno());
    gdnsd_rstate64_t* newstate = xmalloc(sizeof(*newstate));
    do {
        randombytes_buf(newstate, sizeof(*newstate));
    } while (!newstate->y); // y==0 is bad for jlkiss64
    return newstate;
}

F_RETNN F_UNUSED
static gdnsd_rstate32_t* gdnsd_rand32_init(void)
{
    if (sodium_init() < 0)
        log_fatal("Could not initialize libsodium: %s", logf_errno());
    gdnsd_rstate32_t* newstate = xmalloc(sizeof(*newstate));
    do {
        randombytes_buf(newstate, sizeof(*newstate));
    } while (!newstate->y); // y==0 is bad for jkiss32
    return newstate;
}

// This is JLKISS64
F_NONNULL F_UNUSED
static uint64_t gdnsd_rand64_get(gdnsd_rstate64_t* rs)
{
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
static uint32_t gdnsd_rand32_get(gdnsd_rstate32_t* rs)
{
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

#endif // GDNSD_RAND_H
