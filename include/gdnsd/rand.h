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
 * This is the Public-Domain JKISS PRNG implementation which I initially got
 *   from David Jones' RNG paper here:
 *   http://www.cs.ucl.ac.uk/staff/d.jones/GoodPracticeRNG.pdf
 *   ... and then incorporated some usage/optimization hints from
 *   https://github.com/bhickey/librng
 * The actual algorithms ultimately came from George Marsaglia.  I've made
 *   cosmetic modifications (style, C99) and given it a state pointer for
 *   threading, and renamed it into the gdnsd API namespace so they can be
 *   swapped out easily later, and given them initialization from quality
 *   libsodium sources.
 ***************/

struct rstate32 {
    uint32_t x;
    uint32_t y;
    uint32_t z;
    uint32_t c;
};

F_NONNULL F_UNUSED
static uint32_t gdnsd_rand32_get(struct rstate32* rs)
{
    rs->x = 314527869U * rs->x + 1234567U;
    uint32_t y = rs->y;
    y ^= y << 5;
    y ^= y >> 7;
    y ^= y << 22;
    rs->y = y;
    uint64_t t = 4294584393ULL * rs->z + rs->c;
    rs->c = t >> 32;
    rs->z = t;
    return rs->x + rs->y + rs->z;
}

F_NONNULL F_UNUSED
static void gdnsd_rand32_init(struct rstate32* st)
{
    // Re-do initialization until we get all fields non-zero, and ensure that
    // "c" does not exceed its natural limits from the multiply operation in
    // the actual algorithm above (actually looping here should be exceedingly
    // rare if randombytes_buf() is decent!)
    do {
        randombytes_buf(st, sizeof(*st));
    } while (!st->x || !st->y || !st->z || !st->c || st->c >= 4294584393U);
    // Warm up the PRNG as a safety measure, too, with a random cycle count
    // of ~2K-4K iterations.
    uint32_t cycles = 2048U + (randombytes_random() & 0x7FF);
    while (cycles--)
        gdnsd_rand32_get(st);
}

// Unbiased while avoiding div/mod ops most of the time for smaller bounds, and
// being faster than what we did before on average for larger bounds.
// The techniques are from:
// https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
// https://lemire.me/blog/2016/06/30/fast-random-shuffling/
F_NONNULL F_UNUSED
static uint32_t gdnsd_rand32_bounded(struct rstate32* rs, const uint32_t bound)
{
    uint64_t mr = (uint64_t)gdnsd_rand32_get(rs) * bound;
    uint32_t leftover = (uint32_t)mr;
    if (unlikely(leftover < bound)) {
        uint32_t threshold = (0U - bound) % bound;
        while (unlikely(leftover < threshold)) {
            mr = (uint64_t)gdnsd_rand32_get(rs) * bound;
            leftover = (uint32_t)mr;
        }
    }
    return mr >> 32;
}

#endif // GDNSD_RAND_H
