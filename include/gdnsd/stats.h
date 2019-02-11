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

#ifndef GDNSD_STATS_H
#define GDNSD_STATS_H

#include <gdnsd/compiler.h>

#include <inttypes.h>

/*
 * This header defines two data types named stats_t and stats_uint_t,
 *   and two accessor functions for stats_t.
 *
 * stats_t is used to implement an uint-like piece of data which is
 *   shared (without barriers or locking) between multiple threads
 *   and/or CPUs with the following very important caveats:
 *
 * 1) One thread is the "owner", and is the only thread performing
 *   write operations to the value within stats_t.
 * 2) Non-owner threads only read the data, using stats_get().
 * 3) The usage of the stats_t must be such that there are no data
 *   dependencies on it for correctness.  In other words: pay attention
 *   to the word "stats" in the type name; this is intended for storing
 *   and retrieving statistical data which have no bearing on correct
 *   program execution.
 * 4) Further, it's important to realize that the writes will only
 *   be seen by the non-owner threads "when the CPU feels like it".  On
 *   modern mainstream systems with reasonable cache coherency, this
 *   generally happens "pretty soon", soon enough that it doesn't matter
 *   for stats accounting.  There is no actual guarantee on when the
 *   update becomes visible in the general case, and it might *never*
 *   become visible on some exotic architectures that gdnsd doesn't
 *   care to support at this time.
 *
 * stats_uint_t is simply an regular unsigned type of some width that
 *   matches the internal width of stats_t.  You can store the result
 *   of stats_get() in such a type to cache it thread-locally for a while
 *   in cases where that makes sense.
 *
 * The width of the types currently matches uintptr_t (the width of a
 *   pointer), because most mainstream architectures are atomic for
 *   this size of aligned memory access (not atomic in the SMP sense,
 *   atomic in the "you won't read a half-updated value" sense).  We've
 *   made a special exception for x86_64 x32, because it's a
 *   reasonably-common option where pointers are 32-bit, but 64-bit
 *   atomic operations are possible.
 */

#if defined __x86_64__ && defined __ILP32__
typedef uint64_t stats_uint_t;
#else
typedef uintptr_t stats_uint_t;
#endif

typedef struct {
    stats_uint_t _x;
} stats_t;

// stats_own_inc() -> increment stats value from the owner thread only
F_NONNULL F_UNUSED
static void stats_own_inc(stats_t* s)
{
    s->_x++;
}

// stats_get() -> read the value from any other thread
F_NONNULL F_UNUSED
static stats_uint_t stats_get(const stats_t* s)
{
    return *(const volatile stats_uint_t*)&s->_x;
}

#endif // GDNSD_STATS_H
