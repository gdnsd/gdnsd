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

// For uintptr_t
#include <inttypes.h>

#include <gdnsd/compiler.h>
#include <gdnsd/dmn.h>

/*
 * This header defines two data types named stats_t and stats_uint_t,
 *   and several accessor functions for them.
 *
 * stats_t is used to implement an uint-like peice of data which is
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
 *   for stats accounting.  There is no actual gaurantee on when the
 *   update becomes visible in the general case, and it might *never*
 *   become visible on some exotic architectures that gdnsd  doesn't
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
 *   atomic in the "you won't read a half-updated value" sense).
 */

typedef uintptr_t stats_uint_t;
typedef struct { stats_uint_t _x; } stats_t;

// stats_own_set() -> set the stats value from the owner thread only
F_NONNULL F_UNUSED
static void stats_own_set(stats_t* s, const stats_uint_t v)
    { dmn_assert(s); s->_x = v; }

// stats_own_inc() -> increment stats value from the owner thread only
F_NONNULL F_UNUSED
static void stats_own_inc(stats_t* s)
    { dmn_assert(s); s->_x++; }

// stats_own_get() -> read the value from the owner thread
F_NONNULL F_UNUSED
static stats_uint_t stats_own_get(const stats_t* s)
    { dmn_assert(s); return s->_x; }

// stats_get() -> read the value from any other thread
F_NONNULL F_UNUSED
static stats_uint_t stats_get(const stats_t* s)
    { dmn_assert(s); return *(volatile stats_uint_t*)&s->_x; }

#endif // GDNSD_STATS_H
