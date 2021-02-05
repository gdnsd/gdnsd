/* Copyright © 2021 Brandon L Black <blblack@gmail.com>
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
#include <stdatomic.h>

/*
 *   This header defines two data types named stats_t and stats_uint_t, and a
 * number of related functions.  These are built on C11 atomics and are
 * intended to implement fast cross-thread statistical counters which have a
 * single writer (owner) thread but can be read consistently by another thread
 * as stats data.  The general pattern is that the stats storage (a struct
 * containing many stats_t) is allocated and written to as a per-thread chunk
 * of memory, and the stats reporter thread has pointers to all threads'
 * structures and is responsible for reading them all and summing them into a
 * global stats output when requested by users or other software.
 *
 * Rules:
 * 1) One thread is the "owner" of a stats_t (or a block of them), and is the
 *    only thread performing write operations to the value, via
 *    stats_own_{inc,add}().
 * 2) Non-owner threads only read the data, using stats_get().
 * 3) The usage of the stats_t must be such that there are no data dependencies
 *    on it for correctness.  In other words: pay attention to the word "stats"
 *    in the type name; this is intended for storing and retrieving statistical
 *    data which have no bearing on correct program execution.
 *
 *   stats_uint_t is a regular, non-atomic unsigned type of the same width as
 * stats_t.  You can store the result of stats_get() in such a type to cache it
 * thread-locally for a while in cases where that makes sense.
 *
 *   The width of the type and thus the max stat value before rollover is
 * chosen as the platform's pointer type, as this is safely lock/tear-free
 * across a broad range of platforms.  We make an exception for the x86_64
 * "x32" ILP32 ABI and give it a 64-bit long long type even though it has
 * 32-bit pointers.
 *
 */

#if defined __x86_64__ && defined __ILP32__
static_assert(ATOMIC_LLONG_LOCK_FREE == 2, "x86_64 ILP32 has lock-free llong");
typedef unsigned long long stats_uint_t;
typedef atomic_ullong stats_t;
#define PRISTATS "llu"
#else
typedef uintptr_t stats_uint_t;
typedef atomic_uintptr_t stats_t;
#define PRISTATS PRIuPTR
#endif

// stats_get: read the value from a reader thread
F_NONNULL F_UNUSED
static stats_uint_t stats_get(const stats_t* s)
{
    return atomic_load_explicit(s, memory_order_relaxed);
}

// stats_own_add: add stats value from the owner thread only
F_NONNULL F_UNUSED
static void stats_own_add(stats_t* s, const stats_uint_t n)
{
    // Note that doing the add in a local temporary only works because of our
    // one-writer rule.  Otherwise we'd have to use atomic_fetch_add(), which
    // is a full RMW op and often more expensive (e.g. a LCK prefix)
    const stats_uint_t x = atomic_load_explicit(s, memory_order_relaxed) + n;
    atomic_store_explicit(s, x, memory_order_relaxed);
}

// Shorthand for the most common "add" case: increment by one
#define stats_own_inc(s) stats_own_add((s), 1U)

#endif // GDNSD_STATS_H
