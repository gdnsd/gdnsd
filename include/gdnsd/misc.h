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
#include <gdnsd/log.h>

#include <inttypes.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/types.h>

// Register a child process that exists for the life of the daemon, so that
//   the core can SIGTERM and reap it on clean shutdown.
void gdnsd_register_child_pid(pid_t child);

// allocate a new string, concatenating s1 + s2.
// retval is the new string
// if s2_offs is not NULL, *s2_offs will be set
//   to the offset of the copy of s2 within the retval.
F_MALLOC F_NONNULLX(1, 2) F_RETNN
char* gdnsd_str_combine(const char* s1, const char* s2, const char** s2_offs);

// allocate a new string and concatenate all "count" strings
//   from the args list into it.  Meant to be used with small fixed counts,
//   asserts that count is <= 16.
F_MALLOC F_NONNULL F_RETNN
char* gdnsd_str_combine_n(const unsigned count, ...);

// Creates a new heap-allocated copy of the string "haystack", with all
// occurrences of "needle" replaced by "repl".  All string inputs should be NUL
// terminated, and the _len arguments for the needle and repl should be their
// strlen()s.  The needle must have a non-zero size.  This is meant for simple
// uses during configuration-parsing kinds of cases, and errors out if the
// needle, replacement, or original string are of unreasonable size (over half
// the bits of size_t, so ~64K on ILP32).  It's also not terribly efficient :)
F_NONNULL
char* gdnsd_str_subst(const char* haystack, const char* needle, const size_t needle_len, const char* repl, const size_t repl_len);

// set thread name (via pthread_setname_np or similar)
void gdnsd_thread_setname(const char* n);

// scale an unsigned by a double in the range [0.0 - 1.0]
//   and get the ceiling of the result.  Cannot overflow.
F_UNUSED F_CONST
unsigned gdnsd_uscale_ceil(unsigned v, double s);

// Kill+Reap pids from gdnsd_register_child_pid()
void gdnsd_kill_registered_children(void);

// downcase an array of bytes of known length
F_NONNULL F_UNUSED
static void gdnsd_downcase_bytes(char* bytes, unsigned len)
{
    for (unsigned i = 0; i < len; i++)
        if (unlikely((bytes[i] < 0x5B) && (bytes[i] > 0x40)))
            bytes[i] |= 0x20;
}

// downcase an asciiz string
F_NONNULL F_UNUSED
static void gdnsd_downcase_str(char* str)
{
    while (*str) {
        if (unlikely((*str < 0x5B) && (*str > 0x40)))
            *str |= 0x20;
        str++;
    }
}

// gdnsd_lookup2 is lookup2() by Bob Jenkins,
//   from http://www.burtleburtle.net/bob/c/lookup2.c,
//   which is in the public domain.
// It's just been reformatted/styled to match my code.

#define mix(a, b, c) { \
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

F_PURE F_UNUSED F_WUNUSED
static uint32_t gdnsd_lookup2(const uint8_t* k, uint32_t len)
{
    gdnsd_assert(k || !len);

    const uint32_t orig_len = len;

    uint32_t a = 0x9e3779b9;
    uint32_t b = 0x9e3779b9;
    uint32_t c = 0xdeadbeef;

    while (len >= 12) {
        a += (k[0] + ((uint32_t)k[1] << 8)
              + ((uint32_t)k[2] << 16)
              + ((uint32_t)k[3] << 24));
        b += (k[4] + ((uint32_t)k[5] << 8)
              + ((uint32_t)k[6] << 16)
              + ((uint32_t)k[7] << 24));
        c += (k[8] + ((uint32_t)k[9] << 8)
              + ((uint32_t)k[10] << 16)
              + ((uint32_t)k[11] << 24));
        mix(a, b, c);
        k += 12;
        len -= 12;
    }

    c += orig_len;

    switch (len) {
    case 11:
        c += ((uint32_t)k[10] << 24);
        S_FALLTHROUGH; // FALLTHROUGH
    case 10:
        c += ((uint32_t)k[9] << 16);
        S_FALLTHROUGH; // FALLTHROUGH
    case 9:
        c += ((uint32_t)k[8] << 8);
        S_FALLTHROUGH; // FALLTHROUGH
    case 8:
        b += ((uint32_t)k[7] << 24);
        S_FALLTHROUGH; // FALLTHROUGH
    case 7:
        b += ((uint32_t)k[6] << 16);
        S_FALLTHROUGH; // FALLTHROUGH
    case 6:
        b += ((uint32_t)k[5] << 8);
        S_FALLTHROUGH; // FALLTHROUGH
    case 5:
        b += k[4];
        S_FALLTHROUGH; // FALLTHROUGH
    case 4:
        a += ((uint32_t)k[3] << 24);
        S_FALLTHROUGH; // FALLTHROUGH
    case 3:
        a += ((uint32_t)k[2] << 16);
        S_FALLTHROUGH; // FALLTHROUGH
    case 2:
        a += ((uint32_t)k[1] << 8);
        S_FALLTHROUGH; // FALLTHROUGH
    case 1:
        a += k[0];
        S_FALLTHROUGH; // FALLTHROUGH
    default:
        break;
    }

    mix(a, b, c);
    return c;
}

// count2mask converts a uint32_t to the next-largest power of two, minus 1.
// useful in sizing po2-sized hash tables and masking hash results for them.

#ifndef HAVE_BUILTIN_CLZ

F_CONST F_UNUSED
static uint32_t count2mask(uint32_t x)
{
    x |= 1U;
    x |= x >> 1U;
    x |= x >> 2U;
    x |= x >> 4U;
    x |= x >> 8U;
    x |= x >> 16U;
    return x;
}

#else

F_CONST F_UNUSED
static uint32_t count2mask(const uint32_t x)
{
    // This variant is about twice as fast as the above, but
    //  only available w/ GCC 3.4 and above.
    return ((1U << (31U - (unsigned)__builtin_clz(x | 1U))) << 1U) - 1U;
}

#endif

// Called by threads other than DNS I/O threads (e.g. zonefile reloaders, geoip
// database reloaders, etc) to increase their effective nice-ness relative to
// the I/O threads during normal runtime, which should be the only ones to
// enjoy the full benefit of any enhanced priority set up for the process as a
// whole by the initscript or systemd unit.  It would be nice to call this for
// the main thread at runtime as well, but then the reduction would inherit to
// "replace" child daemons by default.  This could be an argument for shifting
// much of the functionality of the main thread off to a side-thread, but there
// are at least a few critical jobs we can't do that for.  Should probably wait
// until after the monitoring rework to look at that.
void gdnsd_thread_reduce_prio(void);

// reset to default any signal handlers that we actually listen to in the main
// process (but don't disturb others (e.g. PIPE/HUP) that may be set to
// SIG_IGN, which is automatically maintained through both fork and exec), and
// then unblock all signals.  Intended to be called in a forked child process
// just before exec-family functions for our own subprocesses (replacement
// daemons, and the extmon helper process).
void gdnsd_reset_signals_for_exec(void);

#endif // GDNSD_MISC_H
