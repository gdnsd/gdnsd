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

#ifndef GDNSD_COMPILER_H
#define GDNSD_COMPILER_H

// Require C11 here, in a way that works back to C89
#if __STDC_VERSION__ < 201112L
#  error C11 compiler required!
#endif

// Headers for compiler features we can take advantage of with C11 broadly:
#include <stdnoreturn.h>
#include <stdalign.h>
#include <assert.h>

// Basic features common to C11-era versions of clang and gcc
#if defined __clang__ || defined __GNUC__
#  define F_PRINTF(X, Y)  __attribute__((__format__(__printf__, X, Y)))
#  define F_NONNULLX(...) __attribute__((__nonnull__(__VA_ARGS__)))
#  define F_NONNULL       __attribute__((__nonnull__))
#  define HAVE_BUILTIN_CLZ 1
#  define GDNSD_HAVE_UNREACH_BUILTIN 1
#  define likely(_x)      __builtin_expect(!!(_x), 1)
#  define unlikely(_x)    __builtin_expect(!!(_x), 0)
#  define V_UNUSED        __attribute__((__unused__))
#  define F_UNUSED        __attribute__((__unused__))
#  define F_CONST         __attribute__((__const__))
#  define F_PURE          __attribute__((__pure__))
#  define F_MALLOC        __attribute__((__malloc__)) __attribute__((__warn_unused_result__))
#  define F_NOINLINE      __attribute__((__noinline__))
#  define F_WUNUSED       __attribute__((__warn_unused_result__))
#  define F_DEPRECATED    __attribute__((__deprecated__))
#  define F_ALLOCSZ(...)  __attribute__((__alloc_size__(__VA_ARGS__)))
#  define F_HOT           __attribute__((__hot__))
#  define F_COLD          __attribute__((__cold__))
#  define F_RETNN         __attribute__((__returns_nonnull__))
#  define F_ALLOCAL(_x)   __attribute__((__alloc_align__((_x))))
#endif

#define PRAG_(x) _Pragma(#x)
#ifdef __clang__
#  define GDNSD_DIAG_PUSH_IGNORED(x) _Pragma("clang diagnostic push") \
                                   PRAG_(clang diagnostic ignored x)
#  define GDNSD_DIAG_POP             _Pragma("clang diagnostic pop")
#  if __has_builtin(__builtin_assume)
#    define GDNSD_HAVE_ASSUME_BUILTIN 1
#  endif
#elif defined __GNUC__
#  if __GNUC__ >= 10 // gcc-10 doesn't have assume yet, but some future version might!
#    if __has_builtin(__builtin_assume)
#      define GDNSD_HAVE_ASSUME_BUILTIN 1
#    endif
#  endif
#  define GDNSD_DIAG_PUSH_IGNORED(x) _Pragma("GCC diagnostic push") \
                                   PRAG_(GCC diagnostic ignored x)
#  define GDNSD_DIAG_POP             _Pragma("GCC diagnostic pop")
#endif

// defaults for unknown compilers and things left unset above
#ifndef F_PRINTF
#  define F_PRINTF(X, Y)
#endif
#ifndef F_NONNULLX
#  define F_NONNULLX(...)
#endif
#ifndef F_NONNULL
#  define F_NONNULL
#endif
#ifndef F_COLD
#  define F_COLD
#endif
#ifndef GDNSD_DIAG_PUSH_IGNORED
#  define GDNSD_DIAG_PUSH_IGNORED(_x)
#endif
#ifndef GDNSD_DIAG_POP
#  define GDNSD_DIAG_POP
#endif
#ifndef   F_RETNN
#  define F_RETNN
#endif
#ifndef likely
#  define likely(_x) (!!(_x))
#endif
#ifndef unlikely
#  define unlikely(_x) (!!(_x))
#endif
#ifndef   V_UNUSED
#  define V_UNUSED
#endif
#ifndef   F_UNUSED
#  define F_UNUSED
#endif
#ifndef   F_CONST
#  define F_CONST
#endif
#ifndef   F_PURE
#  define F_PURE
#endif
#ifndef   F_MALLOC
#  define F_MALLOC
#endif
#ifndef   F_NOINLINE
#  define F_NOINLINE
#endif
#ifndef   F_WUNUSED
#  define F_WUNUSED
#endif
#ifndef   F_DEPRECATED
#  define F_DEPRECATED
#endif
#ifndef   F_ALLOCSZ
#  define F_ALLOCSZ(...)
#endif
#ifndef   F_HOT
#  define F_HOT
#endif
#ifndef   F_ALLOCAL
#  define F_ALLOCAL(_x)
#endif

// Unaligned memory access stuff

#include <inttypes.h>
#include <string.h>

F_UNUSED F_NONNULL
static uint16_t gdnsd_get_una16(const uint8_t* p)
{
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

F_UNUSED F_NONNULL
static uint32_t gdnsd_get_una32(const uint8_t* p)
{
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

F_UNUSED F_NONNULL
static void gdnsd_put_una16(const uint16_t v, uint8_t* p)
{
    memcpy(p, &v, sizeof(v));
}

F_UNUSED F_NONNULL
static void gdnsd_put_una32(const uint32_t v, uint8_t* p)
{
    memcpy(p, &v, sizeof(v));
}

// Generic useful macros
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// Attempt to set a reasonable cache line size define for use in alignas() for
// avoiding destructive interference in data structure accesses shared between
// threads.  The optimal value on a given CPU is not always obvious, and is
// sometimes larger than the actual L1/L2 cacheline (e.g. because of streaming
// prefetch to cachelines, or because L3 is important and has larger lines).
//
// This is a perf optimization - it'd be great to have a more-complete and
// accurate set of conditions and values here, but it's not essential to
// correctness, either.  The default of 64 is probably fairly universal in its
// utility and better than nothing even on arches that happen to have larger
// ideal values, and over-large values can be inefficient on small systems.
//
// This is my initial stab at some important cases, based on googling around
// and staring at the values/rationales some other projects use.  This probably
// needs more research and may be wrong for some (sub-)targets.  We're mainly
// aiming at "modern" (as in, still being manufactured/warrantied and in
// reasonably-widespread use) *nix server hardware.
//
// CONFIG_CACHE_ALIGN is from the optional --with-cache-alignment= configure
// argument, in case someone wants to override for a build at that level.

#if defined(CONFIG_CACHE_ALIGN)
#  define CACHE_ALIGN CONFIG_CACHE_ALIGN
#elif defined(__x86_64__) || defined(__x86_64) || defined(__amd64__) || defined(__amd64)
#  define CACHE_ALIGN 128
#elif defined(__s390__) || defined(__s390x__) || defined(__zarch__)
#  define CACHE_ALIGN 256
#elif defined(__ppc__) || defined(__ppc64__) || defined(__powerpc__) || defined(__powerpc64__)
#  define CACHE_ALIGN 256
#elif defined(__sparc__) || defined(__sparc64__) || defined(__sparc)
#  define CACHE_ALIGN 256
#else
#  define CACHE_ALIGN 64
#endif

#endif // GDNSD_COMPILER_H
