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

// Compiler features we can take advantage of

#if defined __GNUC__ && (__GNUC__ < 3 || (__GNUC__ == 3 && __GNUC_MINOR__ < 4))
#  error Your GCC is way too old (< 3.4)...
#endif

#define PRAG_(x) _Pragma(#x)

// Basic features common to clang and gcc-3.4+
#if defined __clang__ || defined __GNUC__
#  define F_PRINTF(X, Y)  __attribute__((__format__(__printf__, X, Y)))
#  define F_NONNULLX(...) __attribute__((__nonnull__(__VA_ARGS__)))
#  define F_NONNULL       __attribute__((__nonnull__))
#  define F_NORETURN      __attribute__((__noreturn__))
#  define HAVE_BUILTIN_CLZ 1
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
#endif

// Newer features
#ifdef __clang__
#  define GDNSD_DIAG_PUSH_IGNORED(x) _Pragma("clang diagnostic push") \
                                   PRAG_(clang diagnostic ignored x)
#  define GDNSD_DIAG_POP             _Pragma("clang diagnostic pop")
#  if __has_builtin(__builtin_unreachable)
#    define GDNSD_HAVE_UNREACH_BUILTIN 1
#  endif
#  if __has_attribute(cold)
#    define F_COLD __attribute__((__cold__))
#  endif
#  if __has_attribute(returns_nonnull)
#    define F_RETNN         __attribute__((__returns_nonnull__))
#  endif
#  if __has_attribute(hot)
#    define F_HOT           __attribute__((__hot__))
#  endif
#  if __has_attribute(alloc_size)
#    define F_ALLOCSZ(...)  __attribute__((__alloc_size__(__VA_ARGS__)))
#  endif
#  if __has_attribute(alloc_align)
#    define F_ALLOCAL(_x)   __attribute__((__alloc_align__((_x))))
#  endif
#  if __has_attribute(fallthrough)
#    define S_FALLTHROUGH __attribute__((__fallthrough__))
#  endif
#elif defined __GNUC__
#  if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
#    define F_ALLOCSZ(...)  __attribute__((__alloc_size__(__VA_ARGS__)))
#    define F_HOT           __attribute__((__hot__))
#    define F_COLD __attribute__((__cold__))
#  endif
#  if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
#    define GDNSD_HAVE_UNREACH_BUILTIN 1
#  endif
#  if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#    define GDNSD_DIAG_PUSH_IGNORED(x) _Pragma("GCC diagnostic push") \
                                     PRAG_(GCC diagnostic ignored x)
#    define GDNSD_DIAG_POP             _Pragma("GCC diagnostic pop")
#  endif
#  if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9)
#    define F_RETNN         __attribute__((__returns_nonnull__))
#    define F_ALLOCAL(_x)   __attribute__((__alloc_align__((_x))))
#  endif
#  if __GNUC__ > 7 || (__GNUC__ == 7 && __GNUC_MINOR__ >= 1)
#    define S_FALLTHROUGH __attribute__((__fallthrough__))
#  endif
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
#ifndef F_NORETURN
#  if __STDC_VERSION__ >= 201112L // C11
#    define F_NORETURN _Noreturn
#  else
#    define F_NORETURN
#  endif
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
#ifndef   S_FALLTHROUGH
#  define S_FALLTHROUGH ((void)(0))
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
static uint64_t gdnsd_get_una64(const uint8_t* p)
{
    uint64_t v;
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

#endif // GDNSD_COMPILER_H
