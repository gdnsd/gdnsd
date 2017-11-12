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

// Basic features common to clang and gcc
#if defined __clang__ || defined __GNUC__
#  define HAVE_BUILTIN_CLZ 1
#  define likely(_x)      __builtin_expect(!!(_x), 1)
#  define unlikely(_x)    __builtin_expect(!!(_x), 0)
#  define V_UNUSED        __attribute__((__unused__))
#  define F_UNUSED        __attribute__((__unused__))
#  define F_CONST         __attribute__((__const__))
#  define F_PURE          __attribute__((__pure__))
#  define F_MALLOC        __attribute__((__malloc__)) __attribute__((__warn_unused_result__))
#  define F_NORETURN      __attribute__((__noreturn__))
#  define F_NOINLINE      __attribute__((__noinline__))
#  define F_NONNULLX(...) __attribute__((__nonnull__(__VA_ARGS__)))
#  define F_NONNULL       __attribute__((__nonnull__))
#  define F_WUNUSED       __attribute__((__warn_unused_result__))
#  define F_DEPRECATED    __attribute__((__deprecated__))
#endif

// Newer features
#ifdef __clang__
#  if __has_attribute(hot)
#    define F_HOT           __attribute__((__hot__))
#  endif
#  if __has_attribute(alloc_size)
#    define F_ALLOCSZ(...)  __attribute__((__alloc_size__(__VA_ARGS__)))
#  endif
#  if __has_attribute(alloc_align)
#    define F_ALLOCAL(_x)   __attribute__((__alloc_align__((_x))))
#  endif
#  if __has_attribute(returns_nonnull)
#    define F_RETNN         __attribute__((__returns_nonnull__))
#  endif
#elif defined __GNUC__
#  if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
#    define F_ALLOCSZ(...)  __attribute__((__alloc_size__(__VA_ARGS__)))
#    define F_HOT           __attribute__((__hot__))
#  endif
#  if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9)
#    define F_ALLOCAL(_x)   __attribute__((__alloc_align__((_x))))
#    define F_RETNN         __attribute__((__returns_nonnull__))
#  endif
#endif

// defaults for unknown compilers and things left unset above
#ifndef F_NORETURN
#  if __STDC_VERSION__ >= 201112L // C11
#    define F_NORETURN _Noreturn
#  else
#    define F_NORETURN
#  endif
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
#ifndef   F_NONNULLX
#  define F_NONNULLX(...)
#endif
#ifndef   F_NONNULL
#  define F_NONNULL
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
#ifndef   F_RETNN
#  define F_RETNN
#endif

// This is a GCC-ism which also seems to be supported
//    by other common compilers on our platforms.  If it
//    breaks for you, please file a bug report and we'll
//    find a way to fix it.
#define S_PACKED __attribute__((__packed__))

// Unaligned memory access stuff
#include <inttypes.h>
struct _gdnsd_una16 { uint16_t x; } S_PACKED;
struct _gdnsd_una32 { uint32_t x; } S_PACKED;
#define gdnsd_get_una16(_p) (((const struct _gdnsd_una16*)(_p))->x)
#define gdnsd_get_una32(_p) (((const struct _gdnsd_una32*)(_p))->x)
#define gdnsd_put_una16(_v,_p) (((struct _gdnsd_una16*)(_p))->x) = (_v)
#define gdnsd_put_una32(_v,_p) (((struct _gdnsd_una32*)(_p))->x) = (_v)

// Generic useful macros
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// Valgrind hooks for debug builds
#if !defined(NDEBUG) && defined(HAVE_VALGRIND_MEMCHECK_H) && !defined(_CPPCHECK)
#  include <valgrind/memcheck.h>
#define NOWARN_VALGRIND_MAKE_MEM_NOACCESS(x,y) \
    do { int _x V_UNUSED; _x = VALGRIND_MAKE_MEM_NOACCESS(x,y); } while(0)
#else
#  define RUNNING_ON_VALGRIND 0
#  define NOWARN_VALGRIND_MAKE_MEM_NOACCESS(x,y) ((void)(0))
#  define VALGRIND_CREATE_MEMPOOL(x,y,z)  ((void)(0))
#  define VALGRIND_DESTROY_MEMPOOL(x)     ((void)(0))
#  define VALGRIND_MEMPOOL_ALLOC(x,y,z)   ((void)(0))
#endif

// And silence some related warnings on gcc 4.6 + valgrind 3.6
#if !defined(NDEBUG) && defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 5))
#  define NOWARN_VALGRIND_CREATE_MEMPOOL(x,y,z) { \
     _Pragma("GCC diagnostic push"); \
     _Pragma("GCC diagnostic ignored \"-Wunused-but-set-variable\""); \
     VALGRIND_CREATE_MEMPOOL(x,y,z); \
     _Pragma("GCC diagnostic pop"); \
}
#  define NOWARN_VALGRIND_DESTROY_MEMPOOL(x) { \
     _Pragma("GCC diagnostic push"); \
     _Pragma("GCC diagnostic ignored \"-Wunused-but-set-variable\""); \
     VALGRIND_DESTROY_MEMPOOL(x); \
     _Pragma("GCC diagnostic pop"); \
}
#  define NOWARN_VALGRIND_MEMPOOL_ALLOC(x,y,z) { \
     _Pragma("GCC diagnostic push"); \
     _Pragma("GCC diagnostic ignored \"-Wunused-but-set-variable\""); \
     VALGRIND_MEMPOOL_ALLOC(x,y,z); \
     _Pragma("GCC diagnostic pop"); \
}
#else
#  define NOWARN_VALGRIND_CREATE_MEMPOOL(x,y,z) \
     VALGRIND_CREATE_MEMPOOL(x,y,z)
#  define NOWARN_VALGRIND_DESTROY_MEMPOOL(x) \
     VALGRIND_DESTROY_MEMPOOL(x)
#  define NOWARN_VALGRIND_MEMPOOL_ALLOC(x,y,z) \
     VALGRIND_MEMPOOL_ALLOC(x,y,z);
#endif

#endif // GDNSD_COMPILER_H
