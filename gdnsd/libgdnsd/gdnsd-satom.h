/* Copyright © 2011 Brandon L Black <blblack@gmail.com>
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

#ifndef _GDNSD_SATOM_H
#define _GDNSD_SATOM_H

// For uintptr_t
#include <inttypes.h>

#include <gdnsd-compiler.h>
#include <gdnsd-dmn.h>

/*
 * satom_t and friends:
 *
 * These are not for true atomic operations !!
 *
 * These are special purpose constructs, to be used only
 * in certain circumstances.  I'm calling them "semi-atomic".
 *
 * It assumes that read and write operations to a volatile
 * uinptr_t are atomic (as in nobody will ever see an intermediate,
 * half-updated uintptr_t) with respect to POSIX threads.
 * This is used for one writer + many readers, not for concurrent
 * writes and certainly not for concurrent read-modify-write.
 *
 * This isn't a portable set of assumptions (I don't think),
 * but it should work fine on sane, mainstream, modern targets.
 *
 */

typedef uintptr_t satom_uint_t;
typedef struct { volatile satom_uint_t _x; } satom_t;

F_NONNULL
static inline satom_uint_t satom_get(const satom_t* s) { dmn_assert(s); return s->_x; }

F_NONNULL
static inline void satom_set(satom_t* s, const satom_uint_t v) { dmn_assert(s); s->_x = v; }

F_NONNULL
static inline void satom_inc(satom_t* s) { dmn_assert(s); s->_x++; }

#endif // _GDNSD_SATOM_H
