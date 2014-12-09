/* Copyright © 2014 Brandon L Black <blblack@gmail.com>
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

#ifndef GDNSD_ALLOC_H
#define GDNSD_ALLOC_H

#include <gdnsd/compiler.h>

#include <sys/types.h>

#pragma GCC visibility push(default)

// These internally check for errors and throw
//   fatal exceptions.  They also do not allow
//   the use of size==0 as an alternative syntax
//   for free() (this is checked in debug builds).
//   These functions *never* return NULL.

F_MALLOC F_ALLOCSZ(1) F_WUNUSED F_RETNN
void* gdnsd_xmalloc(size_t size);

F_MALLOC F_ALLOCSZ(1,2) F_WUNUSED F_RETNN
void* gdnsd_xcalloc(size_t nmemb, size_t size);

F_ALLOCSZ(2) F_WUNUSED F_RETNN
void* gdnsd_xrealloc(void* ptr, size_t size);

F_MALLOC F_ALLOCSZ(2) F_ALLOCAL(1) F_WUNUSED F_RETNN
void* gdnsd_xpmalign(size_t alignment, size_t size);

#pragma GCC visibility pop

#define xmalloc gdnsd_xmalloc
#define xcalloc gdnsd_xcalloc
#define xrealloc gdnsd_xrealloc

#endif // GDNSD_ALLOC_H
