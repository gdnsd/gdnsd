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
#include <string.h>

// These functions *never* return NULL.  They internally check for errors and
// throw fatal exceptions on attempts to allocate zero bytes or >size_t bytes
// as well as OOM and other conditions signalled by the underlying libc
// allocators.

F_MALLOC F_ALLOCSZ(1) F_RETNN
void* gdnsd_xmalloc(size_t size);

F_MALLOC F_ALLOCSZ(1, 2) F_RETNN
void* gdnsd_xmalloc_n(size_t nmemb, size_t size);

F_MALLOC F_ALLOCSZ(1) F_RETNN
void* gdnsd_xcalloc(size_t size);

F_MALLOC F_ALLOCSZ(1, 2) F_RETNN
void* gdnsd_xcalloc_n(size_t nmemb, size_t size);

F_ALLOCSZ(2) F_WUNUSED F_RETNN
void* gdnsd_xrealloc(void* ptr, size_t size);

F_ALLOCSZ(2, 3) F_WUNUSED F_RETNN
void* gdnsd_xrealloc_n(void* ptr, size_t nmemb, size_t size);

F_MALLOC F_ALLOCSZ(2) F_ALLOCAL(1) F_RETNN
void* gdnsd_xpmalign(size_t alignment, size_t size);

F_MALLOC F_ALLOCSZ(2, 3) F_ALLOCAL(1) F_RETNN
void* gdnsd_xpmalign_n(size_t alignment, size_t nmemb, size_t size);

F_MALLOC F_NONNULL F_RETNN
char* gdnsd_xstrdup(const char* s);

#define xmalloc gdnsd_xmalloc
#define xmalloc_n gdnsd_xmalloc_n
#define xcalloc gdnsd_xcalloc
#define xcalloc_n gdnsd_xcalloc_n
#define xrealloc gdnsd_xrealloc
#define xrealloc_n gdnsd_xrealloc_n
#define xstrdup gdnsd_xstrdup

#endif // GDNSD_ALLOC_H
