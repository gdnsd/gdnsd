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

#ifndef GDNSD_FILE_H
#define GDNSD_FILE_H

#include <gdnsd/compiler.h>

#include <sys/types.h>
#include <stdbool.h>

struct gdnsd_fmap_s_;
typedef struct gdnsd_fmap_s_ gdnsd_fmap_t;

#pragma GCC visibility push(default)

// Given a filename "fn", this will open the file for reading with an fcntl
//   advisory readlock and mmap() it for readonly use.
// On such errors, the return value is NULL.
// This can succeed for zero-length files.  In that case the accessors below
//   will return length 0 and a valid pointer to 1 NUL byte.
// "seq" is an optimization hint: set to true if expected buffer access
//   pattern is sequential.
F_NONNULL F_WUNUSED
gdnsd_fmap_t* gdnsd_fmap_new(const char* fn, const bool seq);

// Get the length of the mapped file data (zero is possible)
F_NONNULL F_PURE
size_t gdnsd_fmap_get_len(const gdnsd_fmap_t* fmap);

// Get the buffer pointer for the mapped file data (always a valid pointer)
F_NONNULL F_RETNN F_PURE
const void* gdnsd_fmap_get_buf(const gdnsd_fmap_t* fmap);

// Destructs the fmap_t object, which includes unmap() of the memory
//   returned via fmap_get_buf() and closing the file descriptor, which
//   implicitly also releases the fcntl advisory readlock.
// If a destruction step fails, this returns true (in which case the file data
//   should perhaps be considered suspect, even if the caller managed to
//   operate on it without error).
F_NONNULL
bool gdnsd_fmap_delete(gdnsd_fmap_t* fmap);

#pragma GCC visibility pop

#endif // GDNSD_FILE_H
