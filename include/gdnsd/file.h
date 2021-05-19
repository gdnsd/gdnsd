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
#include <gdnsd/log.h>

#include <sys/types.h>
#include <stdbool.h>

struct fmap {
    void* buf;
    size_t len;
    bool is_mapped;
};

// Given a filename "fn", this will open the file for reading
//   and mmap() it for readonly use.
// On errors, the return value is NULL.
// This can succeed for zero-length files.  In that case the accessors below
//   will return length 0 and a valid pointer to 1 NUL byte.
// "seq" is an optimization hint: set to true if expected buffer access
//   pattern is sequential.
// "mod" gives a writeable private buffer, instead of a readonly shared one
F_NONNULL F_WUNUSED
struct fmap* gdnsd_fmap_new(const char* fn, const bool seq, const bool mod);

// Get the length of the mapped file data (zero is possible)
F_NONNULL F_UNUSED
static size_t gdnsd_fmap_get_len(const struct fmap* fmap)
{
    gdnsd_assume(fmap->buf);
    return fmap->len;
}

// Get the buffer pointer for the mapped file data (always a valid pointer)
F_NONNULL F_RETNN F_UNUSED
static void* gdnsd_fmap_get_buf(const struct fmap* fmap)
{
    gdnsd_assume(fmap->buf);
    return fmap->buf;
}

// Destructs the fmap_t object, which includes unmap() of the memory
//   returned via fmap_get_buf().
// If a destruction step fails, this returns true (in which case the file data
//   should perhaps be considered suspect, even if the caller managed to
//   operate on it without error).
F_NONNULL
bool gdnsd_fmap_delete(struct fmap* fmap);

#endif // GDNSD_FILE_H
