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

#include <config.h>
#include <gdnsd/file.h>

#include <gdnsd/compiler.h>
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

struct gdnsd_fmap_s_ {
    void* buf;
    size_t len;
};

gdnsd_fmap_t* gdnsd_fmap_new(const char* fn, const bool seq, const bool mod)
{
    const int fd = open(fn, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        log_err("Cannot open '%s' for reading: %s", fn, logf_errno());
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        log_err("Cannot fstat '%s': %s", fn, logf_errno());
        close(fd);
        return NULL;
    }

    // S_ISREG won't fail on symlink here, because this is fstat()
    //   and the earlier open() didn't use O_NOFOLLOW.
    if (!S_ISREG(st.st_mode) || st.st_size < 0) {
        log_err("'%s' is not a regular file", fn);
        close(fd);
        return NULL;
    }

    const size_t len = (size_t)st.st_size;
    char* mapbuf = NULL;

    if (len) {
        const int prot = mod ? (PROT_READ | PROT_WRITE) : PROT_READ;
        const int flags = mod ? MAP_PRIVATE : MAP_SHARED;
        mapbuf = mmap(NULL, len, prot, flags, fd, 0);
        if (mapbuf == MAP_FAILED) {
            log_err("Cannot mmap '%s': %s", fn, logf_errno());
            close(fd);
            return NULL;
        }
        int advice = POSIX_MADV_WILLNEED;
        if (seq)
            advice |= POSIX_MADV_SEQUENTIAL;
        else
            advice |= POSIX_MADV_RANDOM;
        (void)posix_madvise(mapbuf, len, advice);
    } else {
        // mmap doesn't always work for zero-length files, and we also
        //   don't want callers to have to care about cases where this call
        //   was successful but the buffer pointer is NULL due to len == 0,
        //   so allocate a 1-byte buffer containing a NUL for these cases.
        mapbuf = xcalloc(1);
    }

    if (close(fd))
        log_err("Cannot close '%s', continuing anyways: %s", fn, logf_errno());

    gdnsd_fmap_t* fmap = xmalloc(sizeof(*fmap));
    fmap->buf = mapbuf;
    fmap->len = len;

    return fmap;
}

void* gdnsd_fmap_get_buf(const gdnsd_fmap_t* fmap)
{
    gdnsd_assert(fmap->buf);
    return fmap->buf;
}

size_t gdnsd_fmap_get_len(const gdnsd_fmap_t* fmap)
{
    gdnsd_assert(fmap->buf);
    return fmap->len;
}

bool gdnsd_fmap_delete(gdnsd_fmap_t* fmap)
{
    gdnsd_assert(fmap->buf);

    bool rv = false; // true == error
    if (fmap->len) {
        if (munmap(fmap->buf, fmap->len)) {
            log_err("Cannot munmap() %p: %s", fmap->buf, logf_errno());
            rv = true;
        }
    } else {
        free(fmap->buf);
    }

    free(fmap);
    return rv;
}
