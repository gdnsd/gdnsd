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
#include <gdnsd/dmn.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

struct gdnsd_fmap_s_ {
    char* fn;
    int fd;
    void* buf;
    size_t len;
};

// We prefer F_OFD_SETLK because it may save us in some strange corner cases
//   where e.g. a library used by gdnsd or a plugin locks/unlocks the same
//   pathname that an explicit user of this interface held a lock on, because
//   with traditional F_SETLK the library's independent lock release will also
//   release the lock we set here :/
// However, we're not relying on the distinctions about fork() inheritance, as
//   no part of gdnsd should be forking while an fmap is open.  Therefore,
//   regular F_SETLK is acceptable on systems that lack F_OFD_SETLK.
#ifndef F_OFD_SETLK
#define F_OFD_SETLK F_SETLK
#endif

gdnsd_fmap_t* gdnsd_fmap_new(const char* fn, const bool seq) {
    dmn_assert(fn);

    int fd = open(fn, O_RDONLY | O_CLOEXEC);

    if(fd < 0) {
        dmn_log_err("Cannot open '%s' for reading: %s", fn, dmn_logf_errno());
        return NULL;
    }

    struct flock locker;
    memset(&locker, 0, sizeof(struct flock));
    locker.l_type = F_RDLCK;
    locker.l_whence = SEEK_SET;
    if(fcntl(fd, F_OFD_SETLK, &locker)) {
        // try fallback to F_SETLK on EINVAL, in case binary was built with
        // F_OFD_SETLK support, but runtime kernel doesn't have it.
        if(errno != EINVAL
            || (F_OFD_SETLK != F_SETLK && fcntl(fd, F_SETLK, &locker))) {
                dmn_log_err("Cannot get readlock on '%s': %s", fn, dmn_logf_errno());
                close(fd);
                return NULL;
        }
    }

    struct stat st;
    if(fstat(fd, &st) < 0) {
        dmn_log_err("Cannot fstat '%s': %s", fn, dmn_logf_errno());
        close(fd);
        return NULL;
    }

    // S_ISREG won't fail on symlink here, because this is fstat()
    //   and the earlier open() didn't use O_NOFOLLOW.
    if(!S_ISREG(st.st_mode) || st.st_size < 0) {
        dmn_log_err("'%s' is not a regular file", fn);
        close(fd);
        return NULL;
    }

    const size_t len = (size_t)st.st_size;
    char* mapbuf = NULL;

    if(len) {
        mapbuf = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
        if(mapbuf == MAP_FAILED) {
            dmn_log_err("Cannot mmap '%s': %s\n", fn, dmn_logf_errno());
            close(fd);
            // cppcheck-suppress memleak (MAP_FAILED is not a leak :P)
            return NULL;
        }
#ifdef HAVE_POSIX_MADVISE
        if(seq && len > 8192) // why waste the syscall on small files?
            (void)posix_madvise(mapbuf, len, POSIX_MADV_SEQUENTIAL);
#endif
    }
    else {
        // mmap doesn't always work for zero-length files, and we also
        //   don't want callers to have to care about cases where this call
        //   was successful but the buffer pointer is NULL due to len == 0,
        //   so allocate a 1-byte buffer containing a NUL for these cases.
        close(fd);
        fd = -1; // signals this mode of operation for fmap_delete()
        mapbuf = xcalloc(1, 1);
    }

    gdnsd_fmap_t* fmap = xmalloc(sizeof(*fmap));
    fmap->fn = strdup(fn);
    fmap->fd = fd;
    fmap->buf = mapbuf;
    fmap->len = len;

    return fmap;
}

const void* gdnsd_fmap_get_buf(const gdnsd_fmap_t* fmap) {
    dmn_assert(fmap);
    dmn_assert(fmap->buf);
    return fmap->buf;
}

size_t gdnsd_fmap_get_len(const gdnsd_fmap_t* fmap) {
    dmn_assert(fmap);
    dmn_assert(fmap->buf);
    return fmap->len;
}

bool gdnsd_fmap_delete(gdnsd_fmap_t* fmap) {
    dmn_assert(fmap);
    dmn_assert(fmap->buf);

    bool rv = false; // true == error
    if(fmap->fd >= 0) {
        dmn_assert(fmap->len);
        if(munmap(fmap->buf, fmap->len) || close(fmap->fd)) {
            dmn_log_err("Cannot munmap()/close() '%s': %s\n",
                fmap->fn, dmn_logf_errno());
            rv = true;
        }
    }
    else {
        dmn_assert(!fmap->len);
        free(fmap->buf);
    }

    free(fmap->fn);
    free(fmap);

    return rv;
}
