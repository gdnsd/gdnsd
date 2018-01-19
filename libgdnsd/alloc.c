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
#include <gdnsd/alloc.h>

#include <gdnsd/log.h>

#include <stdlib.h>

// We don't expect anything to call our allocators for sizes
//   greater than ~2GB in practice, so this makes a good sanity
//   checkpoint for certain classes of allocation size bugs from
//   bad math, memory bugs, and/or overflows that works well in
//   both the 32 and 64 -bit cases.
#define ALLOC_MAX 2147483647LLU

void* gdnsd_xmalloc(size_t size) {
    dmn_assert(size);

    if(size > ALLOC_MAX)
        log_fatal("Bad allocation request for %zu bytes! backtrace:%s",
            size, dmn_logf_bt());

    void* rv = malloc(size);
    if(!rv)
        log_fatal("Cannot allocate %zu bytes (%s)! backtrace:%s",
            size, dmn_logf_errno(), dmn_logf_bt());
    return rv;
}

void* gdnsd_xcalloc(size_t nmemb, size_t size) {
    dmn_assert(size);
    dmn_assert(nmemb);

    if(size > ALLOC_MAX || (uint64_t)size * (uint64_t)nmemb > ALLOC_MAX)
        log_fatal("Bad allocation request for %zu * %zu bytes! backtrace:%s",
            nmemb, size, dmn_logf_bt());

    void* rv = calloc(nmemb, size);
    if(!rv)
        log_fatal("Cannot allocate %zu bytes (%s)! backtrace:%s",
            size * nmemb, dmn_logf_errno(), dmn_logf_bt());
    return rv;
}

void* gdnsd_xrealloc(void* ptr, size_t size) {
    dmn_assert(size);

    if(size > ALLOC_MAX)
        log_fatal("Bad allocation request for %zu bytes! backtrace:%s",
            size, dmn_logf_bt());

    void* rv = realloc(ptr, size);
    if(!rv)
        log_fatal("Cannot allocate %zu bytes (%s)! backtrace:%s",
            size, dmn_logf_errno(), dmn_logf_bt());
    return rv;
}

void* gdnsd_xpmalign(size_t alignment, size_t size) {
    dmn_assert(alignment);
    dmn_assert(size);

    if(size > ALLOC_MAX)
        log_fatal("Bad allocation request for %zu bytes! backtrace:%s",
            size, dmn_logf_bt());

    void* rv = NULL;
    const int pmrv = posix_memalign(&rv, alignment, size);
    if(pmrv || !rv)
        log_fatal("Cannot allocate %zu bytes aligned to %zu (%s)! backtrace:%s",
            size, alignment, dmn_logf_strerror(pmrv), dmn_logf_bt());
    return rv;
}
