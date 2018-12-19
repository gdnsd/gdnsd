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
#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>

// Fast ok if both numbers < half of size_t, otherwise slow division check
// This is basically what jemalloc does, seems pretty reasonable.
F_CONST
static bool mul_ok(size_t n, size_t s, size_t m)
{
    static const size_t st_high_bits = SIZE_MAX << (sizeof(size_t) * 8 / 2);
    return likely((st_high_bits & (n | s)) == 0) || likely(m / s == n);
}

void* gdnsd_xmalloc(size_t size)
{
    void* rv = malloc(size);
    if (unlikely(!size) || unlikely(!rv))
        log_fatal("Cannot allocate %zu bytes (%s)! backtrace:%s",
                  size, logf_errno(), logf_bt());
    return rv;
}

void* gdnsd_xmalloc_n(size_t nmemb, size_t size)
{
    const size_t full_size = nmemb * size;
    void* rv = malloc(full_size);
    if (unlikely(!full_size) || unlikely(!rv) || unlikely(!mul_ok(nmemb, size, full_size)))
        log_fatal("Cannot allocate %zu * %zu bytes (%s)! backtrace:%s",
                  nmemb, size, logf_errno(), logf_bt());
    return rv;
}

void* gdnsd_xcalloc(size_t size)
{
    void* rv = calloc(1U, size);
    if (unlikely(!size) || unlikely(!rv))
        log_fatal("Cannot allocate %zu bytes (%s)! backtrace:%s",
                  size, logf_errno(), logf_bt());
    return rv;
}

void* gdnsd_xcalloc_n(size_t nmemb, size_t size)
{
    const size_t full_size = nmemb * size;
    void* rv = calloc(nmemb, size);
    if (unlikely(!full_size) || unlikely(!rv) || unlikely(!mul_ok(nmemb, size, full_size)))
        log_fatal("Cannot allocate %zu * %zu bytes (%s)! backtrace:%s",
                  nmemb, size, logf_errno(), logf_bt());
    return rv;
}

void* gdnsd_xrealloc(void* ptr, size_t size)
{
    void* rv = realloc(ptr, size);
    if (unlikely(!size) || unlikely(!rv))
        log_fatal("Cannot allocate %zu bytes (%s)! backtrace:%s",
                  size, logf_errno(), logf_bt());
    return rv;
}

void* gdnsd_xrealloc_n(void* ptr, size_t nmemb, size_t size)
{
    const size_t full_size = nmemb * size;
    void* rv = realloc(ptr, full_size);
    if (unlikely(!full_size) || unlikely(!rv) || unlikely(!mul_ok(nmemb, size, full_size)))
        log_fatal("Cannot allocate %zu * %zu bytes (%s)! backtrace:%s",
                  nmemb, size, logf_errno(), logf_bt());
    return rv;
}

void* gdnsd_xpmalign(size_t alignment, size_t size)
{
    void* rv = NULL;
    const int pmrv = posix_memalign(&rv, alignment, size);
    if (unlikely(!size) || unlikely(pmrv) || unlikely(!rv))
        log_fatal("Cannot allocate %zu bytes aligned to %zu (%s)! backtrace:%s",
                  size, alignment, logf_strerror(pmrv), logf_bt());
    return rv;
}

void* gdnsd_xpmalign_n(size_t alignment, size_t nmemb, size_t size)
{
    const size_t full_size = nmemb * size;
    void* rv = NULL;
    const int pmrv = posix_memalign(&rv, alignment, full_size);
    if (unlikely(!full_size) || unlikely(pmrv) || unlikely(!rv) || unlikely(!mul_ok(nmemb, size, full_size)))
        log_fatal("Cannot allocate %zu * %zu bytes aligned to %zu (%s)! backtrace:%s",
                  nmemb, size, alignment, logf_strerror(pmrv), logf_bt());
    return rv;
}

char* gdnsd_xstrdup(const char* s)
{
    char* rv = strdup(s);
    if (unlikely(!rv))
        log_fatal("strdup() failed: %s! backtrace:%s", logf_errno(), logf_bt());
    return rv;
}
