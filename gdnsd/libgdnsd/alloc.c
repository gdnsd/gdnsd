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

#include "config.h"

#include <stdlib.h>

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>

void* gdnsd_xmalloc(size_t size) {
    dmn_assert(size);
    void* rv = malloc(size);
    if(!rv)
        log_fatal("memory allocation error!");
    return rv;
}

void* gdnsd_xcalloc(size_t nmemb, size_t size) {
    dmn_assert(size); dmn_assert(nmemb);
    void* rv = calloc(nmemb, size);
    if(!rv)
        log_fatal("memory allocation error!");
    return rv;
}

void* gdnsd_xrealloc(void* ptr, size_t size) {
    dmn_assert(size);
    void* rv = realloc(ptr, size);
    if(!rv)
        log_fatal("memory allocation error!");
    return rv;
}

void* gdnsd_xpmalign(size_t alignment, size_t size) {
    dmn_assert(size); dmn_assert(alignment);
    void* rv = NULL;
    if(posix_memalign(&rv, alignment, size) || !rv)
        log_fatal("memory allocation error!");
    return rv;
}
