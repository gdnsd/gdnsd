/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
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
#include "ltarena.h"

#include <gdnsd/alloc.h>
#include <gdnsd/compiler.h>
#include <gdnsd/dname.h>

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

// ltarena: used for dname/label strings only, pooled to
//   reduce the per-alloc overhead of malloc aligning and
//   tracking every single one needlessly.
// Each pool is normally POOL_SIZE, non-growing to preserve
//   *some* amount of locality-of-reference to the related
//   objects referencing the strings.
// We initially reserve room in the ltarena object to track
//   4 pools, which expands by doubling to support far more
//   pools than needed by even the largest zones in existence.
#define POOL_SIZE 1024U // *must* be >= (256 + (red_size*2)) && multiple of 4
#define INIT_POOLS_ALLOC 4U // *must* be 2^n && > 0

// Normally, our pools are initialized to all-zeros for us
//   by xcalloc(), and no red zones are employed.  In debug
//   builds, we initialize a whole pool to 0xDEADBEEF,
//   define a redzone of 4 bytes before and after
//   each block, and then zero out the valid allocated area
//   of each block as it's handed out.
#ifndef NDEBUG
#  define RED_SIZE 4
#else
#  define RED_SIZE 0
#endif

struct ltarena {
    uint8_t** pools;
    size_t pool;
    size_t poffs;
    size_t palloc;
};

static void* make_pool(void)
{
    gdnsd_assert(!(POOL_SIZE & 3U)); // multiple of four

    void* p;
    if (RED_SIZE) {
        // malloc + fill in deadbeef if using redzones
        p = xmalloc(POOL_SIZE);
        uint32_t* p32 = p;
        size_t idx = POOL_SIZE >> 2U;
        while (idx--)
            p32[idx] = 0xDEADBEEF;
    } else {
        // get mem from calloc
        p = xcalloc(POOL_SIZE);
    }

    // let valgrind know what's going on, if running
    //   and we're a debug build
    VALGRIND_MAKE_MEM_NOACCESS(p, POOL_SIZE);
    VALGRIND_CREATE_MEMPOOL(p, RED_SIZE, 1U);

    return p;
}

ltarena_t* lta_new(void)
{
    ltarena_t* rv = xcalloc(sizeof(*rv));
    rv->palloc = INIT_POOLS_ALLOC;
    rv->pools = xmalloc_n(INIT_POOLS_ALLOC, sizeof(*rv->pools));
    rv->pools[0] = make_pool();
    return rv;
}

void lta_close(ltarena_t* lta)
{
    lta->pools = xrealloc_n(lta->pools, lta->pool + 1, sizeof(*lta->pools));
}

void lta_destroy(ltarena_t* lta)
{
    lta_close(lta);
    size_t whichp = lta->pool + 1U;
    while (whichp--) {
        VALGRIND_DESTROY_MEMPOOL(lta->pools[whichp]);
        free(lta->pools[whichp]);
    }
    free(lta->pools);
    free(lta);
}

uint8_t* lta_malloc(ltarena_t* lta, const size_t size)
{
    gdnsd_assert(size);

    // Currently, all allocations obey this assertion.
    // Only labels + dnames are stored here, which max out at 256
    gdnsd_assert(size <= 256);

    // the requested size + redzones on either end, giving the total
    //   this allocation will steal from the pool
    const size_t size_plus_red = size + RED_SIZE + RED_SIZE;

    // this could be a compile-time check, just stuffing here instead for now
    gdnsd_assert(POOL_SIZE >= (256 + RED_SIZE + RED_SIZE));

    // This logically follows from the above asserts, but JIC
    gdnsd_assert(size_plus_red <= POOL_SIZE);

    // handle pool switch if we're out of room
    //   + take care to extend the pools array if necc.
    if (unlikely((lta->poffs + size_plus_red > POOL_SIZE))) {
        if (unlikely(++lta->pool == lta->palloc)) {
            lta->palloc <<= 1U;
            lta->pools = xrealloc_n(lta->pools, lta->palloc, sizeof(*lta->pools));
        }
        lta->pools[lta->pool] = make_pool();
        lta->poffs = 0;
    }

    // assign the space and move our poffs pointer
    uint8_t* rval = &lta->pools[lta->pool][lta->poffs + RED_SIZE];
    lta->poffs += size_plus_red;

    // mark the allocation for valgrind and zero it if doing redzone stuff
    VALGRIND_MEMPOOL_ALLOC(lta->pools[lta->pool], rval, size);
    if (RED_SIZE)
        memset(rval, 0, size);

    return rval;
}
