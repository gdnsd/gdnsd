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
//   8 pools, which expands by doubling to support far more
//   pools than needed by even the largest zones in existence.
#define POOL_SIZE 512U // *must* be >= (256 + (red_size*2)),
                       //    && multiple of 4
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

// INIT_DNHASH_MASK + 1 is the initial number of slots
//   in the dnhash table, which grows by doubling every
//   time the count of stored unique dnames reaches half
//   the slot count.
#define INIT_DNHASH_MASK 31U // *must* be 2^n-1 && > 0

typedef struct {
    unsigned count;
    unsigned mask;
    const uint8_t** table;
} dnhash_t;

F_MALLOC
static dnhash_t* dnhash_new(void) {
    dmn_assert(INIT_DNHASH_MASK);
    dmn_assert(!((INIT_DNHASH_MASK + 1U) & INIT_DNHASH_MASK)); // 2^n-1

    dnhash_t* rv = xmalloc(sizeof(dnhash_t));
    rv->count = 0;
    rv->mask = INIT_DNHASH_MASK;
    rv->table = xcalloc(INIT_DNHASH_MASK + 1U, sizeof(uint8_t*));
    return rv;
}

F_NONNULL
static void dnhash_destroy(dnhash_t* dnhash) {
    dmn_assert(dnhash->table);
    dmn_assert(dnhash->mask);
    free(dnhash->table);
    free(dnhash);
}

// grow a dnhash_t's hashtable size by doubling
F_NONNULL
static void dnhash_grow(dnhash_t* dnhash) {
    dmn_assert(dnhash->count);
    // assert that dnhash->mask is still 2^n-1 and >0
    dmn_assert(dnhash->mask); dmn_assert(!((dnhash->mask + 1U) & dnhash->mask));

    const uint8_t** old_table = dnhash->table;
    const unsigned old_mask = dnhash->mask;
    const unsigned new_mask = (old_mask << 1U) | 1U;
    const uint8_t** new_table = xcalloc(new_mask + 1U, sizeof(uint8_t*));
    for(unsigned i = 0; i <= old_mask; i++) {
        const uint8_t* item = old_table[i];
        if(item) {
            unsigned jmpby = 1U;
            unsigned new_slot = dname_hash(item) & new_mask;
            while(new_table[new_slot]) {
                new_slot += jmpby++;
                new_slot &= new_mask;
            }
            new_table[new_slot] = item;
        }
    }

    free(dnhash->table);
    dnhash->table = new_table;
    dnhash->mask = new_mask;
}

struct _ltarena {
    uint8_t** pools;
    unsigned pool;
    unsigned poffs;
    unsigned palloc;
    dnhash_t* dnhash;
};

static void* make_pool(void) {
    dmn_assert(!(POOL_SIZE & 3U)); // multiple of four

    void* p;
    if(RED_SIZE) {
        // malloc + fill in deadbeef if using redzones
        p = xmalloc(POOL_SIZE);
        uint32_t* p32 = p;
        unsigned idx = POOL_SIZE >> 2U;
        while(idx--)
            p32[idx] = 0xDEADBEEF;
    }
    else {
        // get mem from calloc
        p = xcalloc(1, POOL_SIZE);
    }

    // let valgrind know what's going on, if running
    //   and we're a debug build
    NOWARN_VALGRIND_MAKE_MEM_NOACCESS(p, POOL_SIZE);
    NOWARN_VALGRIND_CREATE_MEMPOOL(p, RED_SIZE, 1U);

    return p;
}

ltarena_t* lta_new(void) {
    ltarena_t* rv = xcalloc(1, sizeof(ltarena_t));
    rv->palloc = INIT_POOLS_ALLOC;
    rv->pools = xmalloc(INIT_POOLS_ALLOC * sizeof(uint8_t*));
    rv->pools[0] = make_pool();
    rv->dnhash = dnhash_new();
    return rv;
}

void lta_close(ltarena_t* lta) {
    if(lta->dnhash) {
        dnhash_destroy(lta->dnhash);
        lta->dnhash = NULL;
        lta->pools = xrealloc(lta->pools, (lta->pool + 1) * sizeof(uint8_t*));
    }
}

void lta_destroy(ltarena_t* lta) {
    lta_close(lta);
    unsigned whichp = lta->pool + 1U;
    while(whichp--) {
        NOWARN_VALGRIND_DESTROY_MEMPOOL(lta->pools[whichp]);
        free(lta->pools[whichp]);
    }
    free(lta->pools);
    free(lta);
}

F_MALLOC F_NONNULL
static uint8_t* lta_malloc(ltarena_t* lta, const unsigned size) {
    dmn_assert(size);
    dmn_assert(lta->dnhash); // not closed

    // Currently, all allocations obey this assertion.
    // Only labels + dnames are stored here, which max out at 256
    dmn_assert(size <= 256);

    // the requested size + redzones on either end, giving the total
    //   this allocation will steal from the pool
    const unsigned size_plus_red = size + RED_SIZE + RED_SIZE;

    // this could be a compile-time check, just stuffing here instead for now
    dmn_assert(POOL_SIZE >= (256 + RED_SIZE + RED_SIZE));

    // This logically follows from the above asserts, but JIC
    dmn_assert(size_plus_red <= POOL_SIZE);

    // handle pool switch if we're out of room
    //   + take care to extend the pools array if necc.
    if(unlikely((lta->poffs + size_plus_red > POOL_SIZE))) {
        if(unlikely(++lta->pool == lta->palloc)) {
            lta->palloc <<= 1U;
            lta->pools = xrealloc(lta->pools, lta->palloc * sizeof(uint8_t*));
        }
        lta->pools[lta->pool] = make_pool();
        lta->poffs = 0;
    }

    // assign the space and move our poffs pointer
    uint8_t* rval = &lta->pools[lta->pool][lta->poffs + RED_SIZE];
    lta->poffs += size_plus_red;

    // mark the allocation for valgrind and zero it if doing redzone stuff
    NOWARN_VALGRIND_MEMPOOL_ALLOC(lta->pools[lta->pool], rval, size);
    if(RED_SIZE)
        memset(rval, 0, size);

    return rval;
}

uint8_t* lta_labeldup(ltarena_t* lta, const uint8_t* label) {
    const unsigned sz = *label + 1U;
    uint8_t* rv = lta_malloc(lta, sz);
    memcpy(rv, label, sz);
    return rv;
}

// this mixes internal access to dnhash_t as well, so it's not
//   properly a just method of ltarena_t in that sense.
const uint8_t* lta_dnamedup(ltarena_t* lta, const uint8_t* dname) {
    dnhash_t* dnhash = lta->dnhash;
    dmn_assert(dnhash); // not closed

    const unsigned hmask = dnhash->mask;
    const uint8_t** table = dnhash->table;
    uint32_t jmpby = 1U;
    uint32_t slotnum = dname_hash(dname) & hmask;
    while(table[slotnum]) {
        if(!gdnsd_dname_cmp(dname, table[slotnum]))
            return table[slotnum];
        slotnum += jmpby++;
        slotnum &= hmask;
    }

    const unsigned dnlen = *dname + 1U;
    uint8_t* retval = lta_malloc(lta, dnlen);
    table[slotnum] = retval;
    memcpy(retval, dname, dnlen);

    if(++dnhash->count > (dnhash->mask >> 1U))
        dnhash_grow(dnhash);

    return retval;
}
