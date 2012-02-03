/* Copyright © 2011 Brandon L Black <blblack@gmail.com>
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

#include "ltarena.h"
#include "gdnsd-compiler.h"

#include <inttypes.h>
#include <string.h>
#include <sys/mman.h>

// ltarena pool sizing/limits/waste:
//   The arena has a base allocation regardless of how small the
//     zonefile data is.
//   The arena is allocated on-demand in terms of fixed number of pools
//   The size of each pool allocated is at least double the previous
//     size, up to a certain limit.  That limit defines the absolute
//     maximum waste.  Waste is also limited to roughly the total allocated.
//   The arena has a minimum overall allocation limit.  That is to say,
//     depending on usage patterns the maximum limit varies, but we know
//     the limit in the worst (min limit) case.
//   With --enable-lowmem:
//     Base allocation: 16K + 256-512B overhead
//     min allocation limit: ~880MB
//     max waste limit: ~16MB
//   Without --enable-lowmem:
//     Base allocation: 16K + 4-8K overhead
//     min allocation limit: ~253GB
//     max waste limit: ~256MB
#define INIT_POOL_SIZE   (16 * 1024)
#if LOWMEM
#  define NUM_POOLS 64
#  define MAX_POOL_SIZE  (16 * 1024 * 1024)
#else
#  define NUM_POOLS 1024
#  define MAX_POOL_SIZE (256 * 1024 * 1024)
#endif

// Normally, our pools are initialized to all-zeros for us
//   by mmap(), and no red zones are employed.  In debug
//   builds, we initialize a whole pool to 0xDEADBEEF,
//   define a redzone of 2 pointer widths before and after
//   each block, and then zero out the valid allocated area
//   of each block as it's handed out.
#ifndef NDEBUG
#  define RED_SIZE (sizeof(uintptr_t) * 2)
#else
#  define RED_SIZE 0
#endif

static void** pools;

static uint32_t dnhash_count = 0;
static uint32_t dnhash_mask = 511; // must be 2^n - 1
static uint8_t** dnhash;

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#define alloc_mmap(size) \
    mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)

#define dnhash_alloc(_new_mask) \
    (uint8_t**)alloc_mmap(((_new_mask) + 1) * sizeof(uint8_t**))
#define dnhash_unalloc(_x, _old_mask) \
    munmap((void*)(_x), ((_old_mask) + 1) * sizeof(uint8_t**))

static void* make_pool(const unsigned bytes) {
    // basic pool size checks
    dmn_assert(!(bytes & (bytes - 1))); // power of two
    dmn_assert(bytes >= INIT_POOL_SIZE);
    dmn_assert(bytes <= MAX_POOL_SIZE);

    // get mem from mmap, assert pointer-aligned
    void* p = alloc_mmap(bytes);
    dmn_assert(!((uintptr_t)p & (sizeof(uintptr_t) - 1)));

    // fill in deadbeef if using redzones
    if(RED_SIZE) {
        uint32_t* p32 = (uint32_t*)p;
        unsigned idx = bytes >> 2;
        while(idx--)
            p32[idx] = 0xDEADBEEF;
    }

    // let valgrind know what's going on, if running
    //   and we're a debug build
    VALGRIND_MAKE_MEM_NOACCESS(p, bytes);
    NOWARN_VALGRIND_CREATE_MEMPOOL(p, RED_SIZE, 1);

    return p;
}

void lta_init(void) {
    pools = calloc(NUM_POOLS, sizeof(void*));
    pools[0] = make_pool(INIT_POOL_SIZE);
    dnhash = dnhash_alloc(dnhash_mask);
}

void lta_close(void) {
    dnhash_unalloc(dnhash, dnhash_mask);
    dnhash = NULL;
}

// This is almost a complete copy of label_djb_hash from ltree.h,
//  but note that the while loop is on --len instead of len--.  For
//  full domainnames, we don't want to hash the constant \0 terminator
//  (hence --len), whereas for labels we do want to use every byte (len--).
F_PURE
static uint32_t dname_djb_hash(const uint8_t* input, const uint32_t hash_mask) {
   dmn_assert(input);

   uint32_t hash = 5381;
   uint32_t len = *input++;
   while(--len)
       hash = (hash * 33) ^ *input++;

   return hash & hash_mask;
}

static void dnhash_grow(void) {
    dmn_assert(dnhash); dmn_assert(dnhash_count); dmn_assert(dnhash_mask);

    const uint32_t new_mask = (dnhash_mask << 1) | 1;
    uint8_t** new_table = dnhash_alloc(new_mask);
    for(uint32_t i = 0; i <= dnhash_mask; i++) {
        uint8_t* item = dnhash[i];
        if(item) {
            uint32_t jmpby = 1;
            uint32_t new_slot = dname_djb_hash(item, new_mask);
            while(new_table[new_slot]) {
                new_slot += jmpby++;
                new_slot &= new_mask;
            }
            new_table[new_slot] = item;
        }
    }

    dnhash_unalloc(dnhash, dnhash_mask);
    dnhash = new_table;
    dnhash_mask = new_mask;
}

uint8_t* lta_dnamedup_hashed(const uint8_t* dn) {
    dmn_assert(dn); dmn_assert(dnhash); dmn_assert(dnhash_mask);

    uint32_t jmpby = 1;
    uint32_t slotnum = dname_djb_hash(dn, dnhash_mask);
    while(dnhash[slotnum]) {
        if(!memcmp(dnhash[slotnum], dn, *dn + 1))
            return dnhash[slotnum];
        slotnum += jmpby++;
        slotnum &= dnhash_mask;
    }

    uint8_t* retval = dnhash[slotnum] = lta_malloc_1(*dn + 1);
    memcpy(retval, dn, *dn + 1);

    if(++dnhash_count > (dnhash_mask >> 1))
        dnhash_grow();

    return retval;
}

uint8_t* lta_labeldup(const uint8_t* dn) {
    dmn_assert(dn);
    uint8_t* retval = lta_malloc_1(*dn + 1);
    memcpy(retval, dn, *dn + 1);
    return retval;
}

void* lta_malloc(const unsigned size, const unsigned align_bytes) {
    dmn_assert(size); dmn_assert(align_bytes);

    // assert that if alignment is requested, it's for the pointer
    //   size exactly, since that's our only use case currently
    //   the pointer size, so that the redzones don't screw it up
    dmn_assert(align_bytes == 1 || align_bytes == sizeof(uintptr_t));

    // Current pool number, allocation offset, and allocated size
    static unsigned pool = 0;
    static unsigned poffs = 0;
    static unsigned pool_size = INIT_POOL_SIZE;

    // branchless shift of poffs forward for alignment if necessary
    const unsigned align_mask = align_bytes - 1;
    poffs += align_mask;
    poffs &= ~align_mask;

    // the requested size + redzones on either end, giving the total
    //   this allocation will steal from the pool
    const unsigned size_plus_red = size + RED_SIZE + RED_SIZE;

    // Currently, all allocations obey this assertion.  Should stay that way.
    dmn_assert(size_plus_red <= MAX_POOL_SIZE);

    // basic sanity assertions on pool sizing
    dmn_assert(!(pool_size & (pool_size - 1))); // power of two
    dmn_assert(pool_size >= INIT_POOL_SIZE);
    dmn_assert(pool_size <= MAX_POOL_SIZE);

    // handle pool switch if we're out of room.  We at least
    //   double the pool size on each switch, and might double
    //   multiple times if warranted to fit the new object in
    //   the very next pool.
    if(unlikely((poffs + size_plus_red > pool_size))) {
        if(unlikely(++pool == NUM_POOLS))
            log_fatal("lta_malloc(): ran out of pools, zone data too large!");
        if(pool_size < MAX_POOL_SIZE)
            do { pool_size <<= 1; }
                while(size_plus_red > pool_size);
        poffs = 0;
        pools[pool] = make_pool(pool_size);
    }

    // assign the space and move our poffs pointer
    void* rval = (void*)((uintptr_t)pools[pool] + poffs + RED_SIZE);
    poffs += size_plus_red;

    // mark the allocation for valgrind and zero it if doing redzone stuff
    NOWARN_VALGRIND_MEMPOOL_ALLOC(pools[pool], rval, size);
    if(RED_SIZE)
        memset(rval, 0, size);

    return rval;
}
