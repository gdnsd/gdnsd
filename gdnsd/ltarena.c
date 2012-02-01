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

#include <string.h>
#include <sys/mman.h>

// --enable-lowmem: up to 64MB as 256 pools of 256K
// 32-bit machines: up to 2GB as 2K pools of 1M
// 64-bit machines: up to 32GB as 8K pools of 4M
#if LOWMEM
#  define NUM_POOLS 256
#  define POOL_SIZE 262144
#else
#  if SIZEOF_UINTPTR_T == 4
#    define NUM_POOLS 2048
#    define POOL_SIZE 1048576
#  else
#    define NUM_POOLS 8192
#    define POOL_SIZE 4194304
#  endif
#endif

static unsigned pool = 0;
static unsigned poffs = 0;
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

void lta_init(void) {
#if LOWMEM
    pools = calloc(NUM_POOLS, sizeof(void*));
#else
    pools = alloc_mmap(NUM_POOLS * sizeof(void*));
#endif
    pools[0] = alloc_mmap(POOL_SIZE);
    VALGRIND_MAKE_MEM_NOACCESS(pools[0], POOL_SIZE);
    NOWARN_VALGRIND_CREATE_MEMPOOL(pools[0], 0, 1);
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

void* lta_malloc(unsigned size, unsigned align_bytes) {
    dmn_assert(size); dmn_assert(align_bytes);

    // shift poffs forward for alignment if necessary
    unsigned align_mask = align_bytes - 1;
    if(poffs & align_mask) {
        poffs &= ~align_mask;
        poffs += align_bytes;
    }

    // handle pool switch if we're out of room
    if(unlikely((size > (POOL_SIZE - poffs)))) {
        if(unlikely(size > POOL_SIZE))
            log_fatal("attempted to lta_malloc() a block of size %u", size);
        if(unlikely(++pool == NUM_POOLS))
            log_fatal("lta ran out of pools!");
        pools[pool] = alloc_mmap(POOL_SIZE);
        poffs = 0;
        VALGRIND_MAKE_MEM_NOACCESS(pools[pool], POOL_SIZE);
        NOWARN_VALGRIND_CREATE_MEMPOOL(pools[pool], 0, 1);
    }

    // assign the space and move our poffs pointer
    void* rval = (void*)((uintptr_t)pools[pool] + poffs);
    poffs += size;

    NOWARN_VALGRIND_MEMPOOL_ALLOC(pools[pool], rval, size);
    return rval;
}

