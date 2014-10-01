/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
 *
 * This file is part of gdnsd.
 *
 * gdnsd-plugin-geoip is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * gdnsd-plugin-geoip is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gdnsd.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// fips104.c - FIPS 10-4 2-letter region code -> full text

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include <gdnsd/alloc.h>
#include <gdnsd/dmn.h>
#include <gdnsd/log.h>
#include <gdnsd/paths.h>

#include "fips104.h"
#include "gdmaps.h"

// Data source URL is http://www.maxmind.com/download/geoip/misc/region_codes.csv
// As of this writing (Mar 13, 2014), the file had a Last-Modified header of
//  "Thu, 30 Jan 2014 18:27:35 GMT" and was 75728 bytes long with 4066 lines/records.

// I expect the record count to be relatively stable in the long
//  term, so I'm picking a fixed hash table size that's a bit
//  over 4x the count and doing an open-address thing.
// Must be a power of two for simple masking.
#define FIPS_HASH_SIZE 16384
#define FIPS_HASH_MASK (FIPS_HASH_SIZE - 1)

typedef struct {
    char* val;
    uint32_t key;
} fips_node_t;

struct _fips_t {
    fips_node_t table[FIPS_HASH_SIZE];
};

// keys are a uint32_t made of 4 bytes: CCRR (Country/Region)
F_CONST
static unsigned fips_djb_hash(uint32_t key) {
   dmn_assert(key);

   unsigned hash = 5381U;
   hash = (hash * 33) ^ (key & 0xFFU);
   hash = (hash * 33) ^ ((key & 0xFF00U) >> 8U);
   hash = (hash * 33) ^ ((key & 0xFF0000U) >> 16U);
   hash = (hash * 33) ^ ((key & 0xFF000000U) >> 24U);

   return hash & FIPS_HASH_MASK;
}

// It is assumed there are no duplicates in the input data.
F_NONNULL
static void fips_hash_add(fips_t* fips, const uint32_t key, const char* val) {
    dmn_assert(fips);
    dmn_assert(key);
    dmn_assert(val);

    unsigned jmpby = 1;
    unsigned slotnum = fips_djb_hash(key);
    while(fips->table[slotnum].key)
        slotnum = (slotnum + jmpby++) & FIPS_HASH_MASK;
    fips->table[slotnum].key = key;
    fips->table[slotnum].val = strdup(val);
}

F_NONNULL
static void fips_parse(fips_t* fips, FILE* file) {
    dmn_assert(fips); dmn_assert(file);

    unsigned line = 0;
    while(1) {
        char ccrr[5];
        char rname[81];

        line++;
        const int fsf_rv = fscanf(file, "%2[A-Z0-9],%2[A-Z0-9],\"%80[^\"\n]\"\n",
            ccrr, ccrr + 2, rname);

        if(fsf_rv != 3) {
            if(fsf_rv != EOF)
                log_fatal("plugin_geoip: parse error in FIPS region name data, line %u", line);
            return;
        }

        uint32_t key = ((unsigned)ccrr[0])
            + ((unsigned)ccrr[1] << 8U)
            + ((unsigned)ccrr[2] << 16U)
            + ((unsigned)ccrr[3] << 24U);

        fips_hash_add(fips, key, rname);
    }
}

/**** public interface ****/

const char* fips_lookup(const fips_t* fips, const uint32_t key) {
    dmn_assert(fips);
    dmn_assert(key);

    unsigned jmpby = 1;
    unsigned slotnum = fips_djb_hash(key);
    while(fips->table[slotnum].key) {
        if(fips->table[slotnum].key == key)
            return fips->table[slotnum].val;
        slotnum = (slotnum + jmpby++) & FIPS_HASH_MASK;
    }

    return NULL;
}

fips_t* fips_init(const char* pathname) {
    dmn_assert(pathname);

    FILE* file = fopen(pathname, "r");
    if(!file)
        log_fatal("plugin_geoip: Cannot fopen() FIPS region file '%s' for reading: %s", pathname, dmn_logf_errno());
    fips_t* fips = xcalloc(1, sizeof(fips_t));
    fips_parse(fips, file);
    if(fclose(file))
        log_fatal("plugin_geoip: fclose() of FIPS region file '%s' failed: %s", pathname, dmn_logf_errno());
    return fips;
}

void fips_destroy(fips_t* fips) {
    dmn_assert(fips);

    for(unsigned i = 0; i < FIPS_HASH_SIZE; i++)
        if(fips->table[i].val)
            free(fips->table[i].val);
    free(fips);
}
