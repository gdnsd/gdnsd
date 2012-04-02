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

#include "zlist.h"

#include <sys/types.h>
#include <dirent.h>

#include "zone.h"
#include "zscan.h"
#include "gdnsd-dname.h"
#include "gdnsd-misc.h"

static zone_t** zlist = NULL;
static unsigned zlist_alloc = 0;
static unsigned num_zones = 0;

// when a zone_t* is deleted from the hashtable,
//   its pointer is replaced with this magic value
//   so that the closed hash can skip over it, and
//   new insertions can re-use the slot if/when
//   applicable.
const void* ZONE_DELETED = (void*)(uintptr_t)0xFFFFFFFF;

F_PURE
static unsigned zlist_djb_hash(const uint8_t* dname) {
   dmn_assert(dname);

   unsigned hash = 5381U;
   unsigned len = *dname++;
   while(--len)
       hash = (hash * 33U) ^ *dname++;

   return hash;
}

// "dname" can be any legal FQDN
// Current implementation starts by searching for "dname" itself
//   as a zone name, and then chops off labels from the left hand
//   side one at a time to search deeper.
zone_t* zlist_find_dname(const uint8_t* dname, unsigned* auth_depth_out) {
    dmn_assert(dname);

    uint8_t dncpy[256];
    gdnsd_dname_copy(dncpy, dname);
    uint8_t* dnptr = dncpy;

    const unsigned hash_mask = zlist_alloc - 1;

    zone_t* rv = NULL;
    do {
        const unsigned dhash = zlist_djb_hash(dnptr);
        unsigned slot = dhash & hash_mask;
        unsigned jmpby = 1;
        while(zlist[slot]) {
            zone_t* zone = zlist[slot];
            if(zone != ZONE_DELETED && zone->hash == dhash && !dname_cmp(zone->dname, dnptr)) {
                rv = zone;
                goto out;
            }
            slot += jmpby++;
            slot &= hash_mask;
        }

        const unsigned dlen = *dnptr++;
        const unsigned llen = *dnptr;
        if(!llen)
            goto out;
        dnptr += llen;
        *dnptr = dlen - llen - 1;
    } while(1);

    out:
    if(auth_depth_out)
        *auth_depth_out = dnptr - dncpy;

    return rv;
}

// Doubles the size of the zlist (or init on first call)
static void zlist_grow(void) {
    if(unlikely(!zlist_alloc)) { // first time
        zlist_alloc = 8; // must be power of two
        zlist = calloc(zlist_alloc, sizeof(zone_t*));
    }
    else {
        const unsigned new_alloc = zlist_alloc << 1; // double
        const unsigned new_hash_mask = new_alloc - 1;
        zone_t** new_list = calloc(new_alloc, sizeof(zone_t*));
        for(unsigned i = 0; i < zlist_alloc; i++) {
            zone_t* zone = zlist[i];
            if(zone && zone != ZONE_DELETED)
                new_list[zone->hash & new_hash_mask] = zone;
        }
        free(zlist);
        zlist = new_list;
        zlist_alloc = new_alloc;
    }
}

// XXX needs delete code, not sure yet whether that will
//   key on the zfn, the dname, or the zone_t*...

static bool zlist_add_zfile(const char* zfn) {
    // grow to maintain an allocation >= num_zones*4
    if(unlikely(zlist_alloc <= (num_zones << 2)))
        zlist_grow();

    bool rv = false;

    zone_t* new_zone = zone_new(zfn);
    unsigned conflict_depth = 0;
    zone_t* conflict = zlist_find_dname(new_zone->dname, &conflict_depth);
    if(conflict) {
        if(conflict_depth)
            log_err("Illegal subzone... XXX");
        else
            log_err("Duplicate zone... XXX");
        zone_delete(new_zone);
        rv = true;
    }
    else if(!ltree_process_zone(new_zone)) {
        unsigned jmpby = 1;
        const unsigned hash_mask = zlist_alloc - 1;
        unsigned slot = new_zone->hash & hash_mask;
        while(zlist[slot] && zlist[slot] != ZONE_DELETED) {
            slot += jmpby++;
            slot &= hash_mask;
        }
        // XXX lock this on runtime updates
        zlist[slot] = new_zone;
    }
    else { // scanning failed...
        zone_delete(new_zone);
        rv = true;
    }

    return rv;
}

void zlist_load_zones(void) {
    DIR* zdhandle = opendir(ZONES_DIR);
    if(!zdhandle)
        log_fatal("Cannot open zones directory '%s': %s", ZONES_DIR, dmn_strerror(errno));

    struct dirent* zfdi;
    while((zfdi = readdir(zdhandle)))
        if(likely(zfdi->d_name[0] != '.'))
            zlist_add_zfile(zfdi->d_name);

    if(closedir(zdhandle))
        log_fatal("closedir(%s) failed: %s", ZONES_DIR, dmn_strerror(errno));
}
