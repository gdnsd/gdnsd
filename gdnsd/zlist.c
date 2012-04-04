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

// the zones list itself
static zone_t** zlist = NULL;

// size zlist is currently allocated to
static unsigned zlist_alloc = 0;

// number of actual zones in the list
static unsigned num_zones = 0;

// number of non-NULL slots in the list
//  (this includes slots where zones were
//  deleted, which haven't yet been
//  reclaimed by by a colliding new zone
//  or a resize operation).
// this is the important number for
//  managing load factor, not num_zones.
static unsigned num_slots_used = 0;

// when a zone_t* is deleted from the hashtable,
//   its pointer is replaced with this magic value
//   so that the closed hash can skip over it, and
//   new insertions can re-use the slot if/when
//   applicable.
static const void* ZONE_DELETED = (void*)(uintptr_t)0x1;

// fast check for a true, non-deleted entry
//   (as opposed to a real empty slot, or a deleted one)
#define SLOT_REAL(x) ((uintptr_t)x & ~1UL)

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
        const unsigned dhash = gdnsd_dname_hash(dnptr);
        unsigned slot = dhash & hash_mask;
        unsigned jmpby = 1;
        while(zlist[slot]) {
            zone_t* zone = zlist[slot];
            if(SLOT_REAL(zone) && zone->hash == dhash && !dname_cmp(zone->dname, dnptr)) {
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
            if(SLOT_REAL(zone))
                new_list[zone->hash & new_hash_mask] = zone;
        }
        free(zlist);
        zlist = new_list;
        zlist_alloc = new_alloc;
        num_slots_used = num_zones; // we reclaimed all deletes
    }
}

// XXX needs delete code, not sure yet whether that will
//   key on the zfn, the dname, or the zone_t*...

static bool zlist_add_zfile(const char* zfn) {
    // grow to maintain an allocation >= num_slots_used*4,
    //   but never shrink in the face of deletions even
    //   after reclaiming them during a grow
    if(unlikely(zlist_alloc <= (num_slots_used << 2)))
        zlist_grow();

    bool rv = false;

    zone_t* new_zone = zone_new(zfn);
    unsigned conflict_depth = 0;
    zone_t* conflict = zlist_find_dname(new_zone->dname, &conflict_depth);
    if(conflict) {
        if(conflict_depth)
            log_err("Cannot load zone '%s': subzone of existing zone '%s'", logf_dname(new_zone->dname), logf_dname(conflict->dname));
        else
            log_err("Cannot load zone '%s' (file: '%s'): duplicate zone name from file '%s'", logf_dname(new_zone->dname), logf_pathname(new_zone->fn), logf_pathname(conflict->fn));
        zone_delete(new_zone);
        rv = true;
    }
    else if(!ltree_process_zone(new_zone)) {
        unsigned jmpby = 1;
        const unsigned hash_mask = zlist_alloc - 1;
        unsigned slot = new_zone->hash & hash_mask;
        while(SLOT_REAL(zlist[slot])) {
            slot += jmpby++;
            slot &= hash_mask;
        }

        // don't increment num_slots_used if overwriting a delete
        if(!zlist[slot])
            num_slots_used++;

        // XXX lock this on runtime updates
        zlist[slot] = new_zone;
        num_zones++;
    }
    else { // scanning failed...
        zone_delete(new_zone);
        rv = true;
    }

    return rv;
}

// XXX in the future when this merges with the non-inotify
//   reload scanner, we don't want directory errors to be fatal
void zlist_load_zones(void) {
    DIR* zdhandle = opendir(ZONES_DIR);
    if(!zdhandle)
        log_fatal("Cannot open zones directory '%s': %s", ZONES_DIR, dmn_strerror(errno));

    unsigned failed = 0;
    struct dirent* zfdi;
    while((zfdi = readdir(zdhandle)))
        if(likely(zfdi->d_name[0] != '.'))
            if(zlist_add_zfile(zfdi->d_name))
                failed++;

    if(closedir(zdhandle))
        log_fatal("closedir(%s) failed: %s", ZONES_DIR, dmn_strerror(errno));

    log_info("%u zones loaded successfully (%u failed)", num_zones, failed);
}

/*
 * zlist_destroy atexit??? XXX
    atexit(ltree_destroy);
*/
