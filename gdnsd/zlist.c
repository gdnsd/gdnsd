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

#include <stdlib.h>

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
static void* const ZONE_DELETED = (void*)(uintptr_t)0x1;

// fast check for a true, non-deleted entry
//   (as opposed to a real empty slot, or a deleted one)
#define SLOT_REAL(x) ((uintptr_t)x & ~1UL)

// "dname" can be any legal FQDN
// Current implementation starts by searching for "dname" itself
//   as a zone name, and then chops off labels from the left hand
//   side one at a time to search deeper.
static zone_t** zlist_find_zone_slot_for(const uint8_t* dname, unsigned* auth_depth_out) {
    dmn_assert(dname);

    uint8_t dncpy[256];
    gdnsd_dname_copy(dncpy, dname);
    uint8_t* dnptr = dncpy;

    const unsigned hash_mask = zlist_alloc - 1;

    zone_t** rv = NULL;
    do {
        const unsigned dhash = gdnsd_dname_hash(dnptr);
        unsigned slot = dhash & hash_mask;
        unsigned jmpby = 1;
        while(zlist[slot]) {
            zone_t* zone = zlist[slot];
            if(SLOT_REAL(zone) && zone->hash == dhash && !dname_cmp(zone->dname, dnptr)) {
                rv = &zlist[slot];
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

zone_t* zlist_find_zone_for(const uint8_t* dname, unsigned* auth_depth_out) {
    zone_t** rv_ptr = zlist_find_zone_slot_for(dname, auth_depth_out);
    return rv_ptr ? *rv_ptr : NULL;
}

// Doubles the size of the zlist
static void zlist_grow(void) {
    dmn_assert(zlist);
    dmn_assert(zlist_alloc);

    const unsigned new_alloc = zlist_alloc << 1; // double
    const unsigned new_hash_mask = new_alloc - 1;
    zone_t** new_list = calloc(new_alloc, sizeof(zone_t*));
    for(unsigned i = 0; i < zlist_alloc; i++) {
        zone_t* zone = zlist[i];
        if(SLOT_REAL(zone)) {
            unsigned jmpby = 1;
            unsigned slot = zone->hash & new_hash_mask;
            while(new_list[slot]) {
                slot += jmpby++;
                slot &= new_hash_mask;
            }
            new_list[slot] = zone;
        }
    }
    free(zlist);
    zlist = new_list;
    zlist_alloc = new_alloc;
    num_slots_used = num_zones; // we reclaimed all deletes
}

static void zlist_destroy(void) {
    dmn_assert(zlist);
    dmn_assert(zlist_alloc);
    if(1) { // XXX debug only or something?
        for(unsigned i = 0; i < zlist_alloc; i++) {
            zone_t* z = zlist[i];
            if(SLOT_REAL(z))
                log_fatal("Zone '%s' from (%s) was still in zlist at termination, leak...", logf_dname(z->dname), z->src);
        }
    }
    free(zlist);
}

void zlist_init(void) {
    dmn_assert(!zlist);
    dmn_assert(!zlist_alloc);
    zlist_alloc = 8; // must be power of two
    zlist = calloc(zlist_alloc, sizeof(zone_t*));
    if(atexit(zlist_destroy))
        log_fatal("atexit(zlist_destroy) failed: %s", logf_errno());
}

void zlist_update(zone_t* z_old, zone_t* z_new) {
    dmn_assert((uintptr_t)z_old | (uintptr_t)z_new); // (NULL,NULL) illegal

    if(z_old) {
        // z_old must be a previous z_new, etc, hence the asserts
        unsigned conflict_depth = 0;
        zone_t** cand = zlist_find_zone_slot_for(z_old->dname, &conflict_depth);
        dmn_assert(cand && *cand);
        bool hidden = false; // actual zlist slot
        while(*cand != z_old) {
            hidden = true; // vs hidden in ->next chain
            cand = &((*cand)->next);
            dmn_assert(cand && *cand);
        }
        if(z_new) {
            z_new->next = (*cand)->next;
            *cand = z_new;
        }
        else {
            // if actual zlist slot, and there is no
            //   ->next to promote, we can't just NULL
            //   it out, we have to set ZONE_DELETED
            //   for the hashtable to skip properly.
            if(!hidden && !(*cand)->next)
                *cand = ZONE_DELETED;
            else
                *cand = (*cand)->next;
        }

        return;
    }

    // rest is for the (NULL,new) insertion case
    dmn_assert(z_new);

    unsigned conflict_depth = 0;
    zone_t** conflict_ptr = zlist_find_zone_slot_for(z_new->dname, &conflict_depth);
    if(conflict_ptr) {
        if(conflict_depth) {
            log_warn("New zone '%s': subzone of existing zone '%s'...", logf_dname(z_new->dname), logf_dname((*conflict_ptr)->dname)); // XXX we don't warn when added in reverse order though...
        }
        else {
            log_warn("New zone data for '%s' from '%s' suppresses existing data from '%s'...", logf_dname(z_new->dname), z_new->src, (*conflict_ptr)->src);
            // store to front of duplicates chain
            z_new->next = *conflict_ptr;
            *conflict_ptr = z_new;
            // XXX need sorting here, which affects warn output as well?
        }
    }
    else {
        // an actual new zone (no other conflict)
        unsigned jmpby = 1;
        const unsigned hash_mask = zlist_alloc - 1;
        unsigned slot = z_new->hash & hash_mask;
        while(SLOT_REAL(zlist[slot])) {
            slot += jmpby++;
            slot &= hash_mask;
        }

        // don't increment num_slots_used if overwriting a delete
        if(!zlist[slot])
            num_slots_used++;

        // XXX lock this on runtime updates
        zlist[slot] = z_new;
        num_zones++;

        // grow to maintain an allocation >= num_slots_used*4,
        //   but never shrink in the face of deletions even
        //   after reclaiming them during a grow
        if(unlikely(zlist_alloc <= (num_slots_used << 2)))
            zlist_grow();
    }
}
