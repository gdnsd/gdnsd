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
#include <pthread.h>

#include "gdnsd-dname.h"
#include "gdnsd-misc.h"

// pthread lock stuff
static pthread_rwlock_t zlist_lock;

static void setup_lock(void) {
    int pthread_err;
    pthread_rwlockattr_t lockatt;
    if((pthread_err = pthread_rwlockattr_init(&lockatt)))
        log_fatal("zlist: pthread_rwlockattr_init() failed: %s", logf_errnum(pthread_err));

    // Non-portable way to boost writer priority.  Our writelocks are held very briefly
    //  and very rarely, whereas the readlocks could be very spammy, and we don't want to
    //  block the write operation forever.  This works on Linux+glibc.
#   ifdef PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP
        if((pthread_err = pthread_rwlockattr_setkind_np(&lockatt, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)))
            log_fatal("zlist: pthread_rwlockattr_setkind_np(PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP) failed: %s", logf_errnum(pthread_err));
#   endif

    if((pthread_err = pthread_rwlock_init(&zlist_lock, &lockatt)))
        log_fatal("zlist: pthread_rwlock_init() failed: %s", logf_errnum(pthread_err));
    if((pthread_err = pthread_rwlockattr_destroy(&lockatt)))
        log_fatal("zlist: pthread_rwlockattr_destroy() failed: %s", logf_errnum(pthread_err));
}

static void destroy_lock(void) {
    int pthread_err;
    if((pthread_err = pthread_rwlock_destroy(&zlist_lock)))
        log_fatal("zlist: pthread_rwlock_destroy() failed: %s", logf_errnum(pthread_err));
}

void zlist_rdlock(void) { pthread_rwlock_rdlock(&zlist_lock); }
void zlist_unlock(void) { pthread_rwlock_unlock(&zlist_lock); }
// because only this file does writes...
static void zlist_wrlock(void) { pthread_rwlock_wrlock(&zlist_lock); }

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

void zone_delete(zone_t* zone) {
    dmn_assert(zone);
    if(zone->root)
        ltree_destroy(zone->root);
    lta_destroy(zone->arena);
    free(zone->src);
    free(zone);
}

zone_t* zone_new(const char* zname, const char* source) {
    dmn_assert(zname);

    // Convert to terminated-dname format and check for problems
    uint8_t dname[256];
    dname_status_t status = dname_from_string(dname, (const uint8_t*)zname, strlen(zname));

    if(status == DNAME_INVALID) {
        log_err("Zone name '%s' is illegal", zname);
        return NULL;
    }

    if(dname_iswild(dname)) {
        log_err("Zone '%s': Wildcard zone names not allowed", logf_dname(dname));
        return NULL;
    }

    if(status == DNAME_PARTIAL)
        dname_terminate(dname);

    zone_t* z = calloc(1, sizeof(zone_t));
    z->arena = lta_new();
    z->dname = lta_dnamedup(z->arena, dname);
    z->hash = dname_hash(z->dname);
    z->src = strdup(source);
    ltree_init_zone(z);

    return z;
}

bool zone_finalize(zone_t* zone) {
    lta_close(zone->arena);
    return ltree_postproc_zone(zone);
}

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
    if(dmn_debug()) {
        for(unsigned i = 0; i < zlist_alloc; i++) {
            zone_t* z = zlist[i];
            if(SLOT_REAL(z))
                log_fatal("Zone '%s' from (%s) was still in zlist at termination, leak...", logf_dname(z->dname), z->src);
        }
    }
    free(zlist);
    destroy_lock();
}

void zlist_init(void) {
    dmn_assert(!zlist);
    dmn_assert(!zlist_alloc);
    zlist_alloc = 8; // must be power of two
    zlist = calloc(zlist_alloc, sizeof(zone_t*));
    setup_lock();
    if(atexit(zlist_destroy))
        log_fatal("atexit(zlist_destroy) failed: %s", logf_errno());
}

void zlist_update(zone_t* z_old, zone_t* z_new) {
    dmn_assert((uintptr_t)z_old | (uintptr_t)z_new); // (NULL,NULL) illegal

    // when replacing, the old and new zones must be the same,
    //  and I think it's even universally true that "src" should match
    if(z_old && z_new) {
        dmn_assert(!dname_cmp(z_old->dname, z_new->dname));
        dmn_assert(!strcmp(z_old->src, z_new->src));
    }


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

        zlist_wrlock();
        if(z_new) {
            z_new->next = (*cand)->next;
            *cand = z_new;
            if(hidden)
                log_info("zlist: updated hidden zone data for '%s' (source '%s' updated) - runtime data set unaffected", logf_dname(z_old->dname), z_old->src);
            else
                log_info("zlist: updated current zone data for '%s' (source '%s' updated)", logf_dname(z_old->dname), z_old->src);
        }
        else {
            // if actual zlist slot, and there is no
            //   ->next to promote, we can't just NULL
            //   it out, we have to set ZONE_DELETED
            //   for the hashtable to skip properly.
            if(!hidden && !(*cand)->next) {
                *cand = ZONE_DELETED;
                log_info("zlist: deleting zone '%s' (only source '%s' removed)", logf_dname(z_old->dname), z_old->src);
            }
            else {
                *cand = (*cand)->next;
                if(hidden)
                    log_info("zlist: deleting hidden zone data for '%s' (source '%s' removed) - runtime data set unaffected", logf_dname(z_old->dname), z_old->src);
                else
                    log_info("zlist: current zone data for '%s' from source '%s' removed - alternate existing data from source '%s' promoted for runtime lookup", logf_dname(z_old->dname), z_old->src, (*cand)->src);
            }
        }
        zlist_unlock();

        return;
    }

    // rest is for the (NULL,new) insertion case
    dmn_assert(z_new);

    unsigned conflict_depth = 0;
    zone_t** conflict_ptr = zlist_find_zone_slot_for(z_new->dname, &conflict_depth);
    if(conflict_ptr) {
        if(conflict_depth) {
            log_warn("zlist: added new zone '%s' (source '%s'): subzone of existing zone '%s', will suppress overlapping data in parent (and usually results in poor delegation behavior...)", logf_dname(z_new->dname), z_new->src, logf_dname((*conflict_ptr)->dname)); // XXX we don't warn when added in reverse order though...
        }
        else {
            log_info("zlist: zone data for '%s' updated from source '%s', suppressing previous data from '%s'", logf_dname(z_new->dname), z_new->src, (*conflict_ptr)->src);
            // XXX need sorting here, which affects warn output as well?
            //  current behavior simply stores the newest added variant
            //   of the zone to the front of the list, make it the active copy
            //   until it's deleted which promotes the next in line.
            //  better behavior would be to sort-on-insert via a comparator that checks:
            //   (1) If both have a defined Serial which is >0, highest Serial wins
            //   (2) Else if both have a defined source mtime >0, highest mtime wins
            //   (3) Else fall back to preferring the newest added in realtime
            // XXX sort needs to be considered in the data replacement case
            //   earlier in this function as well
            z_new->next = *conflict_ptr;
            zlist_wrlock();
            *conflict_ptr = z_new;
            zlist_unlock();
        }
    }
    else {
        // an actual new zone (no other conflict)
        log_info("zlist: added new zone '%s' (source '%s')", logf_dname(z_new->dname), z_new->src);

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

        zlist_wrlock();

        zlist[slot] = z_new;
        num_zones++;

        // grow to maintain an allocation >= num_slots_used*4,
        //   but never shrink in the face of deletions even
        //   after reclaiming them during a grow
        if(unlikely(zlist_alloc <= (num_slots_used << 2)))
            zlist_grow();

        zlist_unlock();
    }
}
