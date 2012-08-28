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

#include "ztree.h"

#include <stdlib.h>
#include <pthread.h>

#include "gdnsd-dname.h"
#include "gdnsd-misc.h"

// pthread lock stuff
static pthread_rwlock_t ztree_lock;

static void setup_lock(void) {
    int pthread_err;
    pthread_rwlockattr_t lockatt;
    if((pthread_err = pthread_rwlockattr_init(&lockatt)))
        log_fatal("ztree: pthread_rwlockattr_init() failed: %s", logf_errnum(pthread_err));

    // Non-portable way to boost writer priority.  Our writelocks are held very briefly
    //  and very rarely, whereas the readlocks could be very spammy, and we don't want to
    //  block the write operation forever.  This works on Linux+glibc.
#   ifdef PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP
        if((pthread_err = pthread_rwlockattr_setkind_np(&lockatt, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)))
            log_fatal("ztree: pthread_rwlockattr_setkind_np(PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP) failed: %s", logf_errnum(pthread_err));
#   endif

    if((pthread_err = pthread_rwlock_init(&ztree_lock, &lockatt)))
        log_fatal("ztree: pthread_rwlock_init() failed: %s", logf_errnum(pthread_err));
    if((pthread_err = pthread_rwlockattr_destroy(&lockatt)))
        log_fatal("ztree: pthread_rwlockattr_destroy() failed: %s", logf_errnum(pthread_err));
}

static void destroy_lock(void) {
    int pthread_err;
    if((pthread_err = pthread_rwlock_destroy(&ztree_lock)))
        log_fatal("ztree: pthread_rwlock_destroy() failed: %s", logf_errnum(pthread_err));
}

void ztree_rdlock(void) { pthread_rwlock_rdlock(&ztree_lock); }
void ztree_unlock(void) { pthread_rwlock_unlock(&ztree_lock); }
// because only this file does writes...
static void ztree_wrlock(void) { pthread_rwlock_wrlock(&ztree_lock); }

// The tree data structure that will hold the zone_t's
struct ztree;
typedef struct ztree ztree_t;
typedef struct {
    ztree_t** store;
    unsigned alloc;
    unsigned count;
} ztchildren_t;

struct ztree {
    uint8_t* label;
    zone_t* zone;
    ztchildren_t* children;
};

// The root node.
static ztree_t* ztree_root = NULL;

/****** zone_t code ********/

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

// Compare two zones for sorting duplicate sources.
// The comparison is by serial and then mtime.
// The way the comparison is used below, in the equal case
//   the "new" zone wins (the one being inserted/updated).
// retval < 0 means za is first
// retval > 0 means zb is first
// retval == 0 means equal
static const uint32_t u_i32_max = 0x80000000UL;
F_PURE F_NONNULL
static int zone_cmp(zone_t* za, zone_t* zb) {
    dmn_assert(za); dmn_assert(zb);

    const unsigned sa = za->serial;
    const unsigned sb = zb->serial;
    int rv = 0;
    if(sa != sb) {
        if(  ((sa > sb) && ((sa - sb) < u_i32_max))
          || ((sa < sb) && ((sb - sa) > u_i32_max))) 
            rv = -1;
        else
            rv = 1;
    }
    else {
       rv = zb->mtime - za->mtime;
    }
    return rv;
}

/******* ztree code *********/

static inline unsigned label_hash(const uint8_t* label) {
    const unsigned len = *label++;
    return gdnsd_lookup2((const char*)label, len);
}

// search the children of one node for a given label
F_NONNULL
static ztree_t* ztree_node_find_child(ztree_t* node, const uint8_t* label) {
    dmn_assert(node); dmn_assert(label);

    ztree_t* rv = NULL;
    ztchildren_t* children = node->children;
    if(children) {
        dmn_assert(children->alloc);
        const unsigned child_mask = children->alloc - 1;
        unsigned jmpby = 1;
        unsigned slot = label_hash(label) & child_mask;
        while((rv = children->store[slot])
          && memcmp(rv->label, label, *label + 1)) {
            slot += jmpby++;
            slot &= child_mask;
        }
    }

    return rv;
}

// "dname" can be any legal FQDN.  This returns the zone_t that
//   logically contains this dname, IFF one exists, for runtime
//   lookup purposes
zone_t* ztree_find_zone_for(const uint8_t* dname, unsigned* auth_depth_out) {
    dmn_assert(dname); dmn_assert(auth_depth_out);

    zone_t* rv = NULL;

    const uint8_t* lstack[127];
    unsigned lcount = dname_to_lstack(dname, lstack);
    ztree_t* current = ztree_root;
    while(current && !current->zone && lcount)
        current = ztree_node_find_child(current, lstack[--lcount]);

    if(current && current->zone) {
        rv = current->zone;
        unsigned auth_depth = lcount;
        while(lcount--)
            auth_depth += lstack[lcount][0];
        *auth_depth_out = auth_depth;
    }

    return rv;
}

// Doubles the size of the childtable in a ztree node,
//   or initializes to 16 slots.
// XXX should we prune empty subtrees during grow?
//   or during deletion, or at all?
F_NONNULL
static void ztree_node_check_grow(ztree_t* node) {
    dmn_assert(node);

    ztchildren_t* old_children = node->children;
    if(!old_children) {
        ztchildren_t* children = calloc(1, sizeof(ztchildren_t));
        children->store = calloc(16, sizeof(ztree_t*));
        children->alloc = 16;
        ztree_wrlock();
        node->children = children;
        ztree_unlock();
    }
    // max load is 25%
    else if(old_children->count >= (old_children->alloc >> 2)) {
        const unsigned new_alloc = old_children->alloc << 1; // double
        const unsigned new_hash_mask = new_alloc - 1;
        ztchildren_t* new_children = calloc(1, sizeof(ztchildren_t));
        new_children->store = calloc(new_alloc, sizeof(ztree_t*));
        new_children->alloc = new_alloc;
        for(unsigned i = 0; i < old_children->alloc; i++) {
            ztree_t* entry = old_children->store[i];
            if(entry) {
                new_children->count++;
                unsigned jmpby = 1;
                unsigned slot = label_hash(entry->label) & new_hash_mask;
                while(new_children->store[slot]) {
                    slot += jmpby++;
                    slot &= new_hash_mask;
                }
                new_children->store[slot] = entry;
            }
        }
        ztree_wrlock();
        node->children = new_children;
        ztree_unlock();
        free(old_children->store);
        free(old_children);
    }
}

// search the children of one node for a given label, creating a new
//  child node if it doesn't exist.
F_NONNULL
static ztree_t* ztree_node_find_or_add_child(ztree_t* node, const uint8_t* label) {
    dmn_assert(node); dmn_assert(label);

    ztree_node_check_grow(node);
    ztchildren_t* children = node->children;
    dmn_assert(children);

    ztree_t* rv;

    const unsigned child_mask = children->alloc - 1;
    unsigned jmpby = 1;
    unsigned slot = label_hash(label) & child_mask;
    while((rv = children->store[slot])
      && memcmp(rv->label, label, *label + 1)) {
        slot += jmpby++;
        slot &= child_mask;
    }

    // came to an empty slot with no memcmp match along the way,
    //   so create a new node at this slot...
    if(!rv) {
        rv = calloc(1, sizeof(ztree_t));
        rv->label = malloc(*label + 1);
        memcpy(rv->label, label, *label + 1);
        ztree_wrlock();
        children->store[slot] = rv;
        ztree_unlock();
        children->count++;
    }

    return rv;
}

static void ztree_leak_warn(ztree_t* node) {
    dmn_assert(node);
    ztchildren_t* children = node->children;
    if(children) {
        for(unsigned i = 0; i < children->alloc; i++) {
            ztree_t* child = children->store[i];
            if(child)
                ztree_leak_warn(child);
        }
    }
    if(node->zone)
        log_warn("Zone '%s' from (%s) was still in ztree at termination, leak...", logf_dname(node->zone->dname), node->zone->src);
}

static void ztree_atexit(void) {
    if(dmn_get_debug())
        ztree_leak_warn(ztree_root);
    destroy_lock();
}

void ztree_init(void) {
    dmn_assert(!ztree_root);
    ztree_root = calloc(1, sizeof(ztree_t));
    setup_lock();
    if(atexit(ztree_atexit))
        log_fatal("atexit(ztree_atexit) failed: %s", logf_errno());
}

void ztree_update(zone_t* z_old, zone_t* z_new) {
    dmn_assert(ztree_root);
    dmn_assert((uintptr_t)z_old | (uintptr_t)z_new); // (NULL,NULL) illegal

    // when replacing, the old and new zone names must be the same, as
    //  well as the ->src strings (because it's not up to the zsrc code
    //  to manage the relationsip between two sources for the same zone;
    //  if ->src changes the zsrc code should treat it as a separate
    //  entity).
    if(z_old && z_new) {
        dmn_assert(!dname_cmp(z_old->dname, z_new->dname));
        dmn_assert(!strcmp(z_old->src, z_new->src));
    }

    // note we only need to writelock when updating ztree->zone, not
    //  when updating some zone's ->next pointer, because the lookup
    //  code only ever looks at the head of the list.  The booleans
    //  "hidden" and "hidden2" track this below...

    if(!z_old) { // insert
        dmn_assert(z_new);
        log_debug("ztree_update: inserting new data for zone '%s' from src '%s'", logf_dname(z_new->dname), z_new->src);
        const uint8_t* lstack[127];
        unsigned lcount = dname_to_lstack(z_new->dname, lstack);
        ztree_t* this_zt = ztree_root;
        while(lcount) {
            this_zt = ztree_node_find_or_add_child(this_zt, lstack[--lcount]);
            dmn_assert(this_zt);
        }

        // Assume existing entries are sorted, find our insert position...
        bool hidden = false;
        zone_t** ins_pp = &this_zt->zone;
        while(*ins_pp && (zone_cmp(*ins_pp, z_new) < 0)) {
            hidden = true;
            ins_pp = &(*ins_pp)->next;
        }

        // only have to lock if updating head of list
        z_new->next = *ins_pp;
        if(!hidden) ztree_wrlock();
        *ins_pp = z_new;
        if(!hidden) ztree_unlock();
    }
    else { // update or delete
        if(z_new)
            log_debug("ztree_update: updating data for zone '%s' from src '%s'", logf_dname(z_old->dname), z_old->src);
        else
            log_debug("ztree_update: deleting data for zone '%s' from src '%s'", logf_dname(z_old->dname), z_old->src);

        const uint8_t* lstack[127];
        unsigned lcount = dname_to_lstack(z_old->dname, lstack);
        ztree_t* this_zt = ztree_root;
        while(lcount) {
            this_zt = ztree_node_find_child(this_zt, lstack[--lcount]);
            dmn_assert(this_zt);
        }

        // find exactly where z_old is stored, either at
        //   this_zt->zone itself, or in some other zone_t's
        //   ->next.
        dmn_assert(this_zt->zone);
        bool hidden = false;
        zone_t** zold_pp = &this_zt->zone;
        while(*zold_pp != z_old) {
            hidden = true;
            zold_pp = &(*zold_pp)->next;
        }

        if(!z_new) { // delete case
            if(!hidden) ztree_wrlock();
            *zold_pp = (*zold_pp)->next;
            if(!hidden) ztree_unlock();
        }
        else { // update case
            // Scan for correct sort position
            bool hidden2 = false;
            zone_t** sort_pp = &this_zt->zone;
            while(*sort_pp && (zone_cmp(*sort_pp, z_new) < 0)) {
                hidden2 = true;
                sort_pp = &(*sort_pp)->next;
            }
            if(sort_pp == zold_pp || sort_pp == &(*zold_pp)->next) {
                // sorts same as old if old is not present, single-step swap
                z_new->next = (*zold_pp)->next;
                if(!hidden) ztree_wrlock();
                *zold_pp = z_new;
                if(!hidden) ztree_unlock();
            }
            else {
                // move required, 2-step swap (add then delete)
                // (I know this looks stupid now, but thinking ahead
                //   for liburcu stuff)
                dmn_assert(hidden || hidden2); // both can't be the head...
                z_new->next = *sort_pp;
                if(!hidden2) ztree_wrlock();
                *sort_pp = z_new;
                if(!hidden2) ztree_unlock();
                if(!hidden) ztree_wrlock();
                *zold_pp = (*zold_pp)->next;
                if(!hidden) ztree_unlock();
            }
        }
    }
}
