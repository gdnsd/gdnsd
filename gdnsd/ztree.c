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
struct ztree {
    uint8_t* label;
    zone_t* zone;
    ztree_t** children;
    unsigned child_alloc;
    unsigned child_count;
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
    if(node->children) {
        dmn_assert(node->child_alloc);
        const unsigned child_mask = node->child_alloc - 1;
        unsigned jmpby = 1;
        unsigned slot = label_hash(label) & child_mask;
        while((rv = node->children[slot])
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
static void ztree_node_grow(ztree_t* node) {
    dmn_assert(node);

    if(!node->children) {
        dmn_assert(!node->child_alloc);
        dmn_assert(!node->child_count);
        ztree_t** temp = calloc(16, sizeof(ztree_t*));
        // XXX really, the whole child table
        // needs to be a single object for this swap,
        // including alloc/count, if we want to urcu...
        ztree_wrlock();
        node->children = temp;
        node->child_alloc = 16;
        node->child_count = 0;
        ztree_unlock();
    }
    else {
        const unsigned new_alloc = node->child_alloc << 1; // double
        const unsigned new_hash_mask = new_alloc - 1;
        unsigned new_count = 0;
        ztree_t** new_children = calloc(new_alloc, sizeof(ztree_t*));
        for(unsigned i = 0; i < node->child_alloc; i++) {
            ztree_t* entry = node->children[i];
            if(entry) {
                new_count++;
                unsigned jmpby = 1;
                unsigned slot = label_hash(entry->label) & new_hash_mask;
                while(new_children[slot]) {
                    slot += jmpby++;
                    slot &= new_hash_mask;
                }
                new_children[slot] = entry;
            }
        }
        free(node->children);
        ztree_wrlock();
        node->children = new_children;
        node->child_alloc = new_alloc;
        node->child_count = new_count;
        ztree_unlock();
    }
}

// search the children of one node for a given label, creating a new
//  child node if it doesn't exist.
F_NONNULL
static ztree_t* ztree_node_find_or_add_child(ztree_t* node, const uint8_t* label) {
    dmn_assert(node); dmn_assert(label);

    // max load is 25%
    if(!node->children || node->child_count >= (node->child_alloc >> 2))
        ztree_node_grow(node);
    dmn_assert(node->children);
    dmn_assert(node->child_alloc);
    dmn_assert(node->child_count < (node->child_alloc >> 2));

    ztree_t* rv;

    const unsigned child_mask = node->child_alloc - 1;
    unsigned jmpby = 1;
    unsigned slot = label_hash(label) & child_mask;
    while((rv = node->children[slot])
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
        node->children[slot] = rv;
        node->child_count++;
        ztree_unlock();
    }

    return rv;
}

static void ztree_leak_warn(ztree_t* node) {
    dmn_assert(node);
    for(unsigned i = 0; i < node->child_alloc; i++) {
        ztree_t* child = node->children[i];
        if(child)
            ztree_leak_warn(child);
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

    if(!z_old) { // insert
        dmn_assert(z_new);
        log_debug("zlist_update: inserting new data for zone '%s' from src '%s'", logf_dname(z_new->dname), z_new->src);
        const uint8_t* lstack[127];
        unsigned lcount = dname_to_lstack(z_new->dname, lstack);
        ztree_t* this_zt = ztree_root;
        while(lcount) {
            this_zt = ztree_node_find_or_add_child(this_zt, lstack[--lcount]);
            dmn_assert(this_zt);
        }

        // insert at front of chain
        // XXX should be sorted rather than implicit arrival order?
        z_new->next = this_zt->zone;
        ztree_wrlock();
        this_zt->zone = z_new;
        ztree_unlock();
    }
    else { // update or delete
        if(z_new)
            log_debug("zlist_update: updating data for zone '%s' from src '%s'", logf_dname(z_old->dname), z_old->src);
        else
            log_debug("zlist_update: deleting data for zone '%s' from src '%s'", logf_dname(z_old->dname), z_old->src);

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

        // only need to lock if the target was the front
        //   of the ->zone chain (in active use for lookups),
        //   because lookup code never uses ->next.
        if(!hidden)
            ztree_wrlock();
        if(z_new) { // update case
            // XXX if we sort on insert above, we have to
            //  re-sort on update here...
            z_new->next = z_old->next;
            *zold_pp = z_new;
        }
        else { // delete case
            *zold_pp = (*zold_pp)->next;
        }
        if(!hidden)
            ztree_unlock();
    }
}
