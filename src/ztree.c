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
#include "ztree.h"

#include "main.h"
#include "zsrc_rfc1035.h"

#include <gdnsd/alloc.h>
#include <gdnsd/dname.h>
#include <gdnsd/log.h>
#include <gdnsd/misc.h>

#include <stdlib.h>

#include <urcu-qsbr.h>

typedef struct {
    ztree_t** store;
    unsigned alloc;
    unsigned count;
} ztchildren_t;

struct ztree_struct {
    uint8_t* label;
    zone_t*  zone;
    ztchildren_t* children;
};

// The root node.
static ztree_t* ztree_root = NULL;

/****** zone_t code ********/

void zone_delete(zone_t* zone)
{
    if (zone->root)
        ltree_destroy(zone->root);
    lta_destroy(zone->arena);
    free(zone->src);
    free(zone);
}

zone_t* zone_new(const char* zname, const char* source)
{
    // Convert to terminated-dname format and check for problems
    uint8_t dname[256];
    dname_status_t status = dname_from_string(dname, zname, strlen(zname));

    if (status == DNAME_INVALID) {
        log_err("Zone name '%s' is illegal", zname);
        return NULL;
    }

    if (dname_iswild(dname)) {
        log_err("Zone '%s': Wildcard zone names not allowed", logf_dname(dname));
        return NULL;
    }

    if (status == DNAME_PARTIAL)
        dname_terminate(dname);

    zone_t* z = xcalloc(sizeof(*z));
    z->arena = lta_new();
    z->dname = lta_dnamedup(z->arena, dname);
    z->hash = dname_hash(z->dname);
    z->src = xstrdup(source);
    ltree_init_zone(z);

    return z;
}

bool zone_finalize(zone_t* zone)
{
    lta_close(zone->arena);
    return ltree_postproc_zone(zone);
}

/******* ztree code *********/

F_NONNULL F_PURE
static ztree_t* ztree_node_find_child(const ztree_t* node, const uint8_t* label)
{
    ztree_t* rv = NULL;
    ztchildren_t* children = node->children;
    if (children) {
        gdnsd_assert(children->alloc);
        const unsigned child_mask = children->alloc - 1;
        unsigned jmpby = 1;
        unsigned slot = ltree_hash(label, child_mask);
        while ((rv = children->store[slot])
                && gdnsd_label_cmp(label, rv->label)) {
            slot += jmpby++;
            slot &= child_mask;
        }
    }

    return rv;
}

// "dname" can be any legal FQDN.  This returns the zone_t that
//   logically contains this dname, IFF one exists, for runtime
//   lookup purposes
// PRCU: executing thread must be registered, online and have reader-lock
zone_t* ztree_find_zone_for(const uint8_t* dname, unsigned* auth_depth_out)
{
    const uint8_t* lstack[127];
    unsigned lcount = dname_to_lstack(dname, lstack);
    ztree_t* current = rcu_dereference(ztree_root);
    while (current && !current->zone && lcount)
        current = ztree_node_find_child(current, lstack[--lcount]);
    zone_t* rv = current ? current->zone : NULL;
    if (rv) {
        unsigned auth_depth = lcount;
        while (lcount--)
            auth_depth += lstack[lcount][0];
        *auth_depth_out = auth_depth;
    }

    return rv;
}

// Doubles the size of the childtable in a ztree node,
//   or initializes to 16 slots.
F_NONNULL
static void ztree_node_check_grow(ztree_t* node)
{
    ztchildren_t* old_children = node->children;
    if (!old_children) {
        ztchildren_t* children = xcalloc(sizeof(*children));
        children->store = xcalloc_n(16, sizeof(*children->store));
        children->alloc = 16;
        node->children = children;
    } else if (old_children->count >= (old_children->alloc >> 2)) {
        // max load is 25%
        const unsigned new_alloc = old_children->alloc << 1; // double
        const unsigned new_hash_mask = new_alloc - 1;
        ztchildren_t* new_children = xcalloc(sizeof(*new_children));
        new_children->store = xcalloc_n(new_alloc, sizeof(*new_children->store));
        new_children->alloc = new_alloc;
        for (unsigned i = 0; i < old_children->alloc; i++) {
            ztree_t* entry = old_children->store[i];
            if (entry) {
                new_children->count++;
                unsigned jmpby = 1;
                unsigned slot = ltree_hash(entry->label, new_hash_mask);
                while (new_children->store[slot]) {
                    slot += jmpby++;
                    slot &= new_hash_mask;
                }
                new_children->store[slot] = entry;
            }
        }
        node->children = new_children;
        free(old_children->store);
        free(old_children);
    }
}

// search the children of one node for a given label, creating a new
//  child node if it doesn't exist.
F_NONNULL
static ztree_t* ztree_node_find_or_add_child(ztree_t* node, const uint8_t* label)
{
    ztree_node_check_grow(node);
    ztchildren_t* children = node->children;
    gdnsd_assert(children);

    ztree_t* rv;

    const unsigned child_mask = children->alloc - 1;
    unsigned jmpby = 1;
    unsigned slot = ltree_hash(label, child_mask);
    while ((rv = children->store[slot])
            && gdnsd_label_cmp(label, rv->label)) {
        slot += jmpby++;
        slot &= child_mask;
    }

    // came to an empty slot with no match along the way,
    //   so create a new node at this slot...
    if (!rv) {
        rv = xcalloc(sizeof(*rv));
        const unsigned lsz = *label + 1U;
        rv->label = xmalloc(lsz);
        memcpy(rv->label, label, lsz);
        children->store[slot] = rv;
        children->count++;
    }

    return rv;
}

F_NONNULL
static void ztree_destroy(ztree_t* node)
{
    ztchildren_t* children = node->children;
    if (children) {
        for (unsigned i = 0; i < children->alloc; i++) {
            ztree_t* child = children->store[i];
            if (child)
                ztree_destroy(child);
        }
        free(children->store);
        free(children);
    }
    if (node->zone)
        zone_delete(node->zone);
    free(node->label);
    free(node);
}

bool ztree_insert_zone(ztree_t* tree, zone_t* new_zone)
{
    const uint8_t* lstack[127];
    unsigned lcount = dname_to_lstack(new_zone->dname, lstack);

    while (lcount) {
        if (tree->zone) {
            log_err("Zone '%s' is a sub-zone of existing zone '%s'", logf_dname(new_zone->dname), logf_dname(tree->zone->dname));
            return true;
        }
        tree = ztree_node_find_or_add_child(tree, lstack[--lcount]);
        gdnsd_assert(tree);
    }

    if (tree->zone) {
        log_err("Zone '%s' is a duplicate of an existing zone", logf_dname(new_zone->dname));
        return true;
    }

    if (tree->children) {
        log_err("Zone '%s' is a super-zone of one or more existing zones", logf_dname(new_zone->dname));
        return true;
    }

    tree->zone = new_zone;
    log_info("Zone %s: source %s with serial %u loaded as authoritative", logf_dname(new_zone->dname), new_zone->src, new_zone->serial);
    return false;
}

void* ztree_zones_reloader_thread(void* init_asvoid)
{
    gdnsd_thread_setname("gdnsd-zreload");
    const bool init = (bool)init_asvoid;
    if (init)
        gdnsd_assert(!ztree_root);
    else
        gdnsd_thread_reduce_prio();

    uintptr_t rv = 0;
    ztree_t* new_ztree = xcalloc(sizeof(*new_ztree));

    // These do not fail if their data directory doesn't exist
    const bool rfc1035_failed = zsrc_rfc1035_load_zones(new_ztree);

    if (rfc1035_failed) {
        ztree_destroy(new_ztree);
        rv = 1; // the zsrc already logged why
    } else {
        ztree_t* old_ztree = ztree_root;
        rcu_assign_pointer(ztree_root, new_ztree);
        synchronize_rcu();
        if (old_ztree)
            ztree_destroy(old_ztree);
    }

    if (!init)
        notify_reload_zones_done();

    return (void*)rv;
}

static void ztree_cleanup(void)
{
    // Should we clean up any still-running reload thread?
    if (ztree_root) {
        ztree_destroy(ztree_root);
        ztree_root = NULL;
    }
}

void ztree_init(void)
{
    zsrc_rfc1035_init();
    gdnsd_atexit(ztree_cleanup);
}
