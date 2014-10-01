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

#include "main.h"
#include <gdnsd/alloc.h>
#include <gdnsd/dname.h>
#include <gdnsd/log.h>
#include <gdnsd/misc.h>
#include <gdnsd/prcu-priv.h>

// The tree data structure that will hold the zone_t's
struct _ztree_struct;
typedef struct _ztree_struct ztree_t;

typedef struct {
    ztree_t** store;
    unsigned alloc;
    unsigned count;
} ztchildren_t;

struct _ztree_struct {
    uint8_t* label;
    zone_t** zones; // -> see below
    unsigned zones_len;
    ztchildren_t* children;
};

// This is how readers access ->zones for a zone_t*
//   (while under a read lock section, of course)
F_NONNULL
static inline zone_t* ztree_reader_get_zone(const ztree_t* zt) {
    dmn_assert(zt);
    zone_t** temp = gdnsd_prcu_rdr_deref(zt->zones);
    return temp ? *temp : NULL;
}

// The root node.
static ztree_t* ztree_root = NULL;

// alternate, temporary root pointer for transactions
static ztree_t* new_root = NULL;

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
    dname_status_t status = dname_from_string(dname, zname, strlen(zname));

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

    zone_t* z = xcalloc(1, sizeof(zone_t));
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
static ztree_t* ztree_node_find_child(ztree_t* node, const uint8_t* label, const bool reader) {
    dmn_assert(node); dmn_assert(label);

    ztree_t* rv = NULL;
    ztchildren_t* children;
    if(reader)
        children = gdnsd_prcu_rdr_deref(node->children);
    else
        children = node->children;
    if(children) {
        dmn_assert(children->alloc);
        const unsigned child_mask = children->alloc - 1;
        unsigned jmpby = 1;
        unsigned slot = label_hash(label) & child_mask;
        if(reader) {
            while((rv = gdnsd_prcu_rdr_deref(children->store[slot]))
              && gdnsd_label_cmp(label, rv->label)) {
                slot += jmpby++;
                slot &= child_mask;
            }
        }
        else {
            while((rv = children->store[slot])
              && gdnsd_label_cmp(label, rv->label)) {
                slot += jmpby++;
                slot &= child_mask;
            }
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
    ztree_t* current = gdnsd_prcu_rdr_deref(ztree_root);
    while(current && !(rv = ztree_reader_get_zone(current)) && lcount)
        current = ztree_node_find_child(current, lstack[--lcount], true);

    if(rv) {
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
        ztchildren_t* children = xcalloc(1, sizeof(ztchildren_t));
        children->store = xcalloc(16, sizeof(ztree_t*));
        children->alloc = 16;
        gdnsd_prcu_upd_assign(node->children, children);
    }
    // max load is 25%
    else if(old_children->count >= (old_children->alloc >> 2)) {
        const unsigned new_alloc = old_children->alloc << 1; // double
        const unsigned new_hash_mask = new_alloc - 1;
        ztchildren_t* new_children = xcalloc(1, sizeof(ztchildren_t));
        new_children->store = xcalloc(new_alloc, sizeof(ztree_t*));
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
        gdnsd_prcu_upd_lock();
        gdnsd_prcu_upd_assign(node->children, new_children);
        gdnsd_prcu_upd_unlock();
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
      && gdnsd_label_cmp(label, rv->label)) {
        slot += jmpby++;
        slot &= child_mask;
    }

    // came to an empty slot with no match along the way,
    //   so create a new node at this slot...
    if(!rv) {
        rv = xcalloc(1, sizeof(ztree_t));
        rv->label = xmalloc(*label + 1);
        memcpy(rv->label, label, *label + 1);
        gdnsd_prcu_upd_assign(children->store[slot], rv);
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
    if(node->zones)
        log_warn("Zone '%s' was still in ztree at termination, leak...", logf_dname(node->zones[0]->dname));
}

static void ztree_atexit(void) {
    ztree_leak_warn(ztree_root);
    gdnsd_prcu_destroy_lock();
}

void ztree_init(void) {
    dmn_assert(!ztree_root);
    gdnsd_prcu_setup_lock();
    ztree_root = xcalloc(1, sizeof(ztree_t));
    gdnsd_atexit_debug(ztree_atexit);
}

// insertion sort for mostly-sorted arrays
F_NONNULL
static void zones_sort(zone_t** list, const unsigned len) {
    dmn_assert(list); dmn_assert(len);
    for(unsigned i = 1; i < len; i++) {
        zone_t* temp = list[i];
        int j = i - 1;
        while(j >= 0 && (zone_cmp(temp, list[j]) <= 0)) {
            list[j + 1] = list[j];
            j--;
        }
        list[j + 1] = temp;
    }
}

static const char zt_msg_hidden[] = "Zone %s: is now a hidden subzone of new parent zone %s";
static const char zt_msg_revealed[] = "Zone %s: subzone unhidden due to removal of parent zone %s";

F_NONNULL
static void ztree_subzone_reporter(const ztree_t* zt, const uint8_t* parent_dname, const bool hide) {
    dmn_assert(zt); dmn_assert(parent_dname);
    const ztchildren_t* ztc = zt->children;
    if(ztc) {
        for(unsigned i = 0; i < ztc->alloc; i++) {
            ztree_t* child = ztc->store[i];
            if(child) {
                if(child->zones)
                    log_warn(hide ? zt_msg_hidden : zt_msg_revealed,
                        logf_dname(child->zones[0]->dname), logf_dname(parent_dname));
                else
                    ztree_subzone_reporter(child, parent_dname, hide);
            }
        }
    }
}

F_NONNULL
static void ztree_report_hidden_subzones(const ztree_t* zt, const uint8_t* parent_dname) {
    dmn_assert(zt); dmn_assert(parent_dname);
    ztree_subzone_reporter(zt, parent_dname, true);
}

F_NONNULL
static void ztree_report_revealed_subzones(const ztree_t* zt, const uint8_t* parent_dname) {
    dmn_assert(zt); dmn_assert(parent_dname);
    ztree_subzone_reporter(zt, parent_dname, false);
}

static void _ztree_update(ztree_t* root, zone_t* z_old, zone_t* z_new, const bool in_txn) {
    dmn_assert(root);
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

    ztree_t* this_zt;
    zone_t** new_list = NULL;
    zone_t** old_list = NULL;

    if(!z_old) { // insert
        dmn_assert(z_new);
        log_debug("ztree_update: inserting new data for zone %s from src %s", logf_dname(z_new->dname), z_new->src);
        const uint8_t* lstack[127];
        unsigned lcount = dname_to_lstack(z_new->dname, lstack);
        this_zt = root;
        const uint8_t* hiding_zone = NULL;
        while(lcount) {
            if(this_zt->zones)
                hiding_zone = this_zt->zones[0]->dname;
            this_zt = ztree_node_find_or_add_child(this_zt, lstack[--lcount]);
            dmn_assert(this_zt);
        }

        const zone_t* old_head = NULL;
        old_list = this_zt->zones;
        if(!this_zt->zones) {
            new_list = xmalloc(sizeof(zone_t*));
            new_list[0] = z_new;
            this_zt->zones_len = 1;
        }
        else {
            // copy zone list and insert new zone at end, then sort
            old_head = old_list[0];
            const unsigned old_len = this_zt->zones_len;
            old_list = this_zt->zones;
            new_list = xmalloc((old_len + 1) * sizeof(zone_t*));
            memcpy(new_list, old_list, old_len * sizeof(zone_t*));
            new_list[old_len] = z_new;
            zones_sort(new_list, old_len + 1);
            this_zt->zones_len++;
        }

        if(z_new == new_list[0]) {
            if(old_head)
                log_info("Zone %s: source %s with serial %u loaded as authoritative (supercedes extant source %s with serial %u)", logf_dname(z_new->dname), z_new->src, z_new->serial, old_head->src, old_head->serial);
            else
                log_info("Zone %s: source %s with serial %u loaded as authoritative", logf_dname(z_new->dname), z_new->src, z_new->serial);
        }
        else {
            log_info("Zone %s: source %s with serial %u loaded (but is hidden by extant source %s with serial %u)", logf_dname(z_new->dname), z_new->src, z_new->serial, new_list[0]->src, new_list[0]->serial);
        }
        if(hiding_zone)
            log_warn("Zone %s was added as a hidden subzone of extant parent %s", logf_dname(z_new->dname), logf_dname(hiding_zone));
        else if(!old_head)
            ztree_report_hidden_subzones(this_zt, z_new->dname);
    }
    else { // update or delete
        const uint8_t* lstack[127];
        unsigned lcount = dname_to_lstack(z_old->dname, lstack);
        this_zt = root;
        const uint8_t* hiding_zone = NULL;
        while(lcount) {
            if(this_zt->zones)
                hiding_zone = this_zt->zones[0]->dname;
            this_zt = ztree_node_find_child(this_zt, lstack[--lcount], false);
            dmn_assert(this_zt);
        }

        old_list = this_zt->zones;
        dmn_assert(this_zt->zones); // z_old must already exist, or programmer error

        const unsigned old_len = this_zt->zones_len;
        if(!z_new) { // delete case
            log_debug("ztree_update: deleting data for zone %s from src %s", logf_dname(z_old->dname), z_old->src);
            if(this_zt->zones_len == 1) {
                new_list = NULL;
                this_zt->zones_len = 0;
                log_info("Zone %s: authoritative source %s with serial %u removed (zone no longer exists)", logf_dname(z_old->dname), z_old->src, z_old->serial);
                if(!hiding_zone)
                    ztree_report_revealed_subzones(this_zt, z_old->dname);
            }
            else {
                const zone_t* old_head = old_list[0];
                new_list = xmalloc((old_len - 1) * sizeof(zone_t*));
                unsigned i,j;
                for(i = 0, j = 0; j < old_len; i++, j++) {
                    if(old_list[j] == z_old)
                        i--;
                    else
                       new_list[i] = old_list[j];
                }
                this_zt->zones_len--;

                // it may not be very obvious due to the strange
                //   copy-loop above, but only one entry is removed,
                //   and the list must still contain at least one entry
                // XXX - re-write the above in a clearer way, and/or
                //    somehow assert the lack of duplicates in the original list?
                dmn_assert(this_zt->zones_len);
                dmn_assert(i == this_zt->zones_len);
                dmn_assert(new_list[0]);

                if(old_head == z_old)
                    log_info("Zone %s: authoritative source %s with serial %u removed (extant source %s with serial %u promoted to authoritative)", logf_dname(z_old->dname), z_old->src, z_old->serial, new_list[0]->src, new_list[0]->serial);
                else
                    log_info("Zone %s: hidden source %s with serial %u removed (extant source %s with serial %u continues to be authoritative)", logf_dname(z_old->dname), z_old->src, z_old->serial, new_list[0]->src, new_list[0]->serial);
            }
        }
        else { // update case
            log_debug("ztree_update: updating data for zone %s from src %s", logf_dname(z_old->dname), z_old->src);
            // replace old with new in new_list
            const zone_t* old_head = old_list[0];
            new_list = xmalloc(old_len * sizeof(zone_t*));
            memcpy(new_list, old_list, old_len * sizeof(zone_t*));
            for(unsigned i = 0; i < old_len; i++)
                if(new_list[i] == z_old)
                    new_list[i] = z_new;
            zones_sort(new_list, old_len);
            if(z_old == old_head) {
                if(z_new == new_list[0])
                    log_info("Zone %s: source %s updated to serial %u from serial %u, continues to be authoritative", logf_dname(z_old->dname), z_old->src, z_new->serial, z_old->serial);
                else
                    log_info("Zone %s: source %s updated to serial %u from serial %u and demoted to hidden.  Extant source %s with serial %u promoted to authoritative", logf_dname(z_old->dname), z_old->src, z_new->serial, z_old->serial, new_list[0]->src, new_list[0]->serial);
            }
            else {
                if(z_new == new_list[0])
                    log_info("Zone %s: source %s updated to serial %u from serial %u, promoted to authoritative (extant source %s with serial %u demoted)", logf_dname(z_old->dname), z_old->src, z_new->serial, z_old->serial, old_head->src, old_head->serial);
                else
                    log_info("Zone %s: hidden source %s updated to serial %u from serial %u. Extant source %s with serial %u continues to be authoritative", logf_dname(z_old->dname), z_old->src, z_new->serial, z_old->serial, old_head->src, old_head->serial);
            }
        }
    }

    // swap lists and free
    if(in_txn) {
        this_zt->zones = new_list;
    }
    else {
        gdnsd_prcu_upd_lock();
        gdnsd_prcu_upd_assign(this_zt->zones, new_list);
        gdnsd_prcu_upd_unlock();
    }
    if(old_list)
        free(old_list);
}

void ztree_update(zone_t* z_old, zone_t* z_new) {
    dmn_assert(ztree_root);
    dmn_assert(!new_root); // no txn currently ongoing
    _ztree_update(ztree_root, z_old, z_new, false);
}

void ztree_txn_update(zone_t* z_old, zone_t* z_new) {
    dmn_assert(ztree_root);
    dmn_assert(new_root); // pending txn
    _ztree_update(new_root, z_old, z_new, true);
}

// clones share linked label and zone values, but
//  not the ztree_t/ztchildren_t containers.
F_NONNULL
static ztree_t* ztree_clone(const ztree_t* original) {
    dmn_assert(original);

    ztree_t* ztclone = xmalloc(sizeof(ztree_t));
    ztclone->label = original->label;
    if  (original->zones) {
        ztclone->zones = xmalloc(original->zones_len * sizeof(zone_t*));
        memcpy(ztclone->zones, original->zones, original->zones_len * sizeof(zone_t*));
        ztclone->zones_len = original->zones_len;
    } else {
        ztclone->zones = NULL;
        ztclone->zones_len = 0;
    }
    ztchildren_t* old_ztc = original->children;
    if(old_ztc) {
        ztchildren_t* new_ztc = ztclone->children = xcalloc(1, sizeof(ztchildren_t));
        new_ztc->alloc = old_ztc->alloc;
        new_ztc->count = old_ztc->count;
        new_ztc->store = xcalloc(new_ztc->alloc, sizeof(ztree_t*));
        for(unsigned i = 0; i < new_ztc->alloc; i++) {
            ztree_t* entry = old_ztc->store[i];
            if(entry)
                new_ztc->store[i] = ztree_clone(entry);
        }
    }
    else {
        ztclone->children = NULL;
    }
    return ztclone;
}

F_NONNULL
static void ztree_destroy_clone(ztree_t* ztclone) {
    dmn_assert(ztclone);

    ztchildren_t* old_ztc = ztclone->children;
    if(old_ztc) {
        if(old_ztc->alloc) {
            for(unsigned i = 0; i < old_ztc->alloc; i++) {
                ztree_t* entry = old_ztc->store[i];
                if(entry)
                    ztree_destroy_clone(entry);
            }
            free(old_ztc->store);
        }
        free(old_ztc);
    }
    if(ztclone->zones)
        free(ztclone->zones);
    free(ztclone);
}

void ztree_txn_start(void) {
    dmn_assert(ztree_root);
    dmn_assert(!new_root); // no txn currently ongoing
    new_root = ztree_clone(ztree_root);
    log_info("Multi-zone update transaction starting ...");
}

void ztree_txn_abort(void) {
    dmn_assert(ztree_root);
    dmn_assert(new_root);
    ztree_destroy_clone(new_root);
    new_root = NULL;
    log_info("Multi-zone update transaction aborted");
}

void ztree_txn_end(void) {
    dmn_assert(ztree_root);
    dmn_assert(new_root);
    ztree_t* old_root = ztree_root;
    gdnsd_prcu_upd_lock();
    gdnsd_prcu_upd_assign(ztree_root, new_root);
    gdnsd_prcu_upd_unlock();
    ztree_destroy_clone(old_root);
    new_root = NULL;
    log_info("Multi-zone update transaction committed");
}
