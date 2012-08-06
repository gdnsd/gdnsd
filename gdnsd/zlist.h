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

#ifndef _GDNSD_ZLIST_H
#define _GDNSD_ZLIST_H

#include "config.h"
#include "gdnsd.h"

#include <inttypes.h>
#include "ltarena.h"

// mutually-dependent stuff between zone.h and ltree.h
struct _zone_struct;
typedef struct _zone_struct zone_t;

#include "ltree.h"

struct _zone_struct {
    unsigned hash;        // hash of dname
    time_t mtime;         // mod time of source
    char* src;            // string description of src, e.g. "rfc1035:example.com"
    const uint8_t* dname; // zone name as a dname (stored in ->arena)
    ltarena_t* arena;     // arena for dname/label storage
    ltree_node_t* root;   // the zone root
    zone_t* next;         // init to NULL, owned by zlist...
};

// Singleton init
void zlist_init(void);

// primary interface for zone data sources
void zlist_update(zone_t* z_old, zone_t* z_new);

// primary interface for zone data runtime lookups
// Argument is any legal fully-qualified dname
// Output is the zone_t structure for the known containing zone,
//   or NULL if no current zone contains the name.
// auth_depth_out is mostly useful for dnspacket.c, it tells you
//   how many bytes into the dname the authoritative zone name
//   starts at.
F_NONNULLX(1)
zone_t* zlist_find_zone_for(const uint8_t* dname, unsigned* auth_depth_out);

// zlist readlock for access
// callers of zlist_find_zone_for() need to lock before calling, and then
//   need to keep that lock for as long as they continue to reference data
//   from the resulting zone_t* (which should be brief...)
void zlist_rdlock(void);
void zlist_unlock(void);

// These are for zsrc_* code to create/delete detached zone_t's used
//   in zlist_update() calls.
F_NONNULL
zone_t* zone_new(const char* zname, const char* source);
F_NONNULL
bool zone_finalize(zone_t* zone);
F_NONNULL
void zone_delete(zone_t* zone);

#endif // _GDNSD_ZLIST_H
