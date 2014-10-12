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

#ifndef GDNSD_ZTREE_H
#define GDNSD_ZTREE_H

#include "config.h"

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "ltarena.h"

// high-res mtime stuff, for zsrc_*.c to use internally...
#if defined HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC
#  define get_mtimens(_xst) ((_xst).st_mtim.tv_nsec)
#  define has_mtimens 1
#elif defined HAVE_STRUCT_STAT_ST_MTIMESPEC_TV_NSEC
#  define get_mtimens(_xst) ((_xst).st_mtimespec.tv_nsec)
#  define has_mtimens 1
#elif defined HAVE_STRUCT_STAT_ST_MTIMENSEC
#  define get_mtimens(_xst) ((_xst).st_mtimensec)
#  define has_mtimens 1
#else
#  define get_mtimens(_xst) 0
#  define has_mtimens 0
#endif

F_UNUSED
static uint64_t get_extended_mtime(const struct stat* st) {
    return (((uint64_t)st->st_mtime) * 1000000000ULL)
        + (uint64_t)get_mtimens(*st);
}

// mutually-dependent stuff between zone.h and ltree.h
struct _zone_struct;
typedef struct _zone_struct zone_t;

#include "ltree.h"

struct _zone_struct {
    unsigned hash;        // hash of dname
    unsigned serial;      // SOA serial from zone data
    uint64_t mtime;       // mod time of source as uint64_t nanoseconds unix-time
                          //    (use get_extended_mtime() above if src is struct stat!)
    char* src;            // string description of src, e.g. "rfc1035:example.com"
    const uint8_t* dname; // zone name as a dname (stored in ->arena)
    ltarena_t* arena;     // arena for dname/label storage
    ltree_node_t* root;   // the zone root
    zone_t* next;         // init to NULL, owned by ztree...
};

// Singleton init
void ztree_init(void);

// --- zsrc_* interfaces ---

// Single-zone transaction:
//  if(z_old && !z_new) -> delete z_old from ztree
//  if(!z_old && z_new) -> insert z_new into ztree
//  if(z_old && z_new) -> replace z_old with z_new in ztree
//  if(!z_old && !z_new) -> illegal
void ztree_update(zone_t* z_old, zone_t* z_new);

// Multi-zone transaction. As above, but there are rules:
//  1) txn_update() can only happen inbetween txn_start()/txn_end()
//  2) You must txn_end() or txn_abort(), do not leave a txn hanging
//  3) regular zlist_update() not allowed during txn.
//  4) Updates will not appear for runtime until after txn_end() returns
//  5) You cannot delete any referenced zone_t's (z_old arguments)
//     until after txn_end() returns.
void ztree_txn_start(void);
void ztree_txn_update(zone_t* z_old, zone_t* z_new);
void ztree_txn_abort(void);
void ztree_txn_end(void);

// These are for zsrc_* code to create/delete detached zone_t's used
//   in ztree_update() calls.
F_NONNULL
zone_t* zone_new(const char* zname, const char* source);
F_NONNULL
bool zone_finalize(zone_t* zone);
F_NONNULL
void zone_delete(zone_t* zone);

// --- dnsio/dnspacket reader interfaces ---

// primary interface for zone data runtime lookups from dnsio threads
// Argument is any legal fully-qualified dname
// Output is the zone_t structure for the known containing zone,
//   or NULL if no current zone contains the name.
// auth_depth_out is mostly useful for dnspacket.c, it tells you
//   how many bytes into the dname the authoritative zone name
//   starts at.
F_HOT F_NONNULL
zone_t* ztree_find_zone_for(const uint8_t* dname, unsigned* auth_depth_out);

#endif // GDNSD_ZTREE_H
