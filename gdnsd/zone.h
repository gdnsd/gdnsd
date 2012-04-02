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

#ifndef _GDNSD_ZONE_H
#define _GDNSD_ZONE_H

#include "config.h"

#include <inttypes.h>
#include "ltarena.h"

static const char ZONES_DIR[] = "etc/zones/";

// mutually-dependent stuff between zone.h and ltree.h
struct _zone_struct;
typedef struct _zone_struct zone_t;

#include "ltree.h"

struct _zone_struct {
    unsigned hash;        // hash of dname
    char* fn;             // zone filename w/ dir prefix, can be used directly
    const uint8_t* dname; // zone name as a dname (stored in ->arena)
    ltarena_t* arena;     // arena for dname/label storage
    ltree_node_t* root;   // the zone root
};

// Allocates a new zone_t (see above).
//   .arena will be initialized for storage
//   .fn will be initialized as "etc/zones/" + zfn
//   .dname will be converted from zfn
//   .hash will be initialized to the hash of dname
//   .root will be NULL until the zone is later scanned/loaded by zscan/ltree code
// This function can fail if the contents of "zfn" cannot be
//   cleanly parsed as an FQDN for "dname", in which case it
//   logs the specific error and returns NULL.
F_NONNULL
zone_t* zone_new(const char* zfn);

// Completely desctructs a zone_t, including .root if present
F_NONNULL
void zone_delete(zone_t* zone);

#endif // _GDNSD_ZONE_H
