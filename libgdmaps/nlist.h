/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
 *
 * This file is part of gdnsd.
 *
 * gdnsd-plugin-geoip is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * gdnsd-plugin-geoip is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gdnsd.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef NLIST_H
#define NLIST_H

#include "ntree.h"

#include <gdnsd/compiler.h>

#include <inttypes.h>
#include <stdbool.h>

typedef struct nlist nlist_t;

// pre_norm flag indicates that the data to be added via _append()
//   will already be in fully normalized form and order other than
//   the possibility of dclist-based merges of adjacent subnets.
// This allows for significant optimizations in GeoIP input case,
//   as GeoIP's data structure implies these guarantees when walked
//   in order for _append().
F_NONNULL F_WUNUSED F_RETNN
nlist_t* nlist_new(const char* map_name, const bool pre_norm);

F_NONNULL
void nlist_destroy(nlist_t* nl);

F_NONNULL
void nlist_append(nlist_t* nl, const uint8_t* ipv6, const unsigned mask, const unsigned dclist);

// Call this when all nlist_append() are complete.  For lists
//   which are not "pre_norm", this does a bunch of normalization
//   transformations on the data first (which can fail, hence
//   the bool retval).  "pre_norm" lists get their normalization
//   state assert()'d expensively in debug builds.
// Regardless, storage is also realloc'd down to exact size.
F_NONNULL
void nlist_finish(nlist_t* nl);

// must pass through _finish() before *any* of the xlate/merge funcs below
F_NONNULL F_RETNN
ntree_t* nlist_xlate_tree(const nlist_t* nl_a);
F_NONNULL F_RETNN
ntree_t* nlist_merge2_tree(const nlist_t* nl_a, const nlist_t* nl_b);

// Just for debugging...
F_NONNULL
void nlist_debug_dump(const nlist_t* nl);

#endif // NLIST_H
