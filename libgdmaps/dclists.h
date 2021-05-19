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

#ifndef DCLISTS_H
#define DCLISTS_H

#include "dcinfo.h"

#include <gdnsd/compiler.h>
#include <gdnsd/vscf.h>

#include <inttypes.h>
#include <stdbool.h>

struct dclists {
    unsigned count; // count of unique result lists
    unsigned old_count; // count from object we cloned from
    uint8_t** list;    // strings of dc numbers
    const struct dcinfo* info; // struct dclists doesn't own "info", just uses it for reference a lot
};

enum dclists_destroy_depth {
    KILL_NO_LISTS,
    KILL_ALL_LISTS,
    KILL_NEW_LISTS
};

// At the nlist/ntree layer, a uint32_t node reference has the high bit set
//   if it's a dclist, and cleared if it's an internal tree-node reference.
// This implies that legal, real dclist indices used in the construction of
//   struct nlist and struct ntree cannot have the high bit set, ever, and thus our
//   list of real dclist indices is a 31-bit value.
// As a further constraint, the maximal 31-bit value is not allowed for a real
//   dclist index because it is used in two magic ways:
//   1) At the dclists/dcmap/gdgeoip layer it's used to signal automatic
//     distance-mapped mapping (DCLIST_AUTO below), which will be translated
//     to a real dclist index before passing to the nlist/tree layer.
//   2) NN_UNDEF is the 'undefined' case at the nlist/tree layer and is the
//     value UINT32_MAX, and we don't want a legit dclist index, when OR'd
//     with the high-bit at the ntree layer, to overlap with this definition
//     of NN_UNDEF.
// Therefore:
#define DCLIST_AUTO 0x7FFFFFFF
#define DCLIST_MAX  0x7FFFFFFE

F_NONNULL F_WUNUSED F_RETNN
struct dclists* dclists_new(const struct dcinfo* info);
F_NONNULL F_WUNUSED F_RETNN
struct dclists* dclists_clone(const struct dclists* old);
F_NONNULL F_PURE
unsigned dclists_get_count(const struct dclists* lists);
F_NONNULL F_PURE F_RETNN
const uint8_t* dclists_get_list(const struct dclists* lists, const uint32_t idx);
F_NONNULL
void dclists_replace_list0(const struct dclists* lists, uint8_t* newlist);

// retval here: true -> "auto", false -> normal list
F_NONNULL
bool dclists_xlate_vscf(const struct dclists* lists, vscf_data_t* vscf_list, const char* map_name, uint8_t* newlist, const bool allow_auto);

F_NONNULL
uint32_t dclists_find_or_add_vscf(struct dclists* lists, vscf_data_t* vscf_list, const char* map_name, const bool allow_auto);
F_NONNULL
uint32_t dclists_city_auto_map(struct dclists* lists, const char* map_name, const double lat, const double lon);
F_NONNULL
void dclists_destroy(struct dclists* lists, enum dclists_destroy_depth depth);

#endif // DCLISTS_H
