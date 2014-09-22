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

#include "config.h"
#include "dcinfo.h"
#include <gdnsd/vscf.h>
#include <inttypes.h>
#include <stdbool.h>

typedef struct _dclists dclists_t;

typedef enum {
   KILL_NO_LISTS,
   KILL_ALL_LISTS,
   KILL_NEW_LISTS
} dclists_destroy_depth_t;

F_NONNULL
dclists_t* dclists_new(const dcinfo_t* info);
F_NONNULL
dclists_t* dclists_clone(const dclists_t* old);
F_NONNULL F_PURE
unsigned dclists_get_count(const dclists_t* lists);
F_NONNULL F_PURE
const uint8_t* dclists_get_list(const dclists_t* lists, const unsigned idx);
F_NONNULL
void dclists_replace_list0(dclists_t* lists, uint8_t* newlist);
F_NONNULL
int dclists_xlate_vscf(dclists_t* lists, vscf_data_t* vscf_list, const char* map_name, uint8_t* newlist, const bool allow_auto);
F_NONNULL
int dclists_find_or_add_vscf(dclists_t* lists, vscf_data_t* vscf_list, const char* map_name, const bool allow_auto);
F_NONNULL
unsigned dclists_city_auto_map(dclists_t* lists, const char* map_name, const unsigned raw_lat, const unsigned raw_lon);
F_NONNULL
void dclists_destroy(dclists_t* lists, dclists_destroy_depth_t depth);

#endif // DCLISTS_H
