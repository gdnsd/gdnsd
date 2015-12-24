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

#ifndef DCMAP_H
#define DCMAP_H

#include "dclists.h"

#include <gdnsd/compiler.h>
#include <gdnsd/vscf.h>

#include <inttypes.h>
#include <stdbool.h>

typedef struct _dcmap dcmap_t;

F_NONNULL F_MALLOC
dcmap_t* dcmap_new(vscf_data_t* map_cfg, dclists_t* dclists, const unsigned parent_def, const unsigned true_depth, const char* map_name, const bool allow_auto);

F_NONNULL F_PURE
uint32_t dcmap_lookup_loc(const dcmap_t* dcmap, const char* locstr);

// size of "lookup" storage below, including terminal NUL
#define DCMAP_LOOKUP_MAXLEN 128
typedef void (*dcmap_lookup_cb_t)(void* data, char* lookup, const unsigned level);
F_NONNULL
uint32_t dcmap_lookup_loc_callback(const dcmap_t* dcmap, dcmap_lookup_cb_t cb, void* data);

F_NONNULL
void dcmap_destroy(dcmap_t* dcmap);

#endif // DCMAP_H
