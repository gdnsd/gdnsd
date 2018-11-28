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

#ifndef DCINFO_H
#define DCINFO_H

#include <gdnsd/compiler.h>
#include <gdnsd/vscf.h>
#include <gdmaps.h>

#include <math.h>

// DEG2RAD converts degrees to radians.  Our auto_dc_coords input
//   and GeoIPCity coordinate data is in degrees, and must be
//   converted to radians before storage (auto_dc_coords) or use
//   (GeoIPCity data), because our geodist() func takes its inputs
//   in radians
#define DEG2RAD (M_PI / 180.0)

// The datacenter numbers are always 1-based, and only up to 254
//  datacenters are supported.  The first datacenter is always #1,
//  and in a 3-datacenter config they're 1, 2, 3.  The zero-value
//  is used to terminate datacenter lists that are implemented
//  as uint8_t* strings on which standard string ops work (e.g.
//  strcmp(), strcpy()).
// dcinfo_t holds a list of datacenters in the order
//  specified in the config, which is the default order.  Therefore
//  the default order, in dclist format, is e.g. for num_dcs == 3,
//  \1\2\3\0.  It also tracks their monitoring index and coordinates.
// dcinfo_t also holds auto_limit, which is the lesser of the
//  configured auto_dc_limit and the actual num_dcs, so that it's
//  always the correct limit for direct application even if num_dcs
//  is < auto_dc_limit.

#define MAX_NUM_DCS 254

typedef struct {
    double lat;
    double lon;
    double cos_lat;
} dcinfo_coords_t;

typedef struct {
    char* name;
    dcinfo_coords_t coords;
    unsigned mon_index;
} dci_t;

typedef struct {
    unsigned num_dcs;    // count of datacenters
    unsigned auto_limit; // lesser of num_dcs and dc_auto_limit cfg
    dci_t* dcs;          // ordered list of datacenters, #num_dcs
} dcinfo_t;

F_NONNULLX(1, 2, 5)
void dcinfo_init(dcinfo_t* info, vscf_data_t* dc_cfg, vscf_data_t* dc_auto_cfg, vscf_data_t* dc_auto_limit_cfg, const char* map_name, monreg_func_t mrf);
F_NONNULL F_PURE
unsigned dcinfo_get_count(const dcinfo_t* info);
F_NONNULL F_PURE
unsigned dcinfo_get_limit(const dcinfo_t* info);
F_NONNULL F_PURE F_RETNN
const dcinfo_coords_t* dcinfo_get_coords(const dcinfo_t* info, const unsigned dcnum);
F_NONNULLX(1) F_PURE
unsigned dcinfo_name2num(const dcinfo_t* info, const char* dcname);
F_NONNULL F_PURE
const char* dcinfo_num2name(const dcinfo_t* info, const unsigned dcnum);
F_NONNULL F_PURE
unsigned dcinfo_map_mon_idx(const dcinfo_t* info, const unsigned dcnum);

#endif // DCINFO_H
