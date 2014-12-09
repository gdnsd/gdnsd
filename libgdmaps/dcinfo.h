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

// DEG2RAD converts degrees to radians.  Our auto_dc_coords input
//   and GeoIPCity coordinate data is in degrees, and must be
//   converted to radians before storage (auto_dc_coords) or use
//   (GeoIPCity data), because our haversine() func takes its inputs
//   in radian format
static const double DEG2RAD = 0.017453292519943295769236907684886;

typedef struct _dcinfo dcinfo_t;

F_NONNULLX(1, 4)
dcinfo_t* dcinfo_new(vscf_data_t* dc_cfg, vscf_data_t* dc_auto_cfg, vscf_data_t* dc_auto_limit_cfg, const char* map_name);
F_NONNULL F_PURE
unsigned dcinfo_get_count(const dcinfo_t* info);
F_NONNULL F_PURE
unsigned dcinfo_get_limit(const dcinfo_t* info);
F_NONNULL F_PURE
const double* dcinfo_get_coords(const dcinfo_t* info, const unsigned dcnum);
F_NONNULLX(1) F_PURE
unsigned dcinfo_name2num(const dcinfo_t* info, const char* dcname);
F_NONNULL F_PURE
const char* dcinfo_num2name(const dcinfo_t* info, const unsigned dcnum);
F_NONNULL F_PURE
unsigned dcinfo_map_mon_idx(const dcinfo_t* info, const unsigned dcnum);

#endif // DCINFO_H
