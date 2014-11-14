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

#ifndef GDGEOIP_H
#define GDGEOIP_H

#include <gdnsd/log.h>
#include "fips104.h"
#include "dclists.h"
#include "dcmap.h"
#include "nlist.h"

F_NONNULL
void validate_country_code(const char* cc, const char* map_name);
F_NONNULL
void validate_continent_code(const char* cc, const char* map_name);

typedef enum {
    V4O_NONE = 0, // no v4_overlay in effect
    V4O_PRIMARY,  // v4_overlay in effect, and this is the primary (must be IPv6, skip IPv4 area)
    V4O_SECONDARY, // v4_overlay in effect, and this is the secondary (must be IPv4)
} gdgeoip_v4o_t;

F_NONNULLX(1,2,3)
nlist_t* gdgeoip_make_list(const char* pathname, const char* map_name, dclists_t* dclists, const dcmap_t* dcmap, const fips_t* fips, const gdgeoip_v4o_t v4o_flag, const bool city_auto_mode, const bool city_no_city);

#endif // GDGEOIP_H
