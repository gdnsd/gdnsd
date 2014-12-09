/* Copyright © 2014 Brandon L Black <blblack@gmail.com>
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

#ifndef GDGEOIP2_H
#define GDGEOIP2_H

#include <gdnsd/compiler.h>

#include "dclists.h"
#include "dcmap.h"
#include "nlist.h"

#include <stdbool.h>

F_NONNULLX(1,2,3)
nlist_t* gdgeoip2_make_list(const char* pathname, const char* map_name, dclists_t* dclists, const dcmap_t* dcmap, const bool city_auto_mode, const bool city_no_region);

#endif // GDGEOIP2_H
