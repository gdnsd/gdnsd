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

#ifndef _GDNSD_ZSCAN_H
#define _GDNSD_ZSCAN_H

#include "config.h"
#include "gdnsd.h"

typedef struct {
    unsigned def_ttl;
    unsigned n_subzones;
    const char* zones_dir;
    const char* name;
    const char* file;
    const uint8_t* dname;
    const uint8_t** subzones;
} zoneinfo_t;

F_NONNULL
void scan_zone(const zoneinfo_t* zone);

#endif // _GDNSD_ZSCAN_H
