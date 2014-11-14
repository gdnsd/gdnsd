/* Copyright © 2013 Timo Teräs <timo.teras@iki.fi>
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

#ifndef GDNSD_ZSCAN_DJB_H
#define GDNSD_ZSCAN_DJB_H

#include "config.h"

typedef struct _zscan_djb_zonedata {
    zone_t* zone;
    int marked;
    struct _zscan_djb_zonedata* next;
} zscan_djb_zonedata_t;

void zscan_djbzone_add(zscan_djb_zonedata_t**, zone_t *zone);
zscan_djb_zonedata_t* zscan_djbzone_get(zscan_djb_zonedata_t*, const uint8_t*, int);
void zscan_djbzone_free(zscan_djb_zonedata_t**);

F_WUNUSED F_NONNULL
bool zscan_djb(const char* djb_path, zscan_djb_zonedata_t** zonedata);

#endif // GDNSD_ZSCAN_DJB_H
