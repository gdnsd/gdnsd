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

#include <config.h>
#include "zsrc_djb.h"

#include "zscan_djb.h"
#include "conf.h"
#include "ltree.h"
#include "main.h"

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/paths.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

static char* djb_dir = NULL;

bool zsrc_djb_load_zones(ztree_t* tree)
{
    gdnsd_assert(djb_dir);

    zscan_djb_zonedata_t* zonedata = NULL;
    int num_zones = 0;
    bool failed = false;

    if (zscan_djb(djb_dir, &zonedata)) {
        failed = true;
    } else if (zonedata) {
        for (zscan_djb_zonedata_t* cur = zonedata; cur; cur = cur->next) {
            if (ztree_insert_zone(tree, cur->zone)) {
                failed = true;
                break;
            }
            num_zones++;
        }
    }

    if (failed)
        log_err("zsrc_djb: failed to load zone data");
    else
        log_info("zsrc_djb: loaded %d zones from %s...", num_zones, djb_dir);

    zscan_djbzone_free(&zonedata);
    return failed;
}

void zsrc_djb_init(void)
{
    djb_dir = gdnsd_resolve_path_cfg("djbdns/", NULL);
}
