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

static struct ev_loop* zones_loop = NULL;
static ev_async* sigusr1_waker = NULL;
static char* djb_dir = NULL;
static zscan_djb_zonedata_t* active_zonedata = NULL;

static void unload_zones(void) {
    if (active_zonedata) {
        ztree_txn_start();
        for (zscan_djb_zonedata_t* cur = active_zonedata; cur; cur = cur->next)
            ztree_txn_update(cur->zone, NULL);
        ztree_txn_end();

        for (zscan_djb_zonedata_t* cur = active_zonedata; cur; cur = cur->next)
            zone_delete(cur->zone);

        zscan_djbzone_free(&active_zonedata);
    }
}

static void zsrc_djb_sync_zones(void) {
    zscan_djb_zonedata_t* zonedata;
    int num_zones = 0;

    if (zscan_djb(djb_dir, &zonedata) || (!active_zonedata && !zonedata))
        return;

    ztree_txn_start();

    for (zscan_djb_zonedata_t* cur = zonedata; cur; cur = cur->next) {
        zscan_djb_zonedata_t* old = zscan_djbzone_get(active_zonedata, cur->zone->dname, 1);
        if (old) {
            old->marked = 1;
            ztree_txn_update(old->zone, cur->zone);
        } else {
            ztree_txn_update(NULL, cur->zone);
        }
        num_zones++;
    }

    for (zscan_djb_zonedata_t* cur = active_zonedata; cur; cur = cur->next)
        if (!cur->marked)
            ztree_txn_update(cur->zone, NULL);

    ztree_txn_end();

    // now delete the unused zone_t's that were removed/replaced in the multi-zone
    //   transaction above.
    for (zscan_djb_zonedata_t* cur = zonedata; cur; cur = cur->next) {
        zscan_djb_zonedata_t* old = zscan_djbzone_get(active_zonedata, cur->zone->dname, 1);
        if (old)
            zone_delete(old->zone);
    }

    for (zscan_djb_zonedata_t* cur = active_zonedata; cur; cur = cur->next)
        if (!cur->marked)
            zone_delete(cur->zone);

    log_info("zsrc_djb: loaded %d zones from %s...", num_zones, djb_dir);

    zscan_djbzone_free(&active_zonedata);
    active_zonedata = zonedata;
}

// XXX check_only could be used to optimize for the checkconf case,
//   so long as the optimization doesn't change the validity of the check.
void zsrc_djb_load_zones(const bool check_only V_UNUSED) {
    djb_dir = gdnsd_resolve_path_cfg("djbdns/", NULL);
    zsrc_djb_sync_zones();
    gdnsd_atexit_debug(unload_zones);
}

// called within our thread/loop to take sigusr1 action
F_NONNULL
static void sigusr1_cb(struct ev_loop* loop V_UNUSED, ev_async* w V_UNUSED, int revents V_UNUSED) {
    log_info("zsrc_djb: received SIGUSR1 notification, scanning for changes...");
    zsrc_djb_sync_zones();
}

// called from main thread to feed ev_async
void zsrc_djb_sigusr1(void) {
    dmn_assert(zones_loop); dmn_assert(sigusr1_waker);
    ev_async_send(zones_loop, sigusr1_waker);
}

void zsrc_djb_runtime_init(struct ev_loop* loop) {
    zones_loop = loop;
    sigusr1_waker = xmalloc(sizeof(ev_async));
    ev_async_init(sigusr1_waker, sigusr1_cb);
    ev_async_start(loop, sigusr1_waker);
}
