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

#include "zsrc_djb.h"
#include "zscan_djb.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "conf.h"
#include "ltree.h"
#include "gdnsd/log.h"
#include "gdnsd/paths.h"

static struct ev_loop* zones_loop = NULL;
static ev_async* sighup_waker = NULL;
static char* djb_dir = NULL;
static zscan_djb_zonedata_t* active_zonedata = NULL;

static void unload_zones(void) {
    ztree_txn_start();
    for (zscan_djb_zonedata_t* cur = active_zonedata; cur; cur = cur->next)
        ztree_txn_update(cur->zone, NULL);
    ztree_txn_end();

    zscan_djbzone_free(&active_zonedata);
}

static void zsrc_djb_sync_zones(void) {
    zscan_djb_zonedata_t* zonedata;
    int num_zones = 0;

    if (zscan_djb(djb_dir, &zonedata))
        return;

    ztree_txn_start();
    for (zscan_djb_zonedata_t* cur = zonedata; cur; cur = cur->next) {
        zscan_djb_zonedata_t* old = zscan_djbzone_get(active_zonedata, cur->zone->dname, 1);
        if (old) {
            old->marked = 1;
            ztree_txn_update(old->zone, cur->zone);
            //ztree_update(old->zone, cur->zone);
        } else {
            ztree_txn_update(NULL, cur->zone);
            //ztree_update(NULL, cur->zone);
        }
        num_zones++;
    }
    for (zscan_djb_zonedata_t* cur = active_zonedata; cur; cur = cur->next) {
        if (!cur->marked)
            ztree_txn_update(cur->zone, NULL);
            //ztree_update(cur->zone, NULL);
    }
    ztree_txn_end();

    log_info("zsrc_djb: loaded %d zones...", num_zones);

    zscan_djbzone_free(&active_zonedata);
    active_zonedata = zonedata;
}

void zsrc_djb_load_zones(void) {
    djb_dir = gdnsd_resolve_path_cfg("djbdns/", NULL);
    zsrc_djb_sync_zones();
    if(atexit(unload_zones))
        log_fatal("zsrc_djb: atexit(unload_zones) failed: %s", logf_errno());
}

// called within our thread/loop to take sighup action
F_NONNULL
static void sighup_cb(struct ev_loop* loop, ev_async* w V_UNUSED, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w);
    log_info("zsrc_djb: received SIGHUP notification, scanning for changes...");
    zsrc_djb_sync_zones();
}

// called from main thread to feed ev_async
void zsrc_djb_sighup(void) {
    dmn_assert(zones_loop); dmn_assert(sighup_waker);
    ev_async_send(zones_loop, sighup_waker);
}

void zsrc_djb_runtime_init(struct ev_loop* loop) {
    dmn_assert(loop);

    zones_loop = loop;
    sighup_waker = malloc(sizeof(ev_async));
    ev_async_init(sighup_waker, sighup_cb);
    ev_async_start(loop, sighup_waker);
}
