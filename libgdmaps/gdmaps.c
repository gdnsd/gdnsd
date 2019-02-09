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

// gdmaps = GeoIP -> Datacenter Mapping library code

#include <config.h>
#include <gdmaps.h>

#include "dcinfo.h"
#include "dclists.h"
#include "dcmap.h"
#include "nlist.h"
#include "ntree.h"
#include "nets.h"
#include "gdgeoip2.h"

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/vscf.h>
#include <gdnsd/paths.h>
#include <gdnsd/misc.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>

#include <ev.h>
#include <urcu-qsbr.h>

// When an input file change is detected, we wait this long
//  for a followup change notification before processing.  Every time we get
//  another notification within the window, we restart the timer again.  This
//  coalesces rapid-fire updates.
#define STAT_RELOAD_WAIT 5.0

// *after* reloading an individual input file, this timer is kicked similarly
//   to the above, to wait for all rapid-fire updates to all input files to
//   quiesce a while.  When it finally expires, the parsed new data from each
//   are merged into a single runtime lookup database, and we do a locked
//   swap of the data for the runtime lookup threads.
#define ALL_RELOAD_WAIT 7.0

typedef struct {
    char* name;
    char* geoip_path;
    char* nets_path;
    dcinfo_t dcinfo; // basic datacenter list/info
    dcmap_t* dcmap; // map of locinfo -> dclist
    dclists_t* dclists; // corresponds to ->tree
    // Pending modified dclist for latest update(s) to ->foo_list, eventually promoted to
    // ->dclists when ->tree is updated, NULL when no pending update(s) are outstanding
    dclists_t* dclists_pend;
    nlist_t* geoip_list; // optional main geoip db
    nlist_t* nets_list; // net overrides, optional
    ntree_t* tree; // merged->translated from the lists above
    ev_stat geoip_stat_watcher;
    ev_stat nets_stat_watcher;
    ev_timer geoip_reload_timer;
    ev_timer nets_reload_timer;
    ev_timer tree_update_timer;
    bool city_auto_mode;
} gdmap_t;

F_NONNULL
static bool gdmap_badkey(const char* key, unsigned klen V_UNUSED, vscf_data_t* val V_UNUSED, const void* mapname_asvoid)
{
    const char* mapname = mapname_asvoid;
    log_fatal("plugin_geoip: map '%s': invalid config key '%s'", mapname, key);
    return false;
}

F_NONNULLX(1, 2, 3)
static void gdmap_init(gdmap_t* gdmap, const char* name, vscf_data_t* map_cfg, monreg_func_t mrf)
{
    // basics
    gdmap->name = xstrdup(name);
    if (!vscf_is_hash(map_cfg))
        log_fatal("plugin_geoip: value for map '%s' must be a hash", name);

    // datacenters config
    vscf_data_t* dc_cfg = vscf_hash_get_data_byconstkey(map_cfg, "datacenters", true);
    if (!dc_cfg)
        log_fatal("plugin_geoip: map '%s': missing required 'datacenters' array", name);
    vscf_data_t* dc_auto_cfg = vscf_hash_get_data_byconstkey(map_cfg, "auto_dc_coords", true);
    vscf_data_t* dc_auto_limit_cfg = vscf_hash_get_data_byconstkey(map_cfg, "auto_dc_limit", true);
    gdmap->city_auto_mode = dc_auto_cfg ? true : false;
    dcinfo_init(&gdmap->dcinfo, dc_cfg, dc_auto_cfg, dc_auto_limit_cfg, name, mrf);
    gdmap->dclists_pend = dclists_new(&gdmap->dcinfo);

    // geoip2 config
    vscf_data_t* gdb2_cfg = vscf_hash_get_data_byconstkey(map_cfg, "geoip2_db", true);
    if (gdb2_cfg) {
        if (!vscf_is_simple(gdb2_cfg) || !vscf_simple_get_len(gdb2_cfg))
            log_fatal("plugin_geoip: map '%s': 'geoip2_db' must have a non-empty string value", name);
        gdmap->geoip_path = gdnsd_resolve_path_cfg(vscf_simple_get_data(gdb2_cfg), "geoip");
    }

    // map config
    vscf_data_t* map_map = vscf_hash_get_data_byconstkey(map_cfg, "map", true);
    if (map_map) {
        if (!vscf_is_hash(map_map))
            log_fatal("plugin_geoip: map '%s': 'map' stanza must be a hash", name);
        if (!gdmap->geoip_path)
            log_fatal("plugin_geoip: map '%s': 'map' stanza requires 'geoip2_db'", name);
        gdmap->dcmap = dcmap_new(map_map, gdmap->dclists_pend, 0, 0, name, gdmap->city_auto_mode);
    }

    // nets config
    vscf_data_t* nets_cfg = vscf_hash_get_data_byconstkey(map_cfg, "nets", true);
    if (!nets_cfg || vscf_is_hash(nets_cfg)) {
        // statically-defined hash or empty, load now, leave path undefined
        gdmap->nets_list = nets_make_list(nets_cfg, gdmap->dclists_pend, name);
        if (!gdmap->nets_list)
            log_fatal("plugin_geoip: map '%s': error in 'nets' data, cannot continue", name);
    } else if (vscf_is_simple(nets_cfg) && vscf_simple_get_len(nets_cfg)) {
        // external file, define path for later loading and stat-watching
        gdmap->nets_path = gdnsd_resolve_path_cfg(vscf_simple_get_data(nets_cfg), "geoip");
    } else {
        log_fatal("plugin_geoip: map '%s': 'nets' stanza must be a hash of direct entries or a filename", name);
    }

    // check for invalid keys
    vscf_hash_iterate_const(map_cfg, true, gdmap_badkey, name);
}

F_NONNULL
static void gdmap_tree_update(gdmap_t* gdmap)
{
    gdnsd_assert(gdmap->dclists_pend);

    ntree_t* merged;

    if (gdmap->geoip_list) {
        merged = nlist_merge2_tree(gdmap->geoip_list, gdmap->nets_list);
    } else {
        merged = nlist_xlate_tree(gdmap->nets_list);
    }

    ntree_t* old_tree = gdmap->tree;
    dclists_t* old_lists = gdmap->dclists;

    rcu_assign_pointer(gdmap->dclists, gdmap->dclists_pend);
    rcu_assign_pointer(gdmap->tree, merged);
    synchronize_rcu();

    gdmap->dclists_pend = NULL;
    if (old_tree)
        ntree_destroy(old_tree);
    if (old_lists)
        dclists_destroy(old_lists, KILL_NO_LISTS);

    log_info("plugin_geoip: map '%s' runtime db updated. nets: %u dclists: %u", gdmap->name, gdmap->tree->count + 1, dclists_get_count(gdmap->dclists));
}

F_NONNULL
static bool gdmap_update_geoip(gdmap_t* gdmap, const char* path, nlist_t** out_list_ptr)
{
    dclists_t* update_dclists;

    if (!gdmap->dclists_pend) {
        gdnsd_assert(gdmap->dclists);
        update_dclists = dclists_clone(gdmap->dclists);
    } else {
        update_dclists = gdmap->dclists_pend;
    }

    nlist_t* new_list = gdgeoip2_make_list(
                            path,
                            gdmap->name,
                            update_dclists,
                            gdmap->dcmap,
                            gdmap->city_auto_mode
                        );

    bool rv = false;

    if (!new_list) {
        log_err("plugin_geoip: map '%s': (Re-)loading geoip database '%s' failed!", gdmap->name, path);
        if (!gdmap->dclists_pend)
            dclists_destroy(update_dclists, KILL_NEW_LISTS);
        rv = true;
    } else {
        if (!gdmap->dclists_pend)
            gdmap->dclists_pend = update_dclists;
        if (*out_list_ptr)
            nlist_destroy(*out_list_ptr);
        *out_list_ptr = new_list;
    }

    return rv;
}

F_NONNULL
static bool gdmap_update_nets(gdmap_t* gdmap)
{
    gdnsd_assert(gdmap->nets_path);

    dclists_t* update_dclists;

    if (!gdmap->dclists_pend) {
        gdnsd_assert(gdmap->dclists);
        update_dclists = dclists_clone(gdmap->dclists);
    } else {
        update_dclists = gdmap->dclists_pend;
    }

    vscf_data_t* nets_cfg = vscf_scan_filename(gdmap->nets_path);
    nlist_t* new_list = NULL;
    if (nets_cfg) {
        if (vscf_is_hash(nets_cfg)) {
            new_list = nets_make_list(nets_cfg, update_dclists, gdmap->name);
            if (!new_list)
                log_err("plugin_geoip: map '%s': (Re-)loading nets file '%s' failed!", gdmap->name, gdmap->nets_path);
        } else {
            gdnsd_assert(vscf_is_array(nets_cfg));
            log_err("plugin_geoip: map '%s': (Re-)loading nets file '%s' failed: file cannot be an array of values", gdmap->name, gdmap->nets_path);
        }
        vscf_destroy(nets_cfg);
    } else {
        log_err("plugin_geoip: map '%s': parsing nets file '%s' failed", gdmap->name, gdmap->nets_path);
    }

    bool rv = false;

    if (!new_list) {
        if (!gdmap->dclists_pend)
            dclists_destroy(update_dclists, KILL_NEW_LISTS);
        rv = true;
    } else {
        if (!gdmap->dclists_pend)
            gdmap->dclists_pend = update_dclists;
        if (gdmap->nets_list)
            nlist_destroy(gdmap->nets_list);
        gdmap->nets_list = new_list;
    }

    return rv;
}

F_NONNULL
static void gdmap_initial_load_all(gdmap_t* gdmap)
{
    gdnsd_assert(gdmap->dclists_pend);
    gdnsd_assert(!gdmap->geoip_list);

    if (gdmap->geoip_path && gdmap_update_geoip(gdmap, gdmap->geoip_path, &gdmap->geoip_list))
        log_fatal("plugin_geoip: map '%s': cannot continue initial load", gdmap->name);

    if (!gdmap->nets_list) {
        gdnsd_assert(gdmap->nets_path);
        if (gdmap_update_nets(gdmap))
            log_fatal("plugin_geoip: map '%s': cannot continue initial load", gdmap->name);
    }

    gdmap_tree_update(gdmap);
}

F_NONNULL
static void gdmap_kick_tree_update(gdmap_t* gdmap, struct ev_loop* loop)
{
    ev_timer* tut = &gdmap->tree_update_timer;
    if (!ev_is_active(tut) && !ev_is_pending(tut))
        log_info("plugin_geoip: map '%s': runtime data changes are pending, waiting for %gs of change quiescence...", gdmap->name, ALL_RELOAD_WAIT);
    else
        log_debug("plugin_geoip: map '%s': Timer for all runtime data re-kicked for %gs due to rapid change...", gdmap->name, ALL_RELOAD_WAIT);
    ev_timer_again(loop, tut);
}

F_NONNULL
static void gdmap_geoip_reload_timer_cb(struct ev_loop* loop, ev_timer* w V_UNUSED, int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_TIMER);

    gdmap_t* gdmap = w->data;
    gdnsd_assert(gdmap);
    gdnsd_assert(gdmap->geoip_path);

    ev_timer_stop(loop, w);

    if (!gdmap_update_geoip(gdmap, gdmap->geoip_path, &gdmap->geoip_list)) {
        gdnsd_assert(gdmap->dclists_pend);
        gdmap_kick_tree_update(gdmap, loop);
    }
}

F_NONNULL
static void gdmap_nets_reload_timer_cb(struct ev_loop* loop, ev_timer* w V_UNUSED, int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_TIMER);

    gdmap_t* gdmap = w->data;
    gdnsd_assert(gdmap);
    gdnsd_assert(gdmap->nets_path);

    ev_timer_stop(loop, w);

    if (!gdmap_update_nets(gdmap)) {
        gdnsd_assert(gdmap->dclists_pend);
        gdmap_kick_tree_update(gdmap, loop);
    }
}

F_NONNULL
static void gdmap_geoip_reload_stat_cb(struct ev_loop* loop, ev_stat* w, int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_STAT);

    gdmap_t* gdmap = w->data;
    gdnsd_assert(gdmap);

    gdnsd_assert(gdmap->geoip_path == w->path);

    if (w->attr.st_nlink) { // file exists
        if (w->attr.st_mtime != w->prev.st_mtime || !w->prev.st_nlink) {
            // Start (or restart) a timer to geoip_reload_timer_cb, so that we
            //  wait for multiple changes to "settle" before re-reading the file
            ev_timer* grt = &gdmap->geoip_reload_timer;
            if (!ev_is_active(grt) && !ev_is_pending(grt))
                log_info("plugin_geoip: map '%s': Change detected in GeoIP database '%s', waiting for %gs of change quiescence...", gdmap->name, w->path, STAT_RELOAD_WAIT);
            else
                log_debug("plugin_geoip: map '%s': Timer for GeoIP database '%s' re-kicked for %gs due to rapid change...", gdmap->name, w->path, STAT_RELOAD_WAIT);
            ev_timer_again(loop, grt);
        }
    } else {
        log_warn("plugin_geoip: map '%s': GeoIP database '%s' disappeared! Internal DB remains unchanged, waiting for it to re-appear...", gdmap->name, w->path);
    }
}

F_NONNULL
static void gdmap_nets_reload_stat_cb(struct ev_loop* loop, ev_stat* w, int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_STAT);

    gdmap_t* gdmap = w->data;
    gdnsd_assert(gdmap);
    gdnsd_assert(gdmap->nets_path);
    gdnsd_assert(gdmap->nets_path == w->path);

    if (w->attr.st_nlink) { // file exists
        if (w->attr.st_mtime != w->prev.st_mtime || !w->prev.st_nlink) {
            ev_timer* nrt = &gdmap->nets_reload_timer;
            if (!ev_is_active(nrt) && !ev_is_pending(nrt))
                log_info("plugin_geoip: map '%s': Change detected in nets file '%s', waiting for %gs of change quiescence...", gdmap->name, w->path, STAT_RELOAD_WAIT);
            else
                log_debug("plugin_geoip: map '%s': Timer for nets file '%s' re-kicked for %gs due to rapid change...", gdmap->name, w->path, STAT_RELOAD_WAIT);
            ev_timer_again(loop, nrt);
        }
    } else {
        log_warn("plugin_geoip: map '%s': nets file '%s' disappeared! Internal DB remains unchanged, waiting for it to re-appear...", gdmap->name, w->path);
    }
}

F_NONNULL
static void gdmap_tree_update_cb(struct ev_loop* loop, ev_timer* w, int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_TIMER);

    gdmap_t* gdmap = w->data;
    gdnsd_assert(gdmap);
    ev_timer_stop(loop, w);
    gdmap_tree_update(gdmap);
}

F_NONNULL
static void gdmap_setup_nets_watcher(gdmap_t* gdmap, struct ev_loop* loop)
{
    gdnsd_assert(gdmap->nets_path);

    ev_timer* nrt = &gdmap->nets_reload_timer;
    ev_init(nrt, gdmap_nets_reload_timer_cb);
    ev_set_priority(nrt, -1);
    nrt->repeat = STAT_RELOAD_WAIT;
    nrt->data = gdmap;

    ev_stat* nsw = &gdmap->nets_stat_watcher;
    ev_stat_init(nsw, gdmap_nets_reload_stat_cb, gdmap->nets_path, 0);
    ev_set_priority(nsw, 0);
    nsw->data = gdmap;
    ev_stat_start(loop, nsw);
}

F_NONNULL
static void gdmap_setup_geoip_watcher(gdmap_t* gdmap, struct ev_loop* loop)
{
    gdnsd_assert(gdmap->geoip_path);

    // the reload stat-quiesce timer
    ev_timer* grt = &gdmap->geoip_reload_timer;
    ev_init(grt, gdmap_geoip_reload_timer_cb);
    ev_set_priority(grt, -1);
    grt->repeat = STAT_RELOAD_WAIT;
    grt->data = gdmap;

    // the reload stat() watcher
    ev_stat* gsw = &gdmap->geoip_stat_watcher;
    ev_stat_init(gsw, gdmap_geoip_reload_stat_cb, gdmap->geoip_path, 0);
    ev_set_priority(gsw, 0);
    gsw->data = gdmap;
    ev_stat_start(loop, gsw);
}

F_NONNULL
static void gdmap_setup_watchers(gdmap_t* gdmap, struct ev_loop* loop)
{
    if (gdmap->geoip_path)
        gdmap_setup_geoip_watcher(gdmap, loop);
    if (gdmap->nets_path)
        gdmap_setup_nets_watcher(gdmap, loop);

    ev_timer* tut = &gdmap->tree_update_timer;
    ev_init(tut, gdmap_tree_update_cb);
    ev_set_priority(tut, -2);
    tut->repeat = ALL_RELOAD_WAIT;
    tut->data = gdmap;
}

F_NONNULL F_PURE
static const char* gdmap_get_name(const gdmap_t* gdmap)
{
    return gdmap->name;
}

F_NONNULL
static const uint8_t* gdmap_lookup(gdmap_t* gdmap, const client_info_t* client, unsigned* scope_mask)
{
    // rcu_thread_online() + rcu_read_lock()
    //   is handled by the iothread and dns lookup code
    //   in the main daemon, in a far outer scope from
    //   this code in runtime terms.

    const unsigned dclist_u = ntree_lookup(
                                  rcu_dereference(gdmap->tree),
                                  client,
                                  scope_mask
                              );
    const uint8_t* dclist_u8 = dclists_get_list(
                                   rcu_dereference(gdmap->dclists),
                                   dclist_u
                               );

    gdnsd_assert(dclist_u8);
    return dclist_u8;
}

/***************************************
 * gdmaps_t and related methods
 **************************************/

struct gdmaps_t {
    pthread_t reload_tid;
    bool reload_thread_spawned;
    unsigned count;
    struct ev_loop* reload_loop;
    gdmap_t* maps;
    monreg_func_t mrf;
};

F_NONNULL
static bool gdmaps_new_iter(const char* key, unsigned klen V_UNUSED, vscf_data_t* val, void* data)
{
    gdmaps_t* gdmaps = data;
    gdmap_init(&gdmaps->maps[gdmaps->count++], key, val, gdmaps->mrf);
    return true;
}

gdmaps_t* gdmaps_new(vscf_data_t* maps_cfg, monreg_func_t mrf)
{
    gdnsd_assert(vscf_is_hash(maps_cfg));

    gdmaps_t* gdmaps = xcalloc(sizeof(*gdmaps));
    gdmaps->mrf = mrf;
    const unsigned num_maps = vscf_hash_get_len(maps_cfg);
    gdmaps->maps = xcalloc_n(num_maps, sizeof(*gdmaps->maps));
    vscf_hash_iterate(maps_cfg, true, gdmaps_new_iter, gdmaps);
    gdnsd_assert(num_maps == gdmaps->count);
    return gdmaps;
}

int gdmaps_name2idx(const gdmaps_t* gdmaps, const char* map_name)
{
    for (unsigned i = 0; i < gdmaps->count; i++)
        if (!strcmp(map_name, gdmap_get_name(&gdmaps->maps[i])))
            return (int)i;
    return -1;
}

const char* gdmaps_idx2name(const gdmaps_t* gdmaps, const unsigned gdmap_idx)
{
    if (gdmap_idx >= gdmaps->count)
        return NULL;
    return gdmap_get_name(&gdmaps->maps[gdmap_idx]);
}

unsigned gdmaps_get_dc_count(const gdmaps_t* gdmaps, const unsigned gdmap_idx)
{
    gdnsd_assert(gdmap_idx < gdmaps->count);
    return dcinfo_get_count(&gdmaps->maps[gdmap_idx].dcinfo);
}

unsigned gdmaps_dcname2num(const gdmaps_t* gdmaps, const unsigned gdmap_idx, const char* dcname)
{
    gdnsd_assert(gdmap_idx < gdmaps->count);
    return dcinfo_name2num(&gdmaps->maps[gdmap_idx].dcinfo, dcname);
}

static const char* gdmaps_dcnum2name(const gdmaps_t* gdmaps, const unsigned gdmap_idx, const unsigned dcnum)
{
    gdnsd_assert(gdmap_idx < gdmaps->count);
    return dcinfo_num2name(&gdmaps->maps[gdmap_idx].dcinfo, dcnum);
}

unsigned gdmaps_map_mon_idx(const gdmaps_t* gdmaps, const unsigned gdmap_idx, const unsigned dcnum)
{
    gdnsd_assert(gdmap_idx < gdmaps->count);
    return dcinfo_map_mon_idx(&gdmaps->maps[gdmap_idx].dcinfo, dcnum);
}

// mostly for debugging / error output
// Note that this doesn't participate in liburcu stuff, and therefore could crash if it were
//   running concurrently with an update swap.  It's only used from the testsuite and gdmaps_geoip_test
//   stuff, though, so that's not important.
static const char dclist_nodc[] = "<INVALID>";
const char* gdmaps_logf_dclist(const gdmaps_t* gdmaps, const unsigned gdmap_idx, const uint8_t* dclist)
{
    gdnsd_assert(gdmap_idx < gdmaps->count);

    // Save original...
    const uint8_t* dclist_orig = dclist;

    // Size the output
    unsigned output_len = 0;
    unsigned dcnum;
    bool first = true;
    while ((dcnum = *dclist++)) {
        const char* dcname = gdmaps_dcnum2name(gdmaps, gdmap_idx, dcnum);
        output_len += strlen(dcname ? dcname : dclist_nodc);
        if (!first)
            output_len += 2;
        first = false;
    }

    // Allocate buffer
    char* buf = gdnsd_fmtbuf_alloc(output_len + 1);
    char* bptr = buf;

    // Actually write the output
    first = true;
    dclist = dclist_orig;
    while ((dcnum = *dclist++)) {
        if (!first) {
            *bptr++ = ',';
            *bptr++ = ' ';
        }
        first = false;
        const char* dcname = gdmaps_dcnum2name(gdmaps, gdmap_idx, dcnum);
        if (!dcname)
            dcname = dclist_nodc;
        const size_t len = strlen(dcname);
        memcpy(bptr, dcname, len);
        bptr += len;
    }
    *bptr = '\0';

    return buf;
}

const uint8_t* gdmaps_lookup(const gdmaps_t* gdmaps, const unsigned gdmap_idx, const client_info_t* client, unsigned* scope_mask)
{
    gdnsd_assert(gdmap_idx < gdmaps->count);
    return gdmap_lookup(&gdmaps->maps[gdmap_idx], client, scope_mask);
}

void gdmaps_load_databases(gdmaps_t* gdmaps)
{
    for (unsigned i = 0; i < gdmaps->count; i++)
        gdmap_initial_load_all(&gdmaps->maps[i]);
}

F_NONNULL
static void* gdmaps_reload_thread(void* arg)
{
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    gdnsd_thread_setname("gdnsd-geoip-db");
    gdnsd_thread_reduce_prio();

    gdmaps_t* gdmaps = arg;
    gdnsd_assert(gdmaps);

    gdmaps->reload_loop = ev_loop_new(EVFLAG_AUTO);
    for (unsigned i = 0; i < gdmaps->count; i++)
        gdmap_setup_watchers(&gdmaps->maps[i], gdmaps->reload_loop);

    ev_run(gdmaps->reload_loop, 0);

    return NULL;
}

void gdmaps_setup_watchers(gdmaps_t* gdmaps)
{
    pthread_attr_t attribs;
    pthread_attr_init(&attribs);
    pthread_attr_setdetachstate(&attribs, PTHREAD_CREATE_DETACHED);
    pthread_attr_setscope(&attribs, PTHREAD_SCOPE_SYSTEM);

    sigset_t sigmask_all;
    sigfillset(&sigmask_all);
    sigset_t sigmask_prev;
    sigemptyset(&sigmask_prev);
    if (pthread_sigmask(SIG_SETMASK, &sigmask_all, &sigmask_prev))
        log_fatal("pthread_sigmask() failed");

    int pthread_err;
    if ((pthread_err = pthread_create(&gdmaps->reload_tid, &attribs, gdmaps_reload_thread, gdmaps)))
        log_fatal("plugin_geoip: failed to create GeoIP reload thread: %s", logf_strerror(pthread_err));

    gdmaps->reload_thread_spawned = true;

    if (pthread_sigmask(SIG_SETMASK, &sigmask_prev, NULL))
        log_fatal("pthread_sigmask() failed");
    pthread_attr_destroy(&attribs);
}
