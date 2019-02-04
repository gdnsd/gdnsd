/* Copyright © 2014 Brandon L Black <blblack@gmail.com>
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

// Each service_type for extfile names a vscf file to monitor, containing:
//   192.168.1.1 => UP
//   foo.example.net. => DOWN/1000
// The array is processed in-order.  If an name is affected more than once
//   (via duplicate "name" keys), the last entry wins.
// The /TTLs are optional, and ignored in one of the two modes (below).
// When a plugin uses a service_type here, the name is looked up in the
//   the data loaded from the file to generate the result.
// In "direct" mode, the state/TTL in the file is copied directly as a final
//   state and TTL for mon-plugin/status-output usage, and updates are loaded
//   as soon as reasonably possible
// In "monitor" mode, any TTLs in the file are ignored, the file is strictly only
//   reloaded on specified monitoring intervals, and the UP/DOWN data from the
//   file feeds into normal anti-flap/TTL calculations, as we do with standard
//   real monitors like http_status.

#include <config.h>

#include <gdnsd/compiler.h>
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/vscf.h>
#include "mon.h"
#include "plugapi.h"
#include <gdnsd/paths.h>
#include "plugins.h"

#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <ev.h>

typedef struct {
    const char* name;
    unsigned midx; // mon idx within svc->mons[]
    unsigned sidx; // sttl idx for monitor core stuff
} extf_mon_t;

typedef struct {
    const char* name;
    const char* path;
    extf_mon_t* mons;
    ev_stat file_watcher; // only used in "direct" case
    ev_timer time_watcher; // used in both cases, differently
    bool direct;
    unsigned timeout;
    unsigned interval;
    unsigned num_mons;
    gdnsd_sttl_t def_sttl;
} extf_svc_t;

static unsigned num_svcs = 0;
static extf_svc_t* service_types = NULL;
static bool testsuite_nodelay = false;

#define SVC_OPT_UINT(_hash, _typnam, _nam, _loc, _min, _max) \
    do { \
        vscf_data_t* _data = vscf_hash_get_data_byconstkey(_hash, #_nam, true); \
        if (_data) { \
            unsigned long _val; \
            if (!vscf_is_simple(_data) \
            || !vscf_simple_get_as_ulong(_data, &_val)) \
                log_fatal("plugin_extfile: Service type '%s': option '%s': Value must be a positive integer", _typnam, #_nam); \
            if (_val < _min || _val > _max) \
                log_fatal("plugin_extfile: Service type '%s': option '%s': Value out of range (%lu, %lu)", _typnam, #_nam, _min, _max); \
            _loc = (unsigned) _val; \
        } \
    } while (0)

#define SVC_OPT_BOOL(_hash, _typnam, _nam, _loc) \
    do { \
        vscf_data_t* _data = vscf_hash_get_data_byconstkey(_hash, #_nam, true); \
        if (_data) { \
            if (!vscf_is_simple(_data) \
            || !vscf_simple_get_as_bool(_data, &_loc)) \
                log_fatal("plugin_extfile: Service type '%s': option %s: Value must be 'true' or 'false'", #_typnam, #_nam); \
        } \
    } while (0)

static void plugin_extfile_add_svctype(const char* name, vscf_data_t* svc_cfg, const unsigned interval, const unsigned timeout)
{
    service_types = xrealloc_n(service_types, num_svcs + 1, sizeof(*service_types));
    extf_svc_t* svc = &service_types[num_svcs++];
    memset(svc, 0, sizeof(*svc));

    svc->name = xstrdup(name);
    svc->timeout = timeout;
    svc->interval = interval;

    vscf_data_t* path_cfg = vscf_hash_get_data_byconstkey(svc_cfg, "file", true);
    if (!path_cfg || !vscf_is_simple(path_cfg))
        log_fatal("plugin_extfile: service_type '%s': the 'file' option is required and must be a string filename", name);
    svc->path = gdnsd_resolve_path_state(vscf_simple_get_data(path_cfg), "extfile");

    svc->direct = false;
    svc->def_sttl = GDNSD_STTL_TTL_MAX;
    SVC_OPT_BOOL(svc_cfg, name, direct, svc->direct);
    SVC_OPT_UINT(svc_cfg, name, def_ttl, svc->def_sttl, 1LU, (unsigned long)GDNSD_STTL_TTL_MAX);
    bool def_down = false;
    SVC_OPT_BOOL(svc_cfg, name, def_down, def_down);
    if (def_down)
        svc->def_sttl |= GDNSD_STTL_DOWN;

    svc->num_mons = 0;
    svc->mons = NULL;
}

static void plugin_extfile_add_mon_cname(const char* desc V_UNUSED, const char* svc_name, const char* cname, const unsigned idx)
{
    extf_svc_t* svc = NULL;
    for (unsigned i = 0; i < num_svcs; i++) {
        if (!strcmp(svc_name, service_types[i].name)) {
            svc = &service_types[i];
            break;
        }
    }

    gdnsd_assert(svc);

    svc->mons = xrealloc_n(svc->mons, svc->num_mons + 1, sizeof(*svc->mons));
    extf_mon_t* mon = &svc->mons[svc->num_mons];
    mon->name = xstrdup(cname);
    mon->sidx = idx;
    mon->midx = svc->num_mons++;
}

static void plugin_extfile_add_mon_addr(const char* desc, const char* svc_name, const char* cname, const gdnsd_anysin_t* addr V_UNUSED, const unsigned idx)
{
    plugin_extfile_add_mon_cname(desc, svc_name, cname, idx);
}

F_NONNULL
static int moncmp(const void* x, const void* y)
{
    const extf_mon_t* xm = x;
    const extf_mon_t* ym = y;
    return strcmp(xm->name, ym->name);
}

F_NONNULLX(1, 2, 3)
static bool process_entry(const extf_svc_t* svc, const char* matchme, vscf_data_t* val, gdnsd_sttl_t* results)
{
    bool success = false;
    if (!vscf_is_simple(val)) {
        log_err("plugin_extfile: Service type '%s': value for '%s' in file '%s' ignored, must be a simple string!", svc->name, matchme, svc->path);
    } else {
        gdnsd_sttl_t result;
        const unsigned def_ttl = svc->def_sttl & GDNSD_STTL_TTL_MASK;
        if (gdnsd_mon_parse_sttl(vscf_simple_get_data(val), &result, def_ttl)) {
            log_err("plugin_extfile: Service type '%s': value for '%s' in file '%s' ignored, must be of the form STATE[/TTL] (where STATE is 'UP' or 'DOWN', and the optional TTL is an unsigned integer in the range 0 - %u)", svc->name, matchme, svc->path, GDNSD_STTL_TTL_MAX);
        } else {
            if (!svc->direct && ((result & GDNSD_STTL_TTL_MASK) != def_ttl))
                log_warn("plugin_extfile: Service type '%s': TTL value for '%s' in file '%s' ignored in 'monitor' mode", svc->name, matchme, svc->path);
            const extf_mon_t findme = { matchme, 0, 0 };
            const extf_mon_t* found = bsearch(&findme, svc->mons, svc->num_mons, sizeof(findme), moncmp);
            if (found) {
                gdnsd_assert(results);
                results[found->midx] = result;
            } else {
                log_warn("plugin_extfile: Service type '%s': entry '%s' in file '%s' ignored, did not match any configured resource!", svc->name, matchme, svc->path);
            }
            success = true;
        }
    }

    return success;
}

F_NONNULL
static void process_file(const extf_svc_t* svc)
{
    vscf_data_t* raw = vscf_scan_filename(svc->path);
    if (!raw) {
        log_err("plugin_extfile: Service type '%s': loading file '%s' failed", svc->name, svc->path);
        return;
    } else {
        if (!vscf_is_hash(raw)) {
            log_err("plugin_extfile: Service type '%s': top level of file '%s' must be a hash", svc->name, svc->path);
            return;
        }
    }

    gdnsd_sttl_t* results = NULL;
    if (svc->num_mons)
        results = xmalloc_n(svc->num_mons, sizeof(*results));

    // FORCED-bit below is temporary (within this function) as a flag
    //   to identify those entries which were not affected by file input.
    // It is cleared before copying the results out elsewhere.
    for (unsigned i = 0; i < svc->num_mons; i++)
        results[i] = svc->def_sttl | GDNSD_STTL_FORCED;

    const unsigned num_raw = vscf_hash_get_len(raw);
    bool success = true;
    for (unsigned i = 0; i < num_raw; i++) {
        const char* matchme = vscf_hash_get_key_byindex(raw, i, NULL);
        vscf_data_t* val = vscf_hash_get_data_byindex(raw, i);
        if (!process_entry(svc, matchme, val, results)) {
            success = false;
            break;
        }
    }

    vscf_destroy(raw);

    if (success) {
        for (unsigned i = 0; i < svc->num_mons; i++) {
            if (results[i] & GDNSD_STTL_FORCED) {
                log_warn("plugin_extfile: Service type '%s': '%s' was defaulted! (not specified by input file)", svc->name, svc->mons[i].name);
                results[i] &= ~GDNSD_STTL_FORCED;
                gdnsd_assert(results[i] == svc->def_sttl);
            }
        }
        if (svc->direct)
            for (unsigned i = 0; i < svc->num_mons; i++)
                gdnsd_mon_sttl_updater(svc->mons[i].sidx, results[i]);
        else
            for (unsigned i = 0; i < svc->num_mons; i++)
                gdnsd_mon_state_updater(svc->mons[i].sidx, !(results[i] & GDNSD_STTL_DOWN));
        log_debug("plugin_extfile: Service type '%s': loaded new data from file '%s'", svc->name, svc->path);
    } else {
        log_err("plugin_extfile: Service type '%s': file load failed, no updates applied", svc->name);
    }

    if (results)
        free(results);
}

F_NONNULL
static void timer_cb(struct ev_loop* loop, ev_timer* w, int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_TIMER);

    extf_svc_t* svc = w->data;
    gdnsd_assert(svc);

    if (svc->direct)
        ev_timer_stop(loop, w);
    process_file(svc);
}

F_NONNULL
static void file_cb(struct ev_loop* loop, ev_stat* w, int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_STAT);
    extf_svc_t* svc = w->data;
    gdnsd_assert(svc);
    gdnsd_assert(svc->direct);

    ev_timer* tw = &svc->time_watcher;
    if (testsuite_nodelay)
        timer_cb(loop, tw, EV_TIMER);
    else
        ev_timer_again(loop, tw);
}

F_NONNULL
static void start_svc(extf_svc_t* svc, struct ev_loop* mon_loop)
{
    const double delay = testsuite_nodelay ? 0.01 : svc->interval;

    ev_timer* tw = &svc->time_watcher;
    if (svc->direct) {
        // in the direct case, interval is the ev_stat time hint, and all ev_stat
        //   hits (re-)kick a 1.02s stat()-settling timer, which processes the file
        //   when it expires.
        ev_timer_init(tw, timer_cb, 0.0, 1.02);
        tw->data = svc;
        ev_stat* fw = &svc->file_watcher;
        ev_stat_init(fw, file_cb, svc->path, delay);
        fw->data = svc;
        ev_stat_start(mon_loop, fw);
    } else {
        // in the monitor case, interval is a fixed repeating timer that processes
        //   the file on every expiry.
        ev_timer_init(tw, timer_cb, delay, delay);
        tw->data = svc;
        ev_timer_start(mon_loop, tw);
    }
}

static void plugin_extfile_start_monitors(struct ev_loop* mon_loop)
{
    for (unsigned i = 0; i < num_svcs; i++)
        start_svc(&service_types[i], mon_loop);
}

static void plugin_extfile_init_monitors(struct ev_loop* mon_loop V_UNUSED)
{
    if (getenv("GDNSD_TESTSUITE_NODELAY"))
        testsuite_nodelay = true;

    for (unsigned i = 0; i < num_svcs; i++) {
        extf_svc_t* svc = &service_types[i];
        // qsort() sets up for the bsearch() in process_file at runtime
        // aftwerwards, the midx values must be rewritten to the new order
        qsort(svc->mons, svc->num_mons, sizeof(*svc->mons), moncmp);
        for (unsigned j = 0; j < svc->num_mons; j++)
            svc->mons[j].midx = j;
        process_file(svc);
    }
}

plugin_t plugin_extfile_funcs = {
    .name = "extfile",
    .config_loaded = false,
    .used = false,
    .load_config = NULL,
    .map_res = NULL,
    .pre_run = NULL,
    .iothread_init = NULL,
    .iothread_cleanup = NULL,
    .resolve = NULL,
    .add_svctype = plugin_extfile_add_svctype,
    .add_mon_addr = plugin_extfile_add_mon_addr,
    .add_mon_cname = plugin_extfile_add_mon_cname,
    .init_monitors = plugin_extfile_init_monitors,
    .start_monitors = plugin_extfile_start_monitors,
};
