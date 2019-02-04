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

#include <gdnsd/compiler.h>
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/vscf.h>
#include "mon.h"
#include "plugapi.h"
#include "plugins.h"

#include <string.h>
#include <inttypes.h>

static void plugin_null_load_config(vscf_data_t* config V_UNUSED, const unsigned num_threads V_UNUSED)
{
    gdnsd_dyn_addr_max(1, 1); // null only ever returns a single IP from each family
}

static int plugin_null_map_res(const char* resname V_UNUSED, const uint8_t* zone_name V_UNUSED)
{
    return 0;
}

static gdnsd_sttl_t plugin_null_resolve(unsigned resnum V_UNUSED, const client_info_t* cinfo V_UNUSED, dyn_result_t* result)
{
    gdnsd_anysin_t tmpsin;
    gdnsd_anysin_fromstr("0.0.0.0", 0, &tmpsin);
    gdnsd_result_add_anysin(result, &tmpsin);
    gdnsd_anysin_fromstr("[::]", 0, &tmpsin);
    gdnsd_result_add_anysin(result, &tmpsin);

    return GDNSD_STTL_TTL_MAX;
}

// Obviously, we could implement "null" monitoring with simpler code,
//  but this exercises some API bits, so it's useful for testing

typedef struct {
    const char* name;
    unsigned interval;
} null_svc_t;

typedef struct {
    unsigned idx;
    null_svc_t* svc;
    ev_timer interval_watcher;
} null_mon_t;

static unsigned num_svcs = 0;
static unsigned num_mons = 0;
static null_svc_t** null_svcs = NULL;
static null_mon_t** null_mons = NULL;

F_NONNULL
static void null_interval_cb(struct ev_loop* loop V_UNUSED, struct ev_timer* t, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_TIMER);

    null_mon_t* mon = t->data;
    gdnsd_assert(mon);
    gdnsd_mon_state_updater(mon->idx, false);
}

static void plugin_null_add_svctype(const char* name, vscf_data_t* svc_cfg V_UNUSED, const unsigned interval, const unsigned timeout V_UNUSED)
{
    null_svc_t* this_svc = xmalloc(sizeof(*this_svc));
    null_svcs = xrealloc_n(null_svcs, num_svcs + 1, sizeof(*null_svcs));
    null_svcs[num_svcs] = this_svc;
    num_svcs++;
    this_svc->name = xstrdup(name);
    this_svc->interval = interval;
}

static void add_mon_any(const char* svc_name, const unsigned idx)
{
    gdnsd_assert(svc_name);

    null_svc_t* this_svc = NULL;

    for (unsigned i = 0; i < num_svcs; i++) {
        if (!strcmp(svc_name, null_svcs[i]->name)) {
            this_svc = null_svcs[i];
            break;
        }
    }

    gdnsd_assert(this_svc);
    null_mon_t* this_mon = xmalloc(sizeof(*this_mon));
    null_mons = xrealloc_n(null_mons, num_mons + 1, sizeof(*null_mons));
    null_mons[num_mons] = this_mon;
    num_mons++;
    this_mon->svc = this_svc;
    this_mon->idx = idx;
    ev_timer* ival_watcher = &this_mon->interval_watcher;
    ev_timer_init(ival_watcher, null_interval_cb, 0, 0);
    ival_watcher->data = this_mon;
}

static void plugin_null_add_mon_addr(const char* desc V_UNUSED, const char* svc_name, const char* cname V_UNUSED, const gdnsd_anysin_t* addr V_UNUSED, const unsigned idx)
{
    add_mon_any(svc_name, idx);
}

static void plugin_null_add_mon_cname(const char* desc V_UNUSED, const char* svc_name, const char* cname V_UNUSED, const unsigned idx)
{
    add_mon_any(svc_name, idx);
}

static void plugin_null_init_monitors(struct ev_loop* mon_loop)
{
    for (unsigned i = 0; i < num_mons; i++) {
        ev_timer* ival_watcher = &null_mons[i]->interval_watcher;
        ev_timer_set(ival_watcher, 0, 0);
        ev_timer_start(mon_loop, ival_watcher);
    }
}

static void plugin_null_start_monitors(struct ev_loop* mon_loop)
{
    for (unsigned i = 0; i < num_mons; i++) {
        null_mon_t* mon = null_mons[i];
        const unsigned ival = mon->svc->interval;
        const double stagger = (((double)i) / ((double)num_mons)) * ((double)ival);
        ev_timer* ival_watcher = &mon->interval_watcher;
        ev_timer_set(ival_watcher, stagger, ival);
        ev_timer_start(mon_loop, ival_watcher);
    }
}

plugin_t plugin_null_funcs = {
    .name = "null",
    .config_loaded = false,
    .used = false,
    .load_config = plugin_null_load_config,
    .map_res = plugin_null_map_res,
    .pre_run = NULL,
    .iothread_init = NULL,
    .iothread_cleanup = NULL,
    .resolve = plugin_null_resolve,
    .add_svctype = plugin_null_add_svctype,
    .add_mon_addr = plugin_null_add_mon_addr,
    .add_mon_cname = plugin_null_add_mon_cname,
    .init_monitors = plugin_null_init_monitors,
    .start_monitors = plugin_null_start_monitors,
};
