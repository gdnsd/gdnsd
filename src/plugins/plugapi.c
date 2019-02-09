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
#include "plugapi.h"

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/net.h>
#include <gdnsd/misc.h>

#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "plugins.h"

#define NUM_PLUGINS 12

static plugin_t* plugins[NUM_PLUGINS] = {
    &plugin_geoip_funcs,
    &plugin_metafo_funcs,
    &plugin_http_status_funcs,
    &plugin_multifo_funcs,
    &plugin_null_funcs,
    &plugin_reflect_funcs,
    &plugin_simplefo_funcs,
    &plugin_static_funcs,
    &plugin_tcp_connect_funcs,
    &plugin_weighted_funcs,
    &plugin_extfile_funcs,
    &plugin_extmon_funcs,
};

// The default (minimum) values here amount to 240 bytes of address
//   storage (12*4+12*16), which is less than the minimum allocation
//   of 256 to store a CNAME, therefore there's no savings trying to
//   go any smaller.
static unsigned addrlimit_v4 = 12U;
static unsigned addrlimit_v6 = 12U;
static unsigned v6_offset = 12U * 4U;

unsigned gdnsd_result_get_v6_offset(void)
{
    return v6_offset;
}

unsigned gdnsd_result_get_alloc(void)
{
    unsigned storage = (addrlimit_v4 * 4U) + (addrlimit_v6 * 16U);
    if (storage < 256U)
        storage = 256U; // true minimum set by CNAME storage
    return sizeof(dyn_result_t) + storage;
}

size_t gdnsd_result_get_max_response(void)
{
    return (addrlimit_v4 * (12U + 4U)) + (addrlimit_v6 * (12U + 16U));
}

void gdnsd_dyn_addr_max(unsigned v4, unsigned v6)
{
    // 360+360 as limits here ensures that a completely maxed-out DYNA response
    // still fits just under 16K in the worst-case scenario.  A zonefile could
    // still be rejected, but only if it uses a maximally-configured DYNA
    // alongside other data which combine to bring it past the 16K mark.
    if (v4 > 360U)
        log_fatal("gdnsd cannot cope with plugin configurations which add >360 IPv4 addresses to a single result!");
    if (v6 > 360U)
        log_fatal("gdnsd cannot cope with plugin configurations which add >360 IPv6 addresses to a single result!");

    if (v4 > addrlimit_v4) {
        addrlimit_v4 = v4;
        v6_offset = v4 * 4U;
    }
    if (v6 > addrlimit_v6)
        addrlimit_v6 = v6;
}

void gdnsd_result_add_anysin(dyn_result_t* result, const gdnsd_anysin_t* sa)
{
    gdnsd_assert(!result->is_cname);
    if (sa->sa.sa_family == AF_INET6) {
        gdnsd_assert(result->count_v6 < addrlimit_v6);
        memcpy(&result->storage[v6_offset + (result->count_v6++ * 16U)], sa->sin6.sin6_addr.s6_addr, 16);
    } else {
        gdnsd_assert(sa->sa.sa_family == AF_INET);
        gdnsd_assert(result->count_v4 < addrlimit_v4);
        result->v4[result->count_v4++] = sa->sin4.sin_addr.s_addr;
    }
}

void gdnsd_result_add_cname(dyn_result_t* result, const uint8_t* dname)
{
    gdnsd_assert(dname_status(dname) == DNAME_VALID);
    gdnsd_assert(!result->is_cname);
    gdnsd_assert(!result->count_v4);
    gdnsd_assert(!result->count_v6);

    result->is_cname = true;
    dname_copy(result->storage, dname);
}

void gdnsd_result_wipe(dyn_result_t* result)
{
    result->is_cname = false;
    result->count_v4 = 0;
    result->count_v6 = 0;
}

void gdnsd_result_wipe_v4(dyn_result_t* result)
{
    result->count_v4 = 0;
}

void gdnsd_result_wipe_v6(dyn_result_t* result)
{
    result->count_v6 = 0;
}

void gdnsd_result_add_scope_mask(dyn_result_t* result, unsigned scope)
{
    if (scope > result->edns_scope_mask)
        result->edns_scope_mask = scope;
}

void gdnsd_result_reset_scope_mask(dyn_result_t* result)
{
    result->edns_scope_mask = 0;
}

plugin_t* gdnsd_plugin_find(const char* pname)
{
    for (unsigned i = 0; i < NUM_PLUGINS; i++) {
        plugin_t* p = plugins[i];
        if (!strcmp(pname, p->name)) {
            if (!p->used)
                p->used = true;
            return p;
        }
    }

    log_fatal("No such plugin '%s'", pname);
}

// The action iterators...

void gdnsd_plugins_configure_all(const unsigned num_threads)
{
    for (unsigned i = 0; i < NUM_PLUGINS; i++) {
        if (plugins[i]->used && plugins[i]->load_config && !plugins[i]->config_loaded) {
            plugins[i]->load_config(NULL, num_threads);
            plugins[i]->config_loaded = true;
        }
    }
}

void gdnsd_plugins_action_init_monitors(struct ev_loop* mon_loop)
{
    for (unsigned i = 0; i < NUM_PLUGINS; i++)
        if (plugins[i]->used && plugins[i]->init_monitors)
            plugins[i]->init_monitors(mon_loop);
}

void gdnsd_plugins_action_start_monitors(struct ev_loop* mon_loop)
{
    for (unsigned i = 0; i < NUM_PLUGINS; i++)
        if (plugins[i]->used && plugins[i]->start_monitors)
            plugins[i]->start_monitors(mon_loop);
}

void gdnsd_plugins_action_pre_run(void)
{
    for (unsigned i = 0; i < NUM_PLUGINS; i++)
        if (plugins[i]->used && plugins[i]->pre_run)
            plugins[i]->pre_run();
}

void gdnsd_plugins_action_iothread_init(void)
{
    for (unsigned i = 0; i < NUM_PLUGINS; i++)
        if (plugins[i]->used && plugins[i]->iothread_init)
            plugins[i]->iothread_init();
}

void gdnsd_plugins_action_iothread_cleanup(void)
{
    for (unsigned i = 0; i < NUM_PLUGINS; i++)
        if (plugins[i]->used && plugins[i]->iothread_cleanup)
            plugins[i]->iothread_cleanup();
}
