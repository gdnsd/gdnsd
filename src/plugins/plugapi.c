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
#include "dnswire.h"

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/net.h>
#include <gdnsd/misc.h>

#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <arpa/inet.h>

#include "plugins.h"

#define NUM_PLUGINS 12

static struct plugin* plugins[NUM_PLUGINS] = {
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

static unsigned addrlimit_v4 = 1U;
static unsigned addrlimit_v6 = 1U;

unsigned gdnsd_result_get_alloc(void)
{
    const unsigned storage_v4 = addrlimit_v4 * 16U;
    const unsigned storage_v6 = addrlimit_v6 * 28U;
    const unsigned storage_cn = 12U + 255U;
    unsigned biggest = storage_v4 > storage_v6 ? storage_v4 : storage_v6;
    biggest = storage_cn > biggest ? storage_cn : biggest;
    return sizeof(struct dyn_result) + biggest;
}

void gdnsd_dyn_addr_max(unsigned v4, unsigned v6)
{
    // 255 ensures even v6 can't even come close to exceeding 16K response packet size
    if (v4 > 255U)
        log_fatal("gdnsd cannot cope with plugin configurations which add >255 IPv4 addresses to a single result!");
    if (v6 > 255U)
        log_fatal("gdnsd cannot cope with plugin configurations which add >255 IPv6 addresses to a single result!");

    if (v4 > addrlimit_v4)
        addrlimit_v4 = v4;
    if (v6 > addrlimit_v6)
        addrlimit_v6 = v6;
}

void gdnsd_result_add_anysin(struct dyn_result* result, const struct anysin* sa)
{
    unsigned rrfixed;
    unsigned this_rr_rdlen;
    if (sa->sa.sa_family == AF_INET6) {
        rrfixed = DNS_RRFIXED_AAAA;
        this_rr_rdlen = 16U;
    } else {
        gdnsd_assert(sa->sa.sa_family == AF_INET);
        rrfixed = DNS_RRFIXED_A;
        this_rr_rdlen = 4U;
    }

    uint8_t* buf = &result->storage[result->storage_len];
    unsigned offs = 0;
    // Note this doesn't efficiently handle the root case, don't care...
    gdnsd_put_una16(htons(0xC00C), &buf[offs]);
    offs += 2U;
    gdnsd_put_una32(rrfixed, &buf[offs]);
    offs += 4U;
    // Note no TTL yet.  Filled in at runtime
    gdnsd_put_una32(0, &buf[offs]);
    offs += 4U;
    gdnsd_put_una16(htons(this_rr_rdlen), &buf[offs]);
    offs += 2U;

    if (sa->sa.sa_family == AF_INET6) {
        gdnsd_assert(result->count < addrlimit_v6);
        memcpy(&buf[offs], sa->sin6.sin6_addr.s6_addr, 16U);
        offs += 16U;
    } else {
        gdnsd_assert(sa->sa.sa_family == AF_INET);
        gdnsd_assert(result->count < addrlimit_v4);
        memcpy(&buf[offs], &sa->sin4.sin_addr.s_addr, 4U);
        offs += 4U;
    }

    result->storage_len += offs;
    result->count++;
}

void gdnsd_result_add_cname(struct dyn_result* result, const uint8_t* dname)
{
    gdnsd_assert(dname_get_status(dname) == DNAME_VALID);
    gdnsd_assert(!result->count);
    gdnsd_assert(!result->storage_len);

    uint8_t* buf = result->storage;
    const unsigned this_rr_rdlen = dname[0];
    unsigned offs = 0;
    gdnsd_put_una16(htons(0xC00C), &buf[offs]);
    offs += 2U;
    gdnsd_put_una32(DNS_RRFIXED_CNAME, &buf[offs]);
    offs += 4U;
    // Note no TTL yet.  Filled in at runtime
    gdnsd_put_una32(0, &buf[offs]);
    offs += 4U;
    gdnsd_put_una16(htons(this_rr_rdlen), &buf[offs]);
    offs += 2U;
    memcpy(&buf[offs], &dname[1], dname[0]);
    result->storage_len = 12U + dname[0];
    result->count = 1U;
}

void gdnsd_result_wipe(struct dyn_result* result)
{
    result->count = 0;
    result->storage_len = 0;
}

void gdnsd_result_add_scope_mask(struct dyn_result* result, unsigned scope)
{
    if (scope > result->edns_scope_mask)
        result->edns_scope_mask = scope;
}

void gdnsd_result_reset_scope_mask(struct dyn_result* result)
{
    result->edns_scope_mask = 0;
}

struct plugin* gdnsd_plugin_find(const char* pname)
{
    for (unsigned i = 0; i < NUM_PLUGINS; i++) {
        struct plugin* p = plugins[i];
        if (!strcmp(pname, p->name)) {
            if (!p->used)
                p->used = true;
            return p;
        }
    }

    log_fatal("No such plugin '%s'", pname);
}

// The action iterators...

void gdnsd_plugins_configure_all(void)
{
    for (unsigned i = 0; i < NUM_PLUGINS; i++) {
        if (plugins[i]->used && plugins[i]->load_config && !plugins[i]->config_loaded) {
            plugins[i]->load_config(NULL);
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
