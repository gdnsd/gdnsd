/* Copyright © 2012 Brandon L Black <blblack@gmail.com> and Jay Reitz <jreitz@gmail.com>
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

#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

typedef struct {
    const char* name;
    bool is_addr;
    union {
        gdnsd_anysin_t addr;
        uint8_t* dname;
    };
} static_resource_t;

static static_resource_t* resources = NULL;
static unsigned num_resources = 0;

static bool config_res(const char* resname, unsigned resname_len V_UNUSED, vscf_data_t* addr, void* data)
{
    unsigned* residx_ptr = data;

    if (vscf_get_type(addr) != VSCF_SIMPLE_T)
        log_fatal("plugin_static: resource %s: must be an IP address or a domainname in string form", resname);

    unsigned res = *residx_ptr;
    (*residx_ptr)++;
    resources[res].name = xstrdup(resname);

    const char* addr_txt = vscf_simple_get_data(addr);
    if (gdnsd_anysin_fromstr(addr_txt, 0, &resources[res].addr)) {
        // Address-parsing failed, treat as domainname for DYNC
        resources[res].is_addr = false;
        resources[res].dname = xmalloc(256);
        dname_status_t status = vscf_simple_get_as_dname(addr, resources[res].dname);
        if (status == DNAME_INVALID)
            log_fatal("plugin_static: resource %s: must be an IPv4 address or a domainname in string form", resname);
        if (status == DNAME_PARTIAL)
            log_fatal("plugin_static: resource %s: '%s' must be fully qualified (end in dot)", resname, addr_txt);
        gdnsd_assert(status == DNAME_VALID);
        resources[res].dname = dname_trim(resources[res].dname);
    } else {
        resources[res].is_addr = true;
    }

    return true;
}

static void plugin_static_load_config(vscf_data_t* config, const unsigned num_threads V_UNUSED)
{
    if (!config)
        log_fatal("static plugin requires a 'plugins' configuration stanza");
    gdnsd_assert(vscf_get_type(config) == VSCF_HASH_T);

    num_resources = vscf_hash_get_len(config);
    if (num_resources) {
        resources = xmalloc_n(num_resources, sizeof(*resources));
        unsigned residx = 0;
        vscf_hash_iterate(config, false, config_res, &residx);
        gdnsd_dyn_addr_max(1, 1); // static only ever returns a single IP
    }
}

static int plugin_static_map_res(const char* resname, const uint8_t* zone_name)
{
    if (resname) {
        for (unsigned i = 0; i < num_resources; i++) {
            if (!strcmp(resname, resources[i].name)) {
                if (resources[i].is_addr)
                    return (int)i;
                if (!zone_name)
                    map_res_err("plugin_static: CNAME resource '%s' cannot be used for a DYNA record", resources[i].name);
                uint8_t* dname = resources[i].dname;
                if (dname_isinzone(zone_name, dname))
                    map_res_err("plugin_static: Resource '%s' CNAME value '%s' cannot be used within zone '%s'", resources[i].name, logf_dname(dname), logf_dname(zone_name));
                return (int)i;
            }
        }
        map_res_err("plugin_static: Unknown resource '%s'", resname);
    }

    map_res_err("plugin_static: resource name required");
}

static gdnsd_sttl_t plugin_static_resolve(unsigned resnum V_UNUSED, const client_info_t* cinfo V_UNUSED, dyn_result_t* result)
{
    if (resources[resnum].is_addr)
        gdnsd_result_add_anysin(result, &resources[resnum].addr);
    else
        gdnsd_result_add_cname(result, resources[resnum].dname);

    return GDNSD_STTL_TTL_MAX;
}

// plugin_static as a monitoring plugin:

typedef struct {
    const char* name;
    gdnsd_sttl_t static_sttl;
} static_svc_t;

typedef struct {
    static_svc_t* svc;
    unsigned idx;
} static_mon_t;

static unsigned num_svcs = 0;
static unsigned num_mons = 0;
static static_svc_t** static_svcs = NULL;
static static_mon_t** static_mons = NULL;

static void plugin_static_add_svctype(const char* name, vscf_data_t* svc_cfg, const unsigned interval V_UNUSED, const unsigned timeout V_UNUSED)
{
    static_svc_t* this_svc = xmalloc(sizeof(*this_svc));
    static_svcs = xrealloc_n(static_svcs, num_svcs + 1, sizeof(*static_svcs));
    static_svcs[num_svcs] = this_svc;
    num_svcs++;

    this_svc->name = xstrdup(name);
    this_svc->static_sttl = GDNSD_STTL_TTL_MAX;

    vscf_data_t* ttl_data = vscf_hash_get_data_byconstkey(svc_cfg, "ttl", true);
    if (ttl_data) {
        unsigned long fixed_ttl = 0;
        if (!vscf_is_simple(ttl_data) || !vscf_simple_get_as_ulong(ttl_data, &fixed_ttl))
            log_fatal("plugin_static: service type '%s': the value of 'ttl' must be a simple integer!", name);
        if (fixed_ttl > GDNSD_STTL_TTL_MAX)
            log_fatal("plugin_static: service type '%s': the value of 'ttl' must be <= %u", name, GDNSD_STTL_TTL_MAX);
        this_svc->static_sttl = fixed_ttl;
    }

    vscf_data_t* state_data = vscf_hash_get_data_byconstkey(svc_cfg, "state", true);
    if (state_data) {
        if (!vscf_is_simple(state_data))
            log_fatal("plugin_static: service type '%s': the value of 'state' must be 'up' or 'down' as a simple string!", name);
        const char* state_txt = vscf_simple_get_data(state_data);
        if (!strcasecmp(state_txt, "down"))
            this_svc->static_sttl |= GDNSD_STTL_DOWN;
        else if (strcasecmp(state_txt, "up"))
            log_fatal("plugin_static: service type '%s': the value of 'state' must be 'up' or 'down', not '%s'", name, state_txt);
    }
}

static void add_mon_any(const char* svc_name, const unsigned idx)
{
    gdnsd_assert(svc_name);

    static_svc_t* this_svc = NULL;

    for (unsigned i = 0; i < num_svcs; i++) {
        if (!strcmp(svc_name, static_svcs[i]->name)) {
            this_svc = static_svcs[i];
            break;
        }
    }
    gdnsd_assert(this_svc);

    static_mon_t* this_mon = xmalloc(sizeof(*this_mon));
    static_mons = xrealloc_n(static_mons, num_mons + 1, sizeof(*static_mons));
    static_mons[num_mons] = this_mon;
    num_mons++;
    this_mon->svc = this_svc;
    this_mon->idx = idx;
}

static void plugin_static_add_mon_addr(const char* desc V_UNUSED, const char* svc_name, const char* cname V_UNUSED, const gdnsd_anysin_t* addr V_UNUSED, const unsigned idx)
{
    add_mon_any(svc_name, idx);
}

static void plugin_static_add_mon_cname(const char* desc V_UNUSED, const char* svc_name, const char* cname V_UNUSED, const unsigned idx)
{
    add_mon_any(svc_name, idx);
}

static void plugin_static_init_monitors(struct ev_loop* mon_loop V_UNUSED)
{
    for (unsigned i = 0; i < num_mons; i++)
        gdnsd_mon_sttl_updater(static_mons[i]->idx, static_mons[i]->svc->static_sttl);
}

plugin_t plugin_static_funcs = {
    .name = "static",
    .config_loaded = false,
    .used = false,
    .load_config = plugin_static_load_config,
    .map_res = plugin_static_map_res,
    .pre_run = NULL,
    .iothread_init = NULL,
    .iothread_cleanup = NULL,
    .resolve = plugin_static_resolve,
    .add_svctype = plugin_static_add_svctype,
    .add_mon_addr = plugin_static_add_mon_addr,
    .add_mon_cname = plugin_static_add_mon_cname,
    .init_monitors = plugin_static_init_monitors,
    .start_monitors = NULL,
};
