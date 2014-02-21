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

#define GDNSD_PLUGIN_NAME static

#include "config.h"
#include <gdnsd/plugin.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

typedef struct {
    const char* name;
    bool is_addr;
    uint32_t ipaddr;
    uint8_t *dname;
} static_resource_t;

static static_resource_t* resources = NULL;
static unsigned num_resources = 0;

static bool config_res(const char* resname, unsigned resname_len V_UNUSED, const vscf_data_t* addr, void* data) {
    unsigned* residx_ptr = data;

    if(vscf_get_type(addr) != VSCF_SIMPLE_T)
        log_fatal("plugin_static: resource %s: must be an IPv4 address or a domainname in string form", resname);

    struct in_addr a;

    unsigned res = (*residx_ptr)++;
    resources[res].name = strdup(resname);

    const char* addr_txt = vscf_simple_get_data(addr);
    if(inet_pton(AF_INET, addr_txt, &a) < 1) {
        // Address-parsing failed, treat as domainname for DYNC
        resources[res].is_addr = false;
        resources[res].dname = malloc(256);
        dname_status_t status = vscf_simple_get_as_dname(addr, resources[res].dname);
        if(status == DNAME_INVALID)
            log_fatal("plugin_static: resource %s: must be an IPv4 address or a domainname in string form", resname);
        if(status == DNAME_VALID)
            resources[res].dname = dname_trim(resources[res].dname);
    }
    else {
        resources[res].is_addr = true;
        resources[res].ipaddr = a.s_addr;
    }

    return true;
}

void plugin_static_load_config(const vscf_data_t* config) {
    if(!config)
        log_fatal("static plugin requires a 'plugins' configuration stanza");
    dmn_assert(vscf_get_type(config) == VSCF_HASH_T);

    num_resources = vscf_hash_get_len(config);
    resources = malloc(num_resources * sizeof(static_resource_t));
    unsigned residx = 0;
    vscf_hash_iterate(config, false, config_res, &residx);
}

int plugin_static_map_res(const char* resname, const uint8_t* origin) {
    if(resname) {
        for(unsigned i = 0; i < num_resources; i++) {
            if(!strcmp(resname, resources[i].name)) {
                if(resources[i].is_addr)
                    return (int)i;
                if(!origin)
                    map_res_err("plugin_static: CNAME resource '%s' cannot be used for a DYNA record", resources[i].name);
                if(dname_is_partial(resources[i].dname)) {
                    uint8_t dnbuf[256];
                    dname_copy(dnbuf, resources[i].dname);
                    dname_status_t status = dname_cat(dnbuf, origin);
                    if(status != DNAME_VALID)
                        map_res_err("plugin_static: CNAME resource '%s' (configured with partial domainname '%s') creates an invalid domainname when used at origin '%s'", resources[i].name, logf_dname(resources[i].dname), logf_dname(origin));
                }
                return (int)i;
            }
        }
        map_res_err("plugin_static: Unknown resource '%s'", resname);
    }

    map_res_err("plugin_static: resource name required");
}

gdnsd_sttl_t plugin_static_resolve(unsigned threadnum V_UNUSED, unsigned resnum V_UNUSED, const uint8_t* origin, const client_info_t* cinfo V_UNUSED, dyn_result_t* result) {
    dmn_assert(!result->is_cname);

    // this (DYNA->CNAME) should be caught during map_res
    //   and cause the zonefile to fail to load
    if(!origin)
        dmn_assert(resources[resnum].is_addr);

    if(resources[resnum].is_addr) {
        result->a.count_v6 = 0;
        result->a.count_v4 = 1;
        result->a.addrs_v4[0] = resources[resnum].ipaddr;
    }
    else {
        dmn_assert(origin);
        result->is_cname = true;
        uint8_t* dname = resources[resnum].dname;
        dname_copy(result->cname, dname);
        if(dname_is_partial(result->cname))
            dname_cat(result->cname, origin);
        dmn_assert(dname_status(result->cname) == DNAME_VALID);
    }

    return GDNSD_STTL_TTL_MASK;
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

void plugin_static_add_svctype(const char* name, const vscf_data_t* svc_cfg, const unsigned interval V_UNUSED, const unsigned timeout V_UNUSED) {
    dmn_assert(name); dmn_assert(svc_cfg);

    static_svcs = realloc(static_svcs, sizeof(static_svc_t*) * ++num_svcs);
    static_svc_t* this_svc = static_svcs[num_svcs - 1] = malloc(sizeof(static_svc_t));
    this_svc->name = strdup(name);
    this_svc->static_sttl = GDNSD_STTL_TTL_MASK;

    const vscf_data_t* state_data = vscf_hash_get_data_byconstkey(svc_cfg, "state", true);
    if(state_data) {
        if(!vscf_is_simple(state_data))
            log_fatal("plugin_static: service type '%s': the value of 'state' must be a string!", name);
        const char* state_txt = vscf_simple_get_data(state_data);
        if(!strcasecmp(state_txt, "down"))
            this_svc->static_sttl |= GDNSD_STTL_DOWN;
        else if(strcasecmp(state_txt, "up"))
            log_fatal("plugin_static: service type '%s': the value of 'state' must be 'up' or 'down', not '%s'", name, state_txt);
    }
}

void plugin_static_add_monitor(const char* desc V_UNUSED, const char* svc_name, const anysin_t* addr V_UNUSED, const unsigned idx) {
    dmn_assert(desc); dmn_assert(svc_name); dmn_assert(addr);

    static_svc_t* this_svc = NULL;

    for(unsigned i = 0; i < num_svcs; i++) {
        if(!strcmp(svc_name, static_svcs[i]->name)) {
            this_svc = static_svcs[i];
            break;
        }
    }
    dmn_assert(this_svc);

    static_mons = realloc(static_mons, sizeof(static_mon_t*) * ++num_mons);
    static_mon_t* this_mon = static_mons[num_mons - 1] = malloc(sizeof(static_mon_t));
    this_mon->svc = this_svc;
    this_mon->idx = idx;
}

void plugin_static_init_monitors(struct ev_loop* mon_loop V_UNUSED) {
    dmn_assert(mon_loop);

    for(unsigned int i = 0; i < num_mons; i++)
        gdnsd_mon_sttl_updater(static_mons[i]->idx, static_mons[i]->svc->static_sttl);
}
