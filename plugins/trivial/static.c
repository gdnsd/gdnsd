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

mon_list_t* plugin_static_load_config(const vscf_data_t* config) {
    if(!config)
        log_fatal("static plugin requires a 'plugins' configuration stanza");
    dmn_assert(vscf_get_type(config) == VSCF_HASH_T);

    num_resources = vscf_hash_get_len(config);
    resources = malloc(num_resources * sizeof(static_resource_t));
    unsigned residx = 0;
    vscf_hash_iterate(config, false, config_res, &residx);

    return NULL;
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

bool plugin_static_resolve(unsigned threadnum V_UNUSED, unsigned resnum V_UNUSED, const uint8_t* origin, const client_info_t* cinfo V_UNUSED, dyn_result_t* result) {
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

    return true;
}
