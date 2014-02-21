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

#define GDNSD_PLUGIN_NAME simplefo

#include "config.h"
#include <gdnsd/plugin.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

typedef enum {
    A_PRI = 0,
    A_SEC = 1
} res_which_t;

typedef enum {
    A_AUTO = 0,
    A_IPv4 = 1,
    A_IPv6 = 2,
} as_af_t;

static const char* which_str[2] = {
    "primary",
    "secondary"
};

static const char* which_str_mon[2] = {
    "/pri/",
    "/sec/"
};

typedef struct {
    anysin_t addrs[2];
    mon_state_t* states[2];
    unsigned num_svcs;
} addrstate_t;

typedef struct {
    const char* name;
    addrstate_t* addrs_v4;
    addrstate_t* addrs_v6;
} res_t;

static res_t* resources = NULL;
static unsigned num_resources = 0;

static mon_list_t mon_list = { 0, NULL };

static const char DEFAULT_SVCNAME[] = "default";

/*********************************/
/* Local, static functions       */
/*********************************/

static void mon_add(const char* svctype, const char* resname, const char* addr_txt, mon_state_t* state_ptr) {
    mon_list.info = realloc(mon_list.info, sizeof(mon_info_t) * (mon_list.count + 1));
    mon_info_t* m = &mon_list.info[mon_list.count++];
    m->svctype = svctype;
    m->desc = resname;
    m->addr = addr_txt;
    m->state_ptr = state_ptr;
}

static bool bad_res_opt(const char* key, unsigned klen V_UNUSED, const vscf_data_t* d V_UNUSED, void* data) {
    log_fatal("plugin_simplefo: resource '%s': bad option '%s'", (const char*)data, key);
}

F_NONNULL
static as_af_t config_addrs(addrstate_t* as, as_af_t as_af, const char* resname, const char* stanza, const vscf_data_t* cfg) {
    dmn_assert(as); dmn_assert(resname); dmn_assert(stanza); dmn_assert(cfg); dmn_assert(vscf_is_hash(cfg));

    unsigned num_svcs;
    const char** svc_names;
    const vscf_data_t* svctypes_data = vscf_hash_get_data_byconstkey(cfg, "service_types", true);
    if(svctypes_data) {
        as->num_svcs = num_svcs = vscf_array_get_len(svctypes_data);
        if(!num_svcs)
            log_fatal("plugin_simplefo: resource %s (%s): service_types cannot be empty", resname, stanza);
        svc_names = malloc(sizeof(char*) * num_svcs);
        for(unsigned i = 0; i < num_svcs; i++) {
            const vscf_data_t* svctype_cfg = vscf_array_get_data(svctypes_data, i);
            if(!vscf_is_simple(svctype_cfg))
                log_fatal("plugin_simplefo: resource %s (%s): 'service_types' value(s) must be strings", resname, stanza);
            svc_names[i] = vscf_simple_get_data(svctype_cfg);
        }
    }
    else {
        as->num_svcs = num_svcs = 1;
        svc_names = malloc(sizeof(char*));
        svc_names[0] = DEFAULT_SVCNAME;
    }

    res_which_t both[2] = { A_PRI, A_SEC };
    for(unsigned i = 0; i < 2; i++) {
        res_which_t which = both[i];
        const vscf_data_t* addrcfg = vscf_hash_get_data_bystringkey(cfg, which_str[which], true);
        if(!addrcfg || VSCF_SIMPLE_T != vscf_get_type(addrcfg))
            log_fatal("plugin_simplefo: resource %s (%s): '%s' must be defined as an IP address string", resname, stanza, which_str[which]);
        const char* addr_txt = vscf_simple_get_data(addrcfg);
        int addr_err = gdnsd_anysin_getaddrinfo(addr_txt, NULL, &as->addrs[which]);
        if(addr_err)
            log_fatal("plugin_simplefo: resource %s: parsing '%s' as an IP address failed: %s", resname, addr_txt, gai_strerror(addr_err));

        const bool ipv6 = as->addrs[which].sa.sa_family == AF_INET6;
        if(as_af == A_IPv6 && !ipv6)
            log_fatal("plugin_simplefo: resource %s (%s): '%s' is not an IPv6 address", resname, stanza, addr_txt);
        else if(as_af == A_IPv4 && ipv6)
            log_fatal("plugin_simplefo: resource %s (%s): '%s' is not an IPv4 address", resname, stanza, addr_txt);

        as->states[which] = malloc(sizeof(mon_state_t) * num_svcs);
        for(unsigned j = 0; j < num_svcs; j++) {
            char* desc = malloc(strlen(resname) + 5 + strlen(which_str_mon[which]) + strlen(svc_names[j]) + 1);
            strcpy(desc, resname);
            strcat(desc, ipv6 ? "/ipv6" : "/ipv4");
            strcat(desc, which_str_mon[which]);
            strcat(desc, svc_names[j]);
            mon_add(svc_names[j], desc, addr_txt, &as->states[which][j]);
        }
    }

    free(svc_names);

    if(as_af == A_AUTO) {
        if(as->addrs[A_PRI].sa.sa_family != as->addrs[A_SEC].sa.sa_family)
            log_fatal("plugin_simplefo: resource %s (%s): primary and secondary must be same address family (IPv4 or IPv6)", resname, stanza);
        return as->addrs[A_PRI].sa.sa_family == AF_INET6 ? A_IPv6 : A_IPv4;
    }

    vscf_hash_iterate(cfg, true, bad_res_opt, (void*)resname);

    return as_af;
}

static bool config_res(const char* resname, unsigned resname_len V_UNUSED, const vscf_data_t* opts, void* data) {
    unsigned* residx_ptr = data;
    unsigned rnum = (*residx_ptr)++;
    res_t* res = &resources[rnum];
    res->name = strdup(resname);

    if(vscf_get_type(opts) != VSCF_HASH_T)
        log_fatal("plugin_simplefo: resource %s: value must be a hash", resname);

    vscf_hash_bequeath_all(opts, "service_types", true, false);

    const vscf_data_t* addrs_v4_cfg = vscf_hash_get_data_byconstkey(opts, "addrs_v4", true);
    const vscf_data_t* addrs_v6_cfg = vscf_hash_get_data_byconstkey(opts, "addrs_v6", true);
    if(!addrs_v4_cfg && !addrs_v6_cfg) {
        addrstate_t* as = malloc(sizeof(addrstate_t));
        as_af_t which = config_addrs(as, A_AUTO, resname, "direct", opts);
        if(which == A_IPv4) {
            res->addrs_v4 = as;
        }
        else {
            dmn_assert(which == A_IPv6);
            res->addrs_v6 = as;
        }
    }
    else {
        if(addrs_v4_cfg) {
            if(!vscf_is_hash(addrs_v4_cfg))
                log_fatal("plugin_simplefo: resource %s: The value of 'addrs_v4', if defined, must be a hash", resname);
            addrstate_t* as = res->addrs_v4 = malloc(sizeof(addrstate_t));
            config_addrs(as, A_IPv4, resname, "addrs_v4", addrs_v4_cfg);
        }
        if(addrs_v6_cfg) {
            if(!vscf_is_hash(addrs_v6_cfg))
                log_fatal("plugin_simplefo: resource %s: The value of 'addrs_v6', if defined, must be a hash", resname);
            addrstate_t* as = res->addrs_v6 = malloc(sizeof(addrstate_t));
            config_addrs(as, A_IPv6, resname, "addrs_v6", addrs_v6_cfg);
        }
    }


    vscf_hash_iterate(opts, true, bad_res_opt, (void*)resname);
    return true;
}

/*********************************/
/* Exported callbacks start here */
/*********************************/

mon_list_t* plugin_simplefo_load_config(const vscf_data_t* config) {
    if(!config)
        log_fatal("simplefo plugin requires a 'plugins' configuration stanza");

    dmn_assert(vscf_get_type(config) == VSCF_HASH_T);

    num_resources = vscf_hash_get_len(config);

    // send service_types to either "resources" or the direct resources
    if(vscf_hash_bequeath_all(config, "service_types", true, false))
        num_resources--; // don't count parameter keys

    resources = calloc(num_resources, sizeof(res_t));
    unsigned residx = 0;
    vscf_hash_iterate(config, true, config_res, &residx);

    return &mon_list;
}

int plugin_simplefo_map_resource_dyna(const char* resname) {
    if(resname) {
        for(unsigned i = 0; i < num_resources; i++)
            if(!strcmp(resname, resources[i].name))
                return (int)i;
        log_err("plugin_simplefo: Unknown resource '%s'", resname);
    }
    else {
        log_err("plugin_simplfo: resource name required");
    }

    return -1;
}

// ---state chart-------------
// p    s    ttl    which fail_upstream?
// up   *    normal pri   no
// dang *    halved pri   no
// down up   halved sec   no
// down dang halved sec   no
// down down halved pri   yes
// ----------------------------
F_NONNULL
static bool resolve_addr(const addrstate_t* as, dynaddr_result_t* result, bool* cut_ttl_ptr) {
    dmn_assert(as); dmn_assert(result); dmn_assert(cut_ttl_ptr);

    bool rv = true;
    res_which_t which = A_PRI;
    mon_state_uint_t p_state = gdnsd_mon_get_min_state(as->states[A_PRI], as->num_svcs);
    switch(p_state) {
        case MON_STATE_DOWN:
            if(gdnsd_mon_get_min_state(as->states[A_SEC], as->num_svcs) != MON_STATE_DOWN)
                which = A_SEC;
            else
                rv = false;
            // fall-through
        case MON_STATE_DANGER:;
            *cut_ttl_ptr = true;
            break;
        default:
            dmn_assert(p_state == MON_STATE_UP);
    }

    gdnsd_dynaddr_add_result_anysin(result, &as->addrs[which]);
    return rv;
}

bool plugin_simplefo_resolve_dynaddr(unsigned threadnum V_UNUSED, unsigned resnum, const client_info_t* cinfo V_UNUSED, dynaddr_result_t* result) {
    bool rv = true;
    bool cut_ttl = false;
    res_t* res = &resources[resnum];

    if(res->addrs_v4) {
        rv &= resolve_addr(res->addrs_v4, result, &cut_ttl);
        dmn_assert(result->count_v4);
    }

    if(res->addrs_v6) {
        rv &= resolve_addr(res->addrs_v6, result, &cut_ttl);
        dmn_assert(result->count_v6);
    }

    if(cut_ttl)
        result->ttl >>= 1;

    return rv;
}

