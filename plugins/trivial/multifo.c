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
 * Author: Brandon L Black <blblack@gmail.com>
 */

#define GDNSD_PLUGIN_NAME multifo

#include "config.h"
#include <gdnsd/plugin.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <math.h>

static const char DEFAULT_SVCNAME[] = "default";
static const double DEF_UP_THRESH = 0.5;

typedef struct {
    anysin_t addr;
    mon_state_t* states;
} addrstate_t;

typedef struct {
    addrstate_t* as;
    unsigned num_svcs;
    unsigned count;
    unsigned up_thresh;
} addrset_t;

typedef struct {
    const char* name;
    addrset_t* aset_v4;
    addrset_t* aset_v6;
} res_t;

static res_t* resources = NULL;
static unsigned num_resources = 0;

static mon_list_t mon_list = { 0, NULL };

/*********************************/
/* Local, static functions       */
/*********************************/

static void mon_add(const char* svctype, const char* desc, const char* addr_txt, mon_state_t* state_ptr) {
    mon_list.info = realloc(mon_list.info, sizeof(mon_info_t) * (mon_list.count + 1));
    mon_info_t* m = &mon_list.info[mon_list.count++];
    m->svctype = strdup(svctype);
    m->desc = desc;
    m->addr = strdup(addr_txt);
    m->state_ptr = state_ptr;
}

F_NONNULL
static bool bad_res_opt(const char* key, unsigned klen V_UNUSED, const vscf_data_t* d V_UNUSED, void* data) {
    dmn_assert(key); dmn_assert(d); dmn_assert(data);
    log_fatal("plugin_multifo: resource '%s': bad option '%s'", (const char*)data, key);
}

// given an array (or actually, even a single value), construct
//  an addrs_vN hash inheriting params from the parent as usual.
// also works for direct config, even though some of the work is redundant.
F_NONNULL
static const vscf_data_t* addrs_hash_from_array(const vscf_data_t* ary, const char* resname, const char* stanza) {
    dmn_assert(ary); dmn_assert(!vscf_is_hash(ary));

    const vscf_data_t* parent = vscf_get_parent(ary);
    dmn_assert(vscf_is_hash(parent));

    vscf_data_t* newhash = vscf_hash_new();
    const unsigned alen = vscf_array_get_len(ary);
    for(unsigned i = 0; i < alen; i++) {
        const vscf_data_t* this_addr_cfg = vscf_array_get_data(ary, i);
        if(!vscf_is_simple(this_addr_cfg))
            log_fatal("plugin_multifo: resource '%s' (%s): if defined as an array, array values must all be address strings", resname, stanza);
        const unsigned lnum = i + 1;
        char lbuf[12];
        snprintf(lbuf, 12, "%u", lnum);
        vscf_hash_add_val(lbuf, strlen(lbuf), newhash, vscf_clone(this_addr_cfg, false));
    }

    vscf_hash_inherit(parent, newhash, "up_thresh", false);
    vscf_hash_inherit(parent, newhash, "service_types", false);
    return newhash;
}

typedef struct {
    const char* resname;
    const char* stanza;
    const char** svc_names;
    addrset_t* aset;
    unsigned idx;
    bool ipv6;
} addrs_iter_data_t;

F_NONNULL
static bool addr_setup(const char* addr_desc, unsigned klen V_UNUSED, const vscf_data_t* addr_data, void* aid_asvoid) {
    dmn_assert(addr_desc); dmn_assert(addr_data); dmn_assert(aid_asvoid);

    addrs_iter_data_t* aid = (addrs_iter_data_t*)aid_asvoid;

    const char* resname = aid->resname;
    const char* stanza = aid->stanza;
    const char** svc_names = aid->svc_names;
    addrset_t* aset = aid->aset;
    const unsigned idx = aid->idx++;
    const bool ipv6 = aid->ipv6;
    addrstate_t* as = &aset->as[idx];

    if(!vscf_is_simple(addr_data))
        log_fatal("plugin_multifo: resource %s (%s): address %s: all addresses must be string values", resname, stanza, addr_desc);
    const char* addr_txt = vscf_simple_get_data(addr_data);

    const int addr_err = gdnsd_anysin_getaddrinfo(addr_txt, NULL, &as->addr);
    if(addr_err)
        log_fatal("plugin_multifo: resource %s (%s): failed to parse address '%s' for '%s': %s", resname, stanza, addr_txt, addr_desc, gai_strerror(addr_err));
    if(ipv6 && as->addr.sa.sa_family != AF_INET6)
        log_fatal("plugin_multifo: resource %s (%s): address '%s' for '%s' is not IPv6", resname, stanza, addr_txt, addr_desc);
    else if(!ipv6 && as->addr.sa.sa_family != AF_INET)
        log_fatal("plugin_multifo: resource %s (%s): address '%s' for '%s' is not IPv4", resname, stanza, addr_txt, addr_desc);

    as->states = malloc(sizeof(mon_state_t) * aset->num_svcs);

    for(unsigned i = 0; i < aset->num_svcs; i++) {
        char *complete_desc = malloc(strlen(resname) + 6 + strlen(addr_desc) + 1 + strlen(svc_names[i]) + 1);
        strcpy(complete_desc, resname);
        strcat(complete_desc, ipv6 ? "/ipv6/" : "/ipv4/");
        strcat(complete_desc, addr_desc);
        strcat(complete_desc, "/");
        strcat(complete_desc, svc_names[i]);
        mon_add(svc_names[i], complete_desc, addr_txt, &as->states[i]);
    }

    return true;
}

F_NONNULL
static void config_addrs(const char* resname, const char* stanza, addrset_t* aset, const bool ipv6, const vscf_data_t* cfg) {
    dmn_assert(resname); dmn_assert(aset); dmn_assert(cfg);

    bool destroy_cfg = false;
    if(!vscf_is_hash(cfg)) {
        cfg = addrs_hash_from_array(cfg, resname, stanza);
        destroy_cfg = true;
    }

    unsigned num_addrs = vscf_hash_get_len(cfg);

    const char** svc_names;
    const vscf_data_t* svctypes_data = vscf_hash_get_data_byconstkey(cfg, "service_types", true);
    if(svctypes_data) {
        num_addrs--;
        aset->num_svcs = vscf_array_get_len(svctypes_data);
        if(!aset->num_svcs)
            log_fatal("plugin_multifo: resource %s (%s): service_types cannot be an empty array (try 'none'?)", resname, stanza);
        svc_names = malloc(sizeof(char*) * aset->num_svcs);
        for(unsigned i = 0; i < aset->num_svcs; i++) {
            const vscf_data_t* svctype_cfg = vscf_array_get_data(svctypes_data, i);
            if(!vscf_is_simple(svctype_cfg))
                log_fatal("plugin_multifo: resource %s (%s): 'service_types' values must be strings", resname, stanza);
            svc_names[i] = vscf_simple_get_data(svctype_cfg);
        }
    }
    else {
        aset->num_svcs = 1;
        svc_names = malloc(sizeof(char*));
        svc_names[0] = DEFAULT_SVCNAME;
    }

    double up_thresh = DEF_UP_THRESH;
    const vscf_data_t* up_thresh_cfg = vscf_hash_get_data_byconstkey(cfg, "up_thresh", true);
    if(up_thresh_cfg) {
        num_addrs--;
        if(!vscf_is_simple(up_thresh_cfg) || !vscf_simple_get_as_double(up_thresh_cfg, &up_thresh)
           || up_thresh <= 0.0 || up_thresh > 1.0)
            log_fatal("plugin_multifo: resource %s (%s): 'up_thresh' must be a floating point value in the range (0.0 - 1.0]", resname, stanza);
    }

    if(!num_addrs)
        log_fatal("plugin_multifo: resource '%s' (%s): must define one or more 'desc => IP' mappings, either directly or inside a subhash named 'addrs'", resname, stanza);
    if(num_addrs > 64)
        log_fatal("plugin_multifo: resource %s (%s): too many IPv%c addresses (limit 64)", resname, stanza, ipv6 ? '6' : '4');

    aset->count = num_addrs;
    aset->as = calloc(num_addrs, sizeof(addrstate_t));
    aset->up_thresh = ceil(up_thresh * aset->count);

    addrs_iter_data_t aid = {
        .resname = resname,
        .stanza = stanza,
        .svc_names = svc_names,
        .aset = aset,
        .idx = 0,
        .ipv6 = ipv6,
    };
    vscf_hash_iterate(cfg, true, addr_setup, &aid);

    free(svc_names);

    if(destroy_cfg)
        vscf_destroy((vscf_data_t*)cfg);
}

static void config_auto(res_t* res, const char* stanza, const vscf_data_t* auto_cfg) {
    dmn_assert(res); dmn_assert(stanza); dmn_assert(auto_cfg);

    bool destroy_cfg = false;
    if(!vscf_is_hash(auto_cfg)) {
        auto_cfg = addrs_hash_from_array(auto_cfg, res->name, stanza);
        destroy_cfg = true;
    }

    // mark parameters
    vscf_hash_get_data_byconstkey(auto_cfg, "up_thresh", true);
    vscf_hash_get_data_byconstkey(auto_cfg, "service_types", true);

    // clone down to just address-label keys
    vscf_data_t* auto_cfg_noparams = vscf_clone(auto_cfg, true);

    if(!vscf_hash_get_len(auto_cfg_noparams))
        log_fatal("plugin_multifo: resource '%s' (%s): no addresses defined!", res->name, stanza);

    const char* first_name = vscf_hash_get_key_byindex(auto_cfg_noparams, 0, NULL);
    const vscf_data_t* first_cfg = vscf_hash_get_data_byindex(auto_cfg_noparams, 0);
    if(!vscf_is_simple(first_cfg))
        log_fatal("plugin_multifo: resource '%s' (%s): The value of '%s' must be an IP address in string form", res->name, stanza, first_name);
    const char* addr_txt = vscf_simple_get_data(first_cfg);
    anysin_t temp_asin;
    const int addr_err = gdnsd_anysin_getaddrinfo(addr_txt, NULL, &temp_asin);
    if(addr_err)
        log_fatal("plugin_multifo: resource %s (%s): failed to parse address '%s' for '%s': %s", res->name, stanza, addr_txt, first_name, gai_strerror(addr_err));

    if(temp_asin.sa.sa_family == AF_INET6) {
        res->aset_v6 = calloc(1, sizeof(addrset_t));
        config_addrs(res->name, stanza, res->aset_v6, true, auto_cfg);
    }
    else {
        dmn_assert(temp_asin.sa.sa_family == AF_INET);
        res->aset_v4 = calloc(1, sizeof(addrset_t));
        config_addrs(res->name, stanza, res->aset_v4, false, auto_cfg);
    }

    vscf_destroy(auto_cfg_noparams);
    if(destroy_cfg)
        vscf_destroy((vscf_data_t*)auto_cfg);
}

F_NONNULL
static bool config_res(const char* resname, unsigned resname_len V_UNUSED, const vscf_data_t* opts, void* data) {
    dmn_assert(resname); dmn_assert(opts); dmn_assert(data);

    unsigned* residx_ptr = data;
    unsigned rnum = (*residx_ptr)++;
    res_t* res = &resources[rnum];
    res->name = strdup(resname);

    const vscf_data_t* addrs_v4_cfg = NULL;
    const vscf_data_t* addrs_v6_cfg = NULL;

    if(vscf_is_hash(opts)) {
        // inherit params downhill if applicable
        vscf_hash_bequeath_all(opts, "up_thresh", true, false);
        vscf_hash_bequeath_all(opts, "service_types", true, false);

        addrs_v4_cfg = vscf_hash_get_data_byconstkey(opts, "addrs_v4", true);
        addrs_v6_cfg = vscf_hash_get_data_byconstkey(opts, "addrs_v6", true);

        if(addrs_v4_cfg) {
            res->aset_v4 = calloc(1, sizeof(addrset_t));
            config_addrs(resname, "addrs_v4", res->aset_v4, false, addrs_v4_cfg);
        }

        if(addrs_v6_cfg) {
            res->aset_v6 = calloc(1, sizeof(addrset_t));
            config_addrs(resname, "addrs_v6", res->aset_v6, true, addrs_v6_cfg);
        }
    }

    if(!addrs_v4_cfg && !addrs_v6_cfg)
        config_auto(res, "direct", opts);
    else if(vscf_is_hash(opts))
        vscf_hash_iterate(opts, true, bad_res_opt, (void*)resname);
    else
        log_fatal("plugin_multifo: resource '%s': an empty array is not a valid resource config", resname);

    return true;
}

/*********************************/
/* Exported callbacks start here */
/*********************************/

mon_list_t* plugin_multifo_load_config(const vscf_data_t* config) {
    if(!config)
        log_fatal("multifo plugin requires a 'plugins' configuration stanza");

    dmn_assert(vscf_is_hash(config));

    num_resources = vscf_hash_get_len(config);

    // inherit params downhill
    if(vscf_hash_bequeath_all(config, "up_thresh", true, false))
        num_resources--;
    if(vscf_hash_bequeath_all(config, "service_types", true, false))
        num_resources--;

    resources = calloc(num_resources, sizeof(res_t));
    unsigned residx = 0;
    vscf_hash_iterate(config, true, config_res, &residx);

    return &mon_list;
}

int plugin_multifo_map_resource_dyna(const char* resname) {
    if(resname) {
        for(unsigned i = 0; i < num_resources; i++)
            if(!strcmp(resname, resources[i].name))
                return (int)i;
        log_err("plugin_multifo: Unknown resource '%s'", resname);
    }
    else {
        log_err("plugin_multifo: resource name required");
    }

    return -1;
}

F_NONNULL
static bool resolve(const addrset_t* aset, dynaddr_result_t* result, bool* cut_ttl_ptr, unsigned* resct_ptr) {
    dmn_assert(aset); dmn_assert(result); dmn_assert(cut_ttl_ptr); dmn_assert(resct_ptr);

    bool rv = true;

    // Add up/danger IPs to result set, signal ttl-cut if any non-up encountered
    for(unsigned i = 0; i < aset->count; i++) {
        const addrstate_t* as = &aset->as[i];
        const mon_state_uint_t state = gdnsd_mon_get_min_state(as->states, aset->num_svcs);
        if(state != MON_STATE_UP)
            *cut_ttl_ptr = true;
        if(state != MON_STATE_DOWN)
            gdnsd_dynaddr_add_result_anysin(result, &as->addr);
    }

    // if up_thresh was not met, signal upstream failure through rv and add all addresses
    if(*resct_ptr < aset->up_thresh) {
        rv = false;
        *resct_ptr = 0;
        for(unsigned i = 0; i < aset->count; i++)
            gdnsd_dynaddr_add_result_anysin(result, &aset->as[i].addr);
    }

    return rv;
}

bool plugin_multifo_resolve_dynaddr(unsigned threadnum V_UNUSED, unsigned resnum, const client_info_t* cinfo V_UNUSED, dynaddr_result_t* result) {
    bool rv = true;
    bool cut_ttl = false;
    res_t* res = &resources[resnum];

    if(res->aset_v4) {
        rv &= resolve(res->aset_v4, result, &cut_ttl, &result->count_v4);
        dmn_assert(result->count_v4);
    }

    if(res->aset_v6) {
        rv &= resolve(res->aset_v6, result, &cut_ttl, &result->count_v6);
        dmn_assert(result->count_v6);
    }

    // Cut TTL in half if any were in DOWN or DANGER states
    if(cut_ttl)
        result->ttl >>= 1;

    return rv;
}
