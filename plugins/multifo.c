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

#include <config.h>

#define GDNSD_PLUGIN_NAME multifo
#include <gdnsd/plugin.h>

#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

static const char DEFAULT_SVCNAME[] = "up";
static const double DEF_UP_THRESH = 0.5;

static unsigned v4_max = 0;
static unsigned v6_max = 0;

typedef struct {
    dmn_anysin_t addr;
    unsigned* indices;
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

/*********************************/
/* Local, static functions       */
/*********************************/

F_NONNULL
static bool bad_res_opt(const char* key, unsigned klen V_UNUSED, vscf_data_t* d V_UNUSED, const void* resname_asvoid) {
    dmn_assert(key); dmn_assert(d); dmn_assert(resname_asvoid);
    const char* resname = resname_asvoid;
    log_fatal("plugin_multifo: resource '%s': bad option '%s'", resname, key);
}

// given an array (or actually, even a single value), construct
//  an addrs_vN hash inheriting params from the parent as usual.
// also works for direct config, even though some of the work is redundant.
F_NONNULL
static vscf_data_t* addrs_hash_from_array(vscf_data_t* ary, const char* resname, const char* stanza) {
    dmn_assert(ary); dmn_assert(!vscf_is_hash(ary));

    vscf_data_t* parent = vscf_get_parent(ary);
    dmn_assert(vscf_is_hash(parent));

    vscf_data_t* newhash = vscf_hash_new();
    const unsigned alen = vscf_array_get_len(ary);
    for(unsigned i = 0; i < alen; i++) {
        vscf_data_t* this_addr_cfg = vscf_array_get_data(ary, i);
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
static bool addr_setup(const char* addr_desc, unsigned klen V_UNUSED, vscf_data_t* addr_data, void* aid_asvoid) {
    dmn_assert(addr_desc); dmn_assert(addr_data); dmn_assert(aid_asvoid);

    addrs_iter_data_t* aid = aid_asvoid;

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

    if(aset->num_svcs) {
        as->indices = xmalloc(sizeof(unsigned) * aset->num_svcs);
        for(unsigned i = 0; i < aset->num_svcs; i++)
            as->indices[i] = gdnsd_mon_addr(svc_names[i], &as->addr);
    }

    return true;
}

F_NONNULL
static void config_addrs(const char* resname, const char* stanza, addrset_t* aset, const bool ipv6, vscf_data_t* cfg) {
    dmn_assert(resname); dmn_assert(aset); dmn_assert(cfg);

    bool destroy_cfg = false;
    if(!vscf_is_hash(cfg)) {
        cfg = addrs_hash_from_array(cfg, resname, stanza);
        destroy_cfg = true;
    }

    unsigned num_addrs = vscf_hash_get_len(cfg);

    aset->num_svcs = 0;
    const char** svc_names = NULL;
    vscf_data_t* svctypes_data = vscf_hash_get_data_byconstkey(cfg, "service_types", true);
    if(svctypes_data) {
        num_addrs--;
        aset->num_svcs = vscf_array_get_len(svctypes_data);
        if(aset->num_svcs) {
            svc_names = xmalloc(sizeof(char*) * aset->num_svcs);
            for(unsigned i = 0; i < aset->num_svcs; i++) {
                vscf_data_t* svctype_cfg = vscf_array_get_data(svctypes_data, i);
                if(!vscf_is_simple(svctype_cfg))
                    log_fatal("plugin_multifo: resource %s (%s): 'service_types' values must be strings", resname, stanza);
                svc_names[i] = vscf_simple_get_data(svctype_cfg);
            }
        }
    }
    else {
        aset->num_svcs = 1;
        svc_names = xmalloc(sizeof(char*));
        svc_names[0] = DEFAULT_SVCNAME;
    }

    double up_thresh = DEF_UP_THRESH;
    vscf_data_t* up_thresh_cfg = vscf_hash_get_data_byconstkey(cfg, "up_thresh", true);
    if(up_thresh_cfg) {
        num_addrs--;
        if(!vscf_is_simple(up_thresh_cfg) || !vscf_simple_get_as_double(up_thresh_cfg, &up_thresh)
           || up_thresh <= 0.0 || up_thresh > 1.0)
            log_fatal("plugin_multifo: resource %s (%s): 'up_thresh' must be a floating point value in the range (0.0 - 1.0]", resname, stanza);
    }

    if(!num_addrs)
        log_fatal("plugin_multifo: resource '%s' (%s): must define one or more 'desc => IP' mappings, either directly or inside a subhash named 'addrs'", resname, stanza);

    aset->count = num_addrs;
    aset->as = xcalloc(num_addrs, sizeof(addrstate_t));
    aset->up_thresh = gdnsd_uscale_ceil(aset->count, up_thresh);

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
        vscf_destroy(cfg);

    if(ipv6) {
        if(num_addrs > v6_max)
            v6_max = num_addrs;
    }
    else {
        if(num_addrs > v4_max)
            v4_max = num_addrs;
    }
}

static void config_auto(res_t* res, const char* stanza, vscf_data_t* auto_cfg) {
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
    vscf_data_t* first_cfg = vscf_hash_get_data_byindex(auto_cfg_noparams, 0);
    if(!vscf_is_simple(first_cfg))
        log_fatal("plugin_multifo: resource '%s' (%s): The value of '%s' must be an IP address in string form", res->name, stanza, first_name);
    const char* addr_txt = vscf_simple_get_data(first_cfg);
    dmn_anysin_t temp_asin;
    const int addr_err = gdnsd_anysin_getaddrinfo(addr_txt, NULL, &temp_asin);
    if(addr_err)
        log_fatal("plugin_multifo: resource %s (%s): failed to parse address '%s' for '%s': %s", res->name, stanza, addr_txt, first_name, gai_strerror(addr_err));

    if(temp_asin.sa.sa_family == AF_INET6) {
        res->aset_v6 = xcalloc(1, sizeof(addrset_t));
        config_addrs(res->name, stanza, res->aset_v6, true, auto_cfg);
    }
    else {
        dmn_assert(temp_asin.sa.sa_family == AF_INET);
        res->aset_v4 = xcalloc(1, sizeof(addrset_t));
        config_addrs(res->name, stanza, res->aset_v4, false, auto_cfg);
    }

    vscf_destroy(auto_cfg_noparams);
    if(destroy_cfg)
        vscf_destroy(auto_cfg);
}

F_NONNULL
static bool config_res(const char* resname, unsigned resname_len V_UNUSED, vscf_data_t* opts, void* data) {
    dmn_assert(resname); dmn_assert(opts); dmn_assert(data);

    unsigned* residx_ptr = data;
    unsigned rnum = (*residx_ptr)++;
    res_t* res = &resources[rnum];
    res->name = strdup(resname);

    vscf_data_t* addrs_v4_cfg = NULL;
    vscf_data_t* addrs_v6_cfg = NULL;

    if(vscf_is_hash(opts)) {
        // inherit params downhill if applicable
        vscf_hash_bequeath_all(opts, "up_thresh", true, false);
        vscf_hash_bequeath_all(opts, "service_types", true, false);

        addrs_v4_cfg = vscf_hash_get_data_byconstkey(opts, "addrs_v4", true);
        addrs_v6_cfg = vscf_hash_get_data_byconstkey(opts, "addrs_v6", true);

        if(addrs_v4_cfg) {
            res->aset_v4 = xcalloc(1, sizeof(addrset_t));
            config_addrs(resname, "addrs_v4", res->aset_v4, false, addrs_v4_cfg);
        }

        if(addrs_v6_cfg) {
            res->aset_v6 = xcalloc(1, sizeof(addrset_t));
            config_addrs(resname, "addrs_v6", res->aset_v6, true, addrs_v6_cfg);
        }
    }

    if(!addrs_v4_cfg && !addrs_v6_cfg)
        config_auto(res, "direct", opts);
    else if(vscf_is_hash(opts))
        vscf_hash_iterate_const(opts, true, bad_res_opt, resname);
    else
        log_fatal("plugin_multifo: resource '%s': an empty array is not a valid resource config", resname);

    return true;
}

/*********************************/
/* Exported callbacks start here */
/*********************************/

void plugin_multifo_load_config(vscf_data_t* config, const unsigned num_threads V_UNUSED) {
    if(!config)
        log_fatal("multifo plugin requires a 'plugins' configuration stanza");

    dmn_assert(vscf_is_hash(config));

    num_resources = vscf_hash_get_len(config);

    // inherit params downhill
    if(vscf_hash_bequeath_all(config, "up_thresh", true, false))
        num_resources--;
    if(vscf_hash_bequeath_all(config, "service_types", true, false))
        num_resources--;

    resources = xcalloc(num_resources, sizeof(res_t));
    unsigned residx = 0;
    vscf_hash_iterate(config, true, config_res, &residx);
    gdnsd_dyn_addr_max(v4_max, v6_max);
}

int plugin_multifo_map_res(const char* resname, const uint8_t* origin V_UNUSED) {
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
static gdnsd_sttl_t resolve(const gdnsd_sttl_t* sttl_tbl, const addrset_t* aset, dyn_result_t* result, const bool isv6) {
    dmn_assert(aset); dmn_assert(result);

    dmn_assert(aset->count);

    gdnsd_sttl_t rv = GDNSD_STTL_TTL_MAX;
    unsigned added = 0;
    for(unsigned i = 0; i < aset->count; i++) {
        const addrstate_t* as = &aset->as[i];
        const gdnsd_sttl_t as_sttl = gdnsd_sttl_min(sttl_tbl, as->indices, aset->num_svcs);
        rv = gdnsd_sttl_min2(rv, as_sttl);
        if(!(as_sttl & GDNSD_STTL_DOWN)) {
            gdnsd_result_add_anysin(result, &as->addr);
            added++;
        }
    }

    // if up_thresh was not met, signal upstream failure through rv and add all addresses
    if(added < aset->up_thresh) {
        rv |= GDNSD_STTL_DOWN;
        if(isv6)
            gdnsd_result_wipe_v6(result);
        else
            gdnsd_result_wipe_v4(result);
        for(unsigned i = 0; i < aset->count; i++)
            gdnsd_result_add_anysin(result, &aset->as[i].addr);
    }
    // else force non-down response in retval, even if "rv" currently has the down flag from
    //   the min/min2 operations on the individual addrs
    else {
        rv &= ~GDNSD_STTL_DOWN;
    }

    assert_valid_sttl(rv);
    return rv;
}

gdnsd_sttl_t plugin_multifo_resolve(unsigned resnum, const uint8_t* origin V_UNUSED, const client_info_t* cinfo V_UNUSED, dyn_result_t* result) {
    dmn_assert(result);

    const gdnsd_sttl_t* sttl_tbl = gdnsd_mon_get_sttl_table();

    res_t* res = &resources[resnum];

    gdnsd_sttl_t rv;

    if(res->aset_v4) {
        rv = resolve(sttl_tbl, res->aset_v4, result, false);
        if(res->aset_v6) {
            const unsigned v6_rv = resolve(sttl_tbl, res->aset_v6, result, true);
            rv = gdnsd_sttl_min2(rv, v6_rv);
        }
    }
    else {
        dmn_assert(res->aset_v6);
        rv = resolve(sttl_tbl, res->aset_v6, result, true);
    }

    assert_valid_sttl(rv);
    return rv;
}
