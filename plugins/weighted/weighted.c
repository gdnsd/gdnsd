/* Copyright © 2011 Anton Tolchanov <anton.tolchanov@gmail.com>
 *
 * Based on other gdnsd plugins by Brandon L Black <blblack@gmail.com>
 * and Jay Reitz <jreitz@gmail.com>
 *
 * This file is part of gdnsd-plugin-weighted.
 *
 * gdnsd-plugin-weighted is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * gdnsd-plugin-weighted is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gdnsd.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "config.h"
#define GDNSD_PLUGIN_NAME weighted
#include <gdnsd/plugin.h>
#include <math.h>

// Importantly, 1048575 * 64 * 64 barely fits in uint32_t
#define MAX_ITEMS_PER_SET 64
#define MAX_ADDRS_PER_GROUP 64
#define MAX_WEIGHT 1048575
#define MAX_WEIGHT_STR "1048575"

/*
  Technically, we could further reduce the 64-limits to just:
   64 addrs per res in ungrouped multi-mode
   64 groups per res in grouped multi-mode
   64 addrs per group in grouped single-mode
  Which frees up situations such as:
   >64 cnames per res
   >64 addrs per res in ungrouped single-mode
   >64 groups per res in grouped single-mode
   >64 addrs per group in grouped multi-mode
  Would still need accurate dynamic array sizing in resolve_dynaddr,
   and would still need to double-check this doesn't cause
   total per-resource weights in excess of 2^32-1 or we
   overflow res->weight (and ditto inside groups in single-mode).
  Will wait for someone to complain about the limits first, though...
*/

typedef struct {
    anysin_t addr;
    unsigned weight;
    mon_state_t* states;
} addrstate_t;

typedef struct {
    addrstate_t* as;
    unsigned count;
    unsigned weight;
    unsigned max_weight;
} res_aitem_t;

typedef enum {
    RES_ASET_UNKNOWN = 0,
    RES_ASET_UNGROUPED = 1,
    RES_ASET_GROUPED = 2,
} res_aset_mode_t;

typedef struct {
    res_aitem_t* items;
    char** svc_names;
    unsigned count;
    unsigned weight;
    unsigned up_weight;
    unsigned max_weight;
    unsigned num_svcs;
    res_aset_mode_t gmode;
    bool multi;
} addrset_t;

typedef struct {
    uint8_t* cname;
    unsigned weight;
} res_citem_t;

typedef struct {
    res_citem_t* items;
    unsigned count;
    unsigned weight;
} cnset_t;

typedef struct {
    const char* name;
    cnset_t* cnames;
    addrset_t* addrs_v4;
    addrset_t* addrs_v6;
} resource_t;

static resource_t* resources = NULL;
static unsigned num_resources = 0;

static mon_list_t mon_list = { 0, NULL };

// tracked configured max sizes, for dynamic arrays later
static unsigned cfg_max_items_per_res = 1;
static unsigned cfg_max_addrs_per_group = 1;

// Per-thread PRNGs

static unsigned iothread_count;
static gdnsd_rstate_t** per_thread_rstates;

static void init_rand_storage(const unsigned num_threads) {
    iothread_count = num_threads;
    per_thread_rstates = malloc(num_threads * sizeof(gdnsd_rstate_t*));
}

static void init_rand(const unsigned tnum) {
    per_thread_rstates[tnum] = gdnsd_rand_init();
}

// it's important that the modulo operation happen in 64-bit space,
//   even though modval and the effective return value are in 32-bit space,
//   because it vastly reduces the bias in the returned numbers.
static uint64_t get_rand(const unsigned tnum, const uint64_t modval) {
    dmn_assert(modval);
    return gdnsd_rand_get64(per_thread_rstates[tnum]) % modval;
}

// Main config code starts here

F_NONNULL
static void config_item_addrs(res_aitem_t* res_item, const char* res_name, const char* stanza, const char* item_name, const bool ipv6, const vscf_data_t* cfg_data, addrset_t* addrset) {
    dmn_assert(res_name); dmn_assert(stanza); dmn_assert(item_name);
    dmn_assert(res_item); dmn_assert(cfg_data); dmn_assert(addrset);

    const unsigned res_name_len = strlen(res_name);
    const unsigned item_name_len = strlen(item_name);

    long wtemp = 0;
    if(!vscf_is_array(cfg_data)
            || (2 != vscf_array_get_len(cfg_data))
            || !vscf_is_simple(vscf_array_get_data(cfg_data, 0))
            || !vscf_is_simple(vscf_array_get_data(cfg_data, 1))
            || !vscf_simple_get_as_long(vscf_array_get_data(cfg_data, 1), &wtemp)
            || wtemp < 1 || wtemp > MAX_WEIGHT )
        log_fatal("plugin_weighted: resource '%s' (%s): item '%s': values in addrs mode must be arrays of [ IPADDR, WEIGHT ], where weight must be an integer in the range 1 - " MAX_WEIGHT_STR, res_name, stanza, item_name);

    res_item->count = 1;
    res_item->as = calloc(res_item->count, sizeof(addrstate_t));
    res_item->as[0].states = calloc(addrset->num_svcs, sizeof(mon_state_t));
    res_item->as[0].weight = wtemp;
    res_item->max_weight = wtemp;
    res_item->weight = wtemp;

    const char* addr_txt = vscf_simple_get_data(vscf_array_get_data(cfg_data, 0));
    int addr_err = gdnsd_anysin_getaddrinfo(addr_txt, NULL, &res_item->as[0].addr);
    if(addr_err)
        log_fatal("plugin_weighted: resource '%s' (%s): item '%s': parsing '%s' as an IP address failed: %s", res_name, stanza, item_name, addr_txt, gai_strerror(addr_err));
    if(ipv6 && res_item->as[0].addr.sa.sa_family != AF_INET6)
        log_fatal("plugin_weighted: resource '%s' (%s): item '%s': '%s' is IPv4, was expecting IPv6", res_name, stanza, item_name, addr_txt);
    else if(!ipv6 && res_item->as[0].addr.sa.sa_family != AF_INET)
        log_fatal("plugin_weighted: resource '%s' (%s): item '%s': '%s' is IPv6, was expecting IPv4", res_name, stanza, item_name, addr_txt);

    for(unsigned i = 0; i < addrset->num_svcs; i++) {
        const unsigned svc_name_len = strlen(addrset->svc_names[i]);
        char *complete_desc = malloc(res_name_len + 1 + 4 + 1 + item_name_len + 1 + svc_name_len + 1);
        sprintf(complete_desc, "%s/%s/%s/%s", res_name, ipv6 ? "ipv6" : "ipv4", item_name, addrset->svc_names[i]);
        mon_list.info = realloc(mon_list.info, sizeof(mon_info_t) * (mon_list.count + 1));
        mon_info_t* m = &mon_list.info[mon_list.count++];
        m->svctype = addrset->svc_names[i];
        m->desc = complete_desc;
        m->addr = addr_txt;
        m->state_ptr = &res_item->as[0].states[i];
    }
    log_debug("plugin_weighted: resource '%s' (%s), item '%s': A '%s' added w/ weight %u", res_name, stanza, item_name, addr_txt, res_item->weight);
}

typedef struct {
    addrset_t* addrset;
    res_aitem_t* res_item;
    const char* res_name;
    const char* stanza;
    const char* item_name;
    bool ipv6;
    unsigned lb_idx;
} iaga_t;

F_NONNULL
static bool config_addr_group_addr(const char* lb_name, const unsigned lb_name_len, const vscf_data_t* lb_data, void* iaga_asvoid) {
    dmn_assert(lb_name); dmn_assert(lb_name_len); dmn_assert(lb_data); dmn_assert(iaga_asvoid);

    iaga_t* iaga = (iaga_t*)iaga_asvoid;

    addrset_t* addrset = iaga->addrset;
    res_aitem_t* res_item = iaga->res_item;
    unsigned lb_idx = iaga->lb_idx++;
    const char* res_name = iaga->res_name;
    const char* stanza = iaga->stanza;
    const char* item_name = iaga->item_name;
    const bool ipv6 = iaga->ipv6;
    const unsigned res_name_len = strlen(res_name);
    const unsigned item_name_len = strlen(item_name);

    long lb_weight = 0;
    if(!vscf_is_array(lb_data)
            || (2 != vscf_array_get_len(lb_data))
            || !vscf_is_simple(vscf_array_get_data(lb_data, 0))
            || !vscf_is_simple(vscf_array_get_data(lb_data, 1))
            || !vscf_simple_get_as_long(vscf_array_get_data(lb_data, 1), &lb_weight)
            || lb_weight < 1 || lb_weight > MAX_WEIGHT )
        log_fatal("plugin_weighted: resource '%s', group '%s': values in address group mode must be arrays of [ IPADDR, WEIGHT ], where weight must be an integer in the range 1 - " MAX_WEIGHT_STR, res_name, item_name);

    res_item->as[lb_idx].states = calloc(addrset->num_svcs, sizeof(mon_state_t));
    res_item->as[lb_idx].weight = lb_weight;

    const char* addr_txt = vscf_simple_get_data(vscf_array_get_data(lb_data, 0));
    int addr_err = gdnsd_anysin_getaddrinfo(addr_txt, NULL, &res_item->as[lb_idx].addr);
    if(addr_err)
        log_fatal("plugin_weighted: resource '%s', group '%s', addr '%s': parsing '%s' as an IP address failed: %s", res_name, item_name, lb_name, addr_txt, gai_strerror(addr_err));
    if(ipv6 && res_item->as[lb_idx].addr.sa.sa_family != AF_INET6)
        log_fatal("plugin_weighted: resource '%s' (%s): item '%s': '%s' is IPv4, was expecting IPv6", res_name, stanza, item_name, addr_txt);
    else if(!ipv6 && res_item->as[lb_idx].addr.sa.sa_family != AF_INET)
        log_fatal("plugin_weighted: resource '%s' (%s): item '%s': '%s' is IPv6, was expecting IPv4", res_name, stanza, item_name, addr_txt);

    for(unsigned i = 0; i < addrset->num_svcs; i++) {
        const unsigned svc_name_len = strlen(addrset->svc_names[i]);
        char *complete_desc = malloc(res_name_len + 1 + 4 + 1 + item_name_len + 1 + lb_name_len + 1 + svc_name_len + 1);
        sprintf(complete_desc, "%s/%s/%s/%s/%s", res_name, ipv6 ? "ipv6" : "ipv4", item_name, lb_name, addrset->svc_names[i]);
        mon_list.info = realloc(mon_list.info, sizeof(mon_info_t) * (mon_list.count + 1));
        mon_info_t* m = &mon_list.info[mon_list.count++];
        m->svctype = addrset->svc_names[i];
        m->desc = complete_desc;
        m->addr = addr_txt;
        m->state_ptr = &res_item->as[lb_idx].states[i];
    }

    log_debug("plugin_weighted: resource '%s' (%s), item '%s', address %s added with weight %u", res_name, stanza, item_name, addr_txt, res_item->as[lb_idx].weight);

    return true;
}

F_NONNULL
static void config_item_addr_groups(res_aitem_t* res_item, const char* res_name, const char* stanza, const char* item_name, const bool ipv6, const vscf_data_t* cfg_data, addrset_t* addrset) {
    dmn_assert(res_name); dmn_assert(stanza); dmn_assert(item_name);
    dmn_assert(res_item); dmn_assert(cfg_data); dmn_assert(addrset);

    if(!vscf_is_hash(cfg_data))
        log_fatal("plugin_weighted: resource '%s' (%s), group '%s': groups values must be a hashes", res_name, stanza, item_name);

    unsigned num_addrs = vscf_hash_get_len(cfg_data);

    if(!num_addrs)
        log_fatal("plugin_weighted: resource '%s' (%s), group '%s': must contain one or more label => [ IPADDR, WEIGHT ] settings", res_name, stanza, item_name);
    if(num_addrs > MAX_ADDRS_PER_GROUP)
        log_fatal("plugin_weighted: resource '%s' (%s), group '%s': too many addresses (max %u)", res_name, stanza, item_name, MAX_ADDRS_PER_GROUP);

    // track maximum group-size actually configured
    if(cfg_max_addrs_per_group < num_addrs)
        cfg_max_addrs_per_group = num_addrs;

    res_item->count = num_addrs;
    res_item->as = calloc(num_addrs, sizeof(addrstate_t));

    iaga_t iaga = {
        .addrset = addrset,
        .res_item = res_item,
        .res_name = res_name,
        .stanza = stanza,
        .item_name = item_name,
        .ipv6 = ipv6,
        .lb_idx = 0
    };
    vscf_hash_iterate(cfg_data, true, config_addr_group_addr, &iaga);

    // sum/max the lb weights
    res_item->weight = 0;
    res_item->max_weight = 0;
    for(unsigned i = 0; i < res_item->count; i++) {
        const unsigned awt = res_item->as[i].weight;
        res_item->weight += awt;
        if(res_item->max_weight < awt)
            res_item->max_weight = awt;
    }

    log_debug("plugin_weighted: resource '%s' (%s), group '%s' with %u addresses & weight %u added", res_name, stanza, item_name, num_addrs, res_item->weight);
}

typedef struct {
    unsigned item_idx;
    addrset_t* addrset;
    const char* res_name;
    const char* stanza;
    bool ipv6;
} addr_iter_data_t;

static bool config_addrset_item(const char* item_name, unsigned klen V_UNUSED, const vscf_data_t* cfg_data, void* aid_asvoid) {

    // pull a bunch of data from addr_iter_data_t...
    addr_iter_data_t* addr_iter_data = (addr_iter_data_t*)aid_asvoid;
    const unsigned item_idx = addr_iter_data->item_idx++;
    addrset_t* addrset = addr_iter_data->addrset;
    const char* res_name = addr_iter_data->res_name;
    const char* stanza = addr_iter_data->stanza;
    const bool ipv6 = addr_iter_data->ipv6;

    // autodetect if not set
    if(unlikely(addrset->gmode == RES_ASET_UNKNOWN)) {
        dmn_assert(!item_idx); // should get set on first iteration
        if(vscf_is_hash(cfg_data)) {
            addrset->gmode = RES_ASET_GROUPED;
        }
        else {
            if(!vscf_is_array(cfg_data))
                log_fatal("plugin_weighted: resource '%s' (%s): item data must be hash (grouped mode) or array (ungrouped mode)", res_name, stanza);
            addrset->gmode = RES_ASET_UNGROUPED;
        }
    }

    res_aitem_t* res_item = &addrset->items[item_idx];
    if(addrset->gmode == RES_ASET_UNGROUPED) {
        config_item_addrs(res_item, res_name, stanza, item_name, ipv6, cfg_data, addrset);
    }
    else {
        dmn_assert(addrset->gmode == RES_ASET_GROUPED);
        config_item_addr_groups(res_item, res_name, stanza, item_name, ipv6, cfg_data, addrset);
    }

    return true;
}

F_NONNULL
static void config_addrset(const char* res_name, const char* stanza, const bool ipv6, addrset_t* addrset, const vscf_data_t* cfg) {
    dmn_assert(res_name); dmn_assert(stanza); dmn_assert(addrset); dmn_assert(cfg);

    if(!vscf_is_hash(cfg))
        log_fatal("plugin_weighted: resource '%s' stanza '%s' value must be a hash", res_name, stanza);

    const vscf_data_t* parent = vscf_get_parent(cfg);

    // inherit down the applicable res-level parameters
    vscf_hash_inherit(parent, (vscf_data_t*)cfg, "service_types", true);
    vscf_hash_inherit(parent, (vscf_data_t*)cfg, "multi", true);
    vscf_hash_inherit(parent, (vscf_data_t*)cfg, "up_thresh", true);

    // Get a starting assumption of our item count
    addrset->count = vscf_hash_get_len(cfg);

    /////// Process the parameters...

    // service_types
    const vscf_data_t* res_stypes = vscf_hash_get_data_byconstkey(cfg, "service_types", true);
    if (res_stypes) {
        addrset->count--; // minus one for service_types entry
        addrset->num_svcs = vscf_array_get_len(res_stypes);
        if(!addrset->num_svcs)
            log_fatal("plugin_weighted: resource '%s' (%s): service_types cannot be an empty array", res_name, stanza);
        addrset->svc_names = malloc(addrset->num_svcs * sizeof(char*));
        for(unsigned i = 0; i < addrset->num_svcs; i++) {
            const vscf_data_t* this_svc_cfg = vscf_array_get_data(res_stypes, i);
            if(!vscf_is_simple(this_svc_cfg))
                log_fatal("plugin_weighted: resource '%s' (%s): service_types values must be strings", res_name, stanza);
            addrset->svc_names[i] = strdup(vscf_simple_get_data(this_svc_cfg));
        }
    }
    else {
        addrset->num_svcs = 1;
        addrset->svc_names = malloc(sizeof(char*));
        addrset->svc_names[0] = strdup("default");
    }

    // multi option
    addrset->multi = false;
    const vscf_data_t* multi_cfg = vscf_hash_get_data_byconstkey(cfg, "multi", true);
    if(multi_cfg) {
        addrset->count--; // minus one for multi entry
        if(!vscf_is_simple(multi_cfg) || !vscf_simple_get_as_bool(multi_cfg, &addrset->multi))
            log_fatal("plugin_weighted: resource '%s' (%s): 'multi' must be a boolean value ('true' or 'false')", res_name, stanza);
    }

    // up threshold as double
    double up_thresh = 0.5;
    const vscf_data_t* thresh_cfg = vscf_hash_get_data_byconstkey(cfg, "up_thresh", true);
    if(thresh_cfg) {
        addrset->count--; // minus one for up_thresh entry
        if(!vscf_is_simple(thresh_cfg) || !vscf_simple_get_as_double(thresh_cfg, &up_thresh)
           || up_thresh <= 0.0 || up_thresh > 1.0)
            log_fatal("plugin_weighted: resource '%s' (%s): 'up_thresh' must be a floating point value in the range (0.0 - 1.0]", res_name, stanza);
    }

    if(addrset->count > MAX_ITEMS_PER_SET)
        log_fatal("plugin_weighted: resource '%s' (%s): number of direct groups or addrs within one family cannot be more than %u", res_name, stanza, MAX_ITEMS_PER_SET);
    if(!addrset->count)
        log_fatal("plugin_weighted: resource '%s' (%s): empty address-family sets not allowed", res_name, stanza);

    // track maximum res-size actually configured
    if(cfg_max_items_per_res < addrset->count)
        cfg_max_items_per_res = addrset->count;

    addrset->items = calloc(addrset->count, sizeof(res_aitem_t));
    addrset->gmode = RES_ASET_UNKNOWN;
    addr_iter_data_t aid = {
        .item_idx = 0,
        .addrset = addrset,
        .res_name = res_name,
        .stanza = stanza,
        .ipv6 = ipv6
    };
    vscf_hash_iterate(cfg, true, config_addrset_item, &aid);

    addrset->weight = 0;
    addrset->max_weight = 0;
    for(unsigned i = 0; i < addrset->count; i++) {
        const unsigned iwt = addrset->items[i].weight;
        dmn_assert(iwt); dmn_assert(addrset->items[i].max_weight);
        addrset->weight += iwt;
        if(addrset->max_weight < iwt)
            addrset->max_weight = iwt;
    }

    dmn_assert(addrset->weight);
    dmn_assert(addrset->max_weight);

    addrset->up_weight = ceil(up_thresh * addrset->weight);
    dmn_assert(addrset->up_weight);
}

typedef struct {
    cnset_t* cnset;
    const char* res_name;
    const char* stanza;
    unsigned item_idx;
} cname_iter_data_t;

F_NONNULL
static bool config_item_cname(const char* item_name, unsigned klen V_UNUSED, const vscf_data_t* cfg_data, void* cid_asvoid) {
    dmn_assert(item_name); dmn_assert(cfg_data); dmn_assert(cid_asvoid);
    cname_iter_data_t* cid = (cname_iter_data_t*)cid_asvoid;

    cnset_t* cnset = cid->cnset;
    const char* res_name = cid->res_name;
    const char* stanza = cid->stanza;
    const unsigned item_idx = cid->item_idx++;
    res_citem_t* res_item = &cnset->items[item_idx];

    long wtemp = 0;
    if(!vscf_is_array(cfg_data)
            || (2 != vscf_array_get_len(cfg_data))
            || !vscf_is_simple(vscf_array_get_data(cfg_data, 0))
            || !vscf_is_simple(vscf_array_get_data(cfg_data, 1))
            || !vscf_simple_get_as_long(vscf_array_get_data(cfg_data, 1), &wtemp)
            || wtemp < 1 || wtemp > MAX_WEIGHT )
        log_fatal("plugin_weighted: resource '%s' (%s), item '%s': values in cname mode must be arrays of [ CNAME, WEIGHT ], where weight must be an integer in the range 1 - " MAX_WEIGHT_STR, res_name, stanza, item_name);
    res_item->weight = wtemp;

    uint8_t* dname = malloc(256);
    dname_status_t dnstat = vscf_simple_get_as_dname(vscf_array_get_data(cfg_data, 0), dname);
    if(dnstat == DNAME_INVALID)
        log_fatal("plugin_weighted: resource '%s' (%s), item '%s': '%s' is not a legal domainname", res_name, stanza, item_name, vscf_simple_get_data(vscf_array_get_data(cfg_data, 0)));
    if(dnstat == DNAME_VALID)
        dname = dname_trim(dname);
    res_item->cname = dname;

    log_debug("plugin_weighted: resource '%s' (%s), item '%s', CNAME '%s' added with weight %u", res_name, stanza, item_name, logf_dname(dname), res_item->weight);

    return true;
}

F_NONNULL
static void config_cnameset(const char* res_name, const char* stanza, cnset_t* cnset, const vscf_data_t* cfg) {
    dmn_assert(res_name); dmn_assert(stanza); dmn_assert(cnset); dmn_assert(cfg);

    if(!vscf_is_hash(cfg))
        log_fatal("plugin_weighted: resource '%s' stanza '%s' value must be a hash", res_name, stanza);

    cnset->count = vscf_hash_get_len(cfg);

    if(cnset->count > MAX_ITEMS_PER_SET)
        log_fatal("plugin_weighted: resource '%s' (%s): number of cnames cannot be more than %u", res_name, stanza, MAX_ITEMS_PER_SET);
    if(!cnset->count)
        log_fatal("plugin_weighted: resource '%s' (%s): empty cname sets not allowed", res_name, stanza);

    cnset->items = calloc(cnset->count, sizeof(res_citem_t));
    cname_iter_data_t cid = {
        .cnset = cnset,
        .res_name = res_name,
        .stanza = stanza,
        .item_idx = 0,
    };
    vscf_hash_iterate(cfg, true, config_item_cname, &cid);

    cnset->weight = 0;
    for(unsigned i = 0; i < cnset->count; i++) {
        const unsigned cwt = cnset->items[i].weight;
        dmn_assert(cwt);
        cnset->weight += cwt;
    }

    dmn_assert(cnset->weight);
}

F_NONNULL
static void config_auto(resource_t* res, const vscf_data_t* res_cfg) {
    dmn_assert(res); dmn_assert(res_cfg); dmn_assert(vscf_is_hash(res_cfg));

    // mark all possible parameter-keys
    vscf_hash_get_data_byconstkey(res_cfg, "service_types", true);
    vscf_hash_get_data_byconstkey(res_cfg, "multi", true);
    vscf_hash_get_data_byconstkey(res_cfg, "up_thresh", true);

    // make a copy that contains no parameters, only item-name keys
    vscf_data_t* res_cfg_noparams = vscf_clone(res_cfg, true);

    if(!vscf_hash_get_len(res_cfg_noparams))
        log_fatal("plugin_weighted: resource '%s' (direct) contains no weighted items", res->name);

    const char* first_name = vscf_hash_get_key_byindex(res_cfg_noparams, 0, NULL);
    const vscf_data_t* first_cfg = vscf_hash_get_data_byindex(res_cfg_noparams, 0);
    if(vscf_is_hash(first_cfg)) { // grouped address mode...
        if(!vscf_hash_get_len(first_cfg))
            log_fatal("plugin_weighted: resource '%s' (direct): group '%s': contains no addresses", res->name, first_name);
        const char* lb_name = vscf_hash_get_key_byindex(first_cfg, 0, NULL);
        const vscf_data_t* lb_cfg = vscf_hash_get_data_byindex(first_cfg, 0);
        if(!vscf_is_array(lb_cfg) || !vscf_array_get_len(lb_cfg) || !vscf_is_simple(vscf_array_get_data(lb_cfg, 0)))
            log_fatal("plugin_weighted: resource '%s' (direct): group '%s': item '%s': value must be an array of [ IP, weight ]", res->name, first_name, lb_name);
        const char* first_addr_txt = vscf_simple_get_data(vscf_array_get_data(lb_cfg, 0));
        anysin_t temp_sin;
        int addr_err = gdnsd_anysin_getaddrinfo(first_addr_txt, NULL, &temp_sin);
        if(addr_err)
            log_fatal("plugin_weighted: resource '%s' (direct): group '%s': item '%s': could not parse '%s' as an IP address: %s", res->name, first_name, lb_name, first_addr_txt, gai_strerror(addr_err));
        if(temp_sin.sa.sa_family == AF_INET6) {
            res->addrs_v6 = calloc(1, sizeof(addrset_t));
            config_addrset(res->name, "direct", true, res->addrs_v6, res_cfg);
        }
        else {
            dmn_assert(temp_sin.sa.sa_family == AF_INET);
            res->addrs_v4 = calloc(1, sizeof(addrset_t));
            config_addrset(res->name, "direct", false, res->addrs_v4, res_cfg);
        }
    }
    else if(vscf_is_array(first_cfg)) { // ungrouped address, or cnames
        const vscf_data_t* first_ac = vscf_array_get_data(first_cfg, 0);
        if(!first_ac || !vscf_is_simple(first_ac))
            log_fatal("plugin_weighted: resource '%s' (direct): item '%s': first element of array should be an IP address or CNAME string", res->name, first_name);
        anysin_t temp_sin;
        if(gdnsd_anysin_getaddrinfo(vscf_simple_get_data(first_ac), NULL, &temp_sin)) {
            // was not a valid address, try cnames mode
            res->cnames = calloc(1, sizeof(cnset_t));
            config_cnameset(res->name, "direct", res->cnames, res_cfg_noparams);
        }
        else {
            // was a valid address, try addrset mode
            if(temp_sin.sa.sa_family == AF_INET6) {
                res->addrs_v6 = calloc(1, sizeof(addrset_t));
                config_addrset(res->name, "direct", true, res->addrs_v6, res_cfg);
            }
            else {
                dmn_assert(temp_sin.sa.sa_family == AF_INET);
                res->addrs_v4 = calloc(1, sizeof(addrset_t));
                config_addrset(res->name, "direct", false, res->addrs_v4, res_cfg);
            }
        }
    }
    else {
        log_fatal("plugin_weighted: resource '%s' (direct): item '%s': resource type not detectable (should be array of [ IP, weight ], array of [ CNAME, weight ], or hashed address group ...)", res->name, first_name);
    }

    vscf_destroy(res_cfg_noparams);
}

static bool res_mixed_fail(const char* item_name, unsigned klen V_UNUSED, const vscf_data_t* d V_UNUSED, void* rname_asvoid) {
    log_fatal("plugin_weighted: resource '%s' seems to have explicit 'addrs', 'addrs_v4', 'addrs_v6', or 'cnames' configuration mixed with direct item config (e.g. '%s'), which is not allowed", (const char*)rname_asvoid, item_name);
    return false;
}

static bool config_res(const char* res_name, unsigned klen V_UNUSED, const vscf_data_t* res_cfg, void* idx_asvoid) {
    unsigned* idx_ptr = (unsigned*) idx_asvoid;
    resource_t* res = &resources[(*idx_ptr)++];
    res->name = strdup(res_name);
    if(!vscf_is_hash(res_cfg))
        log_fatal("plugin_weighted: the value of resource '%s' must be a hash", res_name);

    /* Resource config: up to 3 subsets in parallel:
     * resX => {
     *     addrs_v4 => { ... (IPv4, grouped or not)  }
     *     addrs_v6 => { ... (IPv6, grouped or not)  }
     *     cnames => { ... }
     * }
     * OR: auto-detect any of the possibilities at the top level as the only subset
     */

    // Check for bad old config, so that we error out on it.  If we don't, old "addrs"
    //   config actually looks like a legitimate grouped configuration, which is silently bad.
    const vscf_data_t* addrs_cfg = vscf_hash_get_data_byconstkey(res_cfg, "addrs", true);
    if(addrs_cfg)
        log_fatal("plugin_weighted: resource '%s': key 'addrs' is illegal, choose another name for this item", res_name);

    // grab explicit sub-stanzas
    const vscf_data_t* addrs_v4_cfg = vscf_hash_get_data_byconstkey(res_cfg, "addrs_v4", true);
    const vscf_data_t* addrs_v6_cfg = vscf_hash_get_data_byconstkey(res_cfg, "addrs_v6", true);
    const vscf_data_t* cnames_cfg = vscf_hash_get_data_byconstkey(res_cfg, "cnames", true);

    if(addrs_v4_cfg) {
        res->addrs_v4 = calloc(1, sizeof(addrset_t));
        config_addrset(res_name, "addrs_v4", false, res->addrs_v4, addrs_v4_cfg);
    }

    if(addrs_v6_cfg) {
        res->addrs_v6 = calloc(1, sizeof(addrset_t));
        config_addrset(res_name, "addrs_v6", true, res->addrs_v6, addrs_v6_cfg);
    }

    if(cnames_cfg) {
        if(addrs_v4_cfg || addrs_v6_cfg)
            log_warn("plugin_weighted: resource '%s': mixing 'cnames' and addrs_v[46] in the same resource is deprecated - please split the cnames part into a separate resource", res_name);
        res->cnames = calloc(1, sizeof(cnset_t));
        config_cnameset(res_name, "cnames", res->cnames, cnames_cfg);
        // in the case that 'cnames' is explicitly defined, but addrs_v4/addrs_v6
        //   are not, we need to get any resource-level inherited address parameters
        //   marked so that we don't fail the mixed explicit+direct check at the bottom
        //   of this function.
        if(!addrs_v4_cfg && !addrs_v6_cfg) {
            vscf_hash_get_data_byconstkey(res_cfg, "service_types", true);
            vscf_hash_get_data_byconstkey(res_cfg, "multi", true);
            vscf_hash_get_data_byconstkey(res_cfg, "up_thresh", true);
        }
    }

    if(!addrs_v4_cfg && !addrs_v6_cfg && !cnames_cfg) {
        config_auto(res, res_cfg);
    }
    else {
       // if unmarked keys remain in res_cfg (explicit sets would have marked params),
       //    fail due to mixed direct cfg + sub-stanzas.
       vscf_hash_iterate(res_cfg, true, res_mixed_fail, (void*)res_name);
    }

    return true;
}

////// exported callbacks start here

mon_list_t* plugin_weighted_load_config(const vscf_data_t* config) {
    dmn_assert(config);
    dmn_assert(vscf_is_hash(config));

    num_resources = vscf_hash_get_len(config);
    if(vscf_hash_bequeath_all(config, "service_types", true, false))
        num_resources--; // don't count service_types
    if(vscf_hash_bequeath_all(config, "multi", true, false))
        num_resources--; // don't count multi
    if(vscf_hash_bequeath_all(config, "up_thresh", true, false))
        num_resources--; // don't count up_thresh

    resources = calloc(num_resources, sizeof(resource_t));
    unsigned idx = 0;
    vscf_hash_iterate(config, true, config_res, &idx);
    return &mon_list;
}

void plugin_weighted_full_config(const unsigned num_threads) {
    dmn_assert(num_threads);
    init_rand_storage(num_threads);
}

int plugin_weighted_map_resource_dyna(const char* resname) {
    if(resname) {
        for(unsigned i = 0; i < num_resources; i++) {
            if (!strcmp(resname, resources[i].name)) {
                if(!resources[i].addrs_v4 && !resources[i].addrs_v6) {
                    log_err("plugin_weighted: Resource '%s' used in a DYNA RR, but has no address config data", resources[i].name);
                    return -1;
                }
                log_debug("plugin_weighted: resource '%s' mapped", resources[i].name);
                return (int)i;
            }
        }
        log_err("plugin_weighted: unknown resource '%s'", resname);
    }
    else {
        log_err("plugin_weighted: resource name required");
    }

    return -1;
}

int plugin_weighted_map_resource_dync(const char* resname, const uint8_t* origin) {
    if(resname) {
        for(unsigned i = 0; i < num_resources; i++) {
            if (!strcmp(resname, resources[i].name)) {
                cnset_t* cnset = resources[i].cnames;
                if(!cnset) {
                    log_err("plugin_weighted: Resource '%s' used in a DYNC RR, but has no cnames config data", resources[i].name);
                    return -1;
                }
                for(unsigned j = 0; j < cnset->count; j++) {
                    const uint8_t* dname = cnset->items[j].cname;
                    if(dname_status(dname) == DNAME_PARTIAL) {
                        uint8_t dnbuf[256];
                        dname_copy(dnbuf, dname);
                        if(dname_cat(dnbuf, origin) != DNAME_VALID) {
                            log_err("plugin_weighted: Name '%s' of resource '%s', when used at origin '%s', produces an invalid domainname", logf_dname(dname), resources[i].name, logf_dname(origin));
                            return -1;
                        }
                    }
                }
                log_debug("plugin_weighted: resource '%s' mapped", resources[i].name);
                return (int)i;
            }
        }
        log_err("plugin_weighted: unknown resource '%s'", resname);
    }
    else {
        log_err("plugin_weighted: resource name required in zonefile references");
    }

    return -1;
}

void plugin_weighted_iothread_init(const unsigned threadnum) { init_rand(threadnum); }

void plugin_weighted_resolve_dyncname(unsigned threadnum, unsigned resnum, const uint8_t* origin, const client_info_t* cinfo V_UNUSED, dyncname_result_t* result) {
    dmn_assert(origin); dmn_assert(result);

    const resource_t* resource = &resources[resnum];
    dmn_assert(resource);
    cnset_t* cnset = resource->cnames;
    dmn_assert(cnset);
    dmn_assert(cnset->weight);

    const unsigned item_rand = get_rand(threadnum, cnset->weight);
    unsigned running_total = 0;
    unsigned chosen = 0;
    for(unsigned j = 0; j < cnset->count; j++) {
        running_total += cnset->items[j].weight;
        if(item_rand < running_total) {
            chosen = j;
            break;
        }
    }

    const uint8_t* dname = cnset->items[chosen].cname;
    dname_copy(result->dname, dname);
    if (dname_status(dname) == DNAME_PARTIAL) {
        dname_cat(result->dname, origin);
        dmn_assert(dname_status(result->dname) == DNAME_VALID);
    }
}

F_NONNULL
static bool resolve(const unsigned threadnum, const addrset_t* aset, dynaddr_result_t* result, bool* cut_ttl_ptr) {
    dmn_assert(aset); dmn_assert(result); dmn_assert(cut_ttl_ptr);

    const unsigned num_items = aset->count;
    unsigned dyn_items_sum = 0; // sum of dyn_item_sums[]
    unsigned dyn_items_max = 0; // max of dyn_item_sums[]
    unsigned dyn_item_sums[cfg_max_items_per_res]; // sum of dyn_addr_weights[N][]
    unsigned dyn_item_maxs[cfg_max_items_per_res]; // max of dyn_addr_weights[N][]
    // addr cfg weight or 0, depends on status:
    unsigned dyn_addr_weights[cfg_max_items_per_res][cfg_max_addrs_per_group];
    bool rv = true;

    // Get dynamic info about each item
    for(unsigned item_idx = 0; item_idx < aset->count; item_idx++) {
        const res_aitem_t* res_item = &aset->items[item_idx];
        dyn_item_sums[item_idx] = 0;
        dyn_item_maxs[item_idx] = 0;
        for(unsigned addr_idx = 0; addr_idx < res_item->count; addr_idx++) {
            const addrstate_t* addr = &res_item->as[addr_idx];
            const mon_state_uint_t addr_state
                = gdnsd_mon_get_min_state(addr->states, aset->num_svcs);
            if(addr_state != MON_STATE_UP)
                *cut_ttl_ptr = true;
            if(addr_state != MON_STATE_DOWN) {
                dyn_addr_weights[item_idx][addr_idx] = addr->weight;
                dyn_item_sums[item_idx] += addr->weight;
                if(addr->weight > dyn_item_maxs[item_idx])
                    dyn_item_maxs[item_idx] = addr->weight;
            }
            else {
                dyn_addr_weights[item_idx][addr_idx] = 0;
            }
        }
    }

    // summarize dynamic info at the resource level
    for(unsigned item_idx = 0; item_idx < aset->count; item_idx++) {
        const unsigned isum = dyn_item_sums[item_idx];
        dyn_items_sum += isum;
        if(dyn_items_max < isum)
            dyn_items_max = isum;
    }

    // if all items looked completely-down, treat them all as completely-up
    if(!dyn_items_sum) {
        rv = false;
        dyn_items_sum = aset->weight;
        dyn_items_max = aset->max_weight;
        for(unsigned item_idx = 0; item_idx < num_items; item_idx++) {
            const res_aitem_t* res_item = &aset->items[item_idx];
            dyn_item_sums[item_idx] = res_item->weight;
            dyn_item_maxs[item_idx] = res_item->max_weight;
            for(unsigned addr_idx = 0; addr_idx < res_item->count; addr_idx++)
                dyn_addr_weights[item_idx][addr_idx] = res_item->as[addr_idx].weight;
        }
    }

    dmn_assert(dyn_items_sum);
    dmn_assert(dyn_items_max);

    if(aset->multi) {
        // Outer decision: choose multiple items based on dyn_items_max
        for(unsigned item_idx = 0; item_idx < num_items; item_idx++) {
            const res_aitem_t* res_item = &aset->items[item_idx];
            const unsigned item_rand = get_rand(threadnum, dyn_items_max);
            const unsigned isum = dyn_item_sums[item_idx];
            if(item_rand < isum) {
                dmn_assert(isum); // given that they're both uints
                // Inner decision: choose one addr based on dyn_item->sum
                const unsigned addr_rand = get_rand(threadnum, isum);
                unsigned addr_running_total = 0;
                for(unsigned addr_idx = 0; addr_idx < res_item->count; addr_idx++) {
                    addr_running_total += dyn_addr_weights[item_idx][addr_idx];
                    if(addr_rand < addr_running_total) {
                        gdnsd_dynaddr_add_result_anysin(result, &res_item->as[addr_idx].addr);
                        break;
                    }
                }
            }
        }
    }
    else {
        // Outer decision: choose one item based on dyn_items_sum
        const unsigned item_rand = get_rand(threadnum, dyn_items_sum);
        unsigned item_running_total = 0;
        for(unsigned item_idx = 0; item_idx < num_items; item_idx++) {
            item_running_total += dyn_item_sums[item_idx];
            if(item_rand < item_running_total) {
                const res_aitem_t* chosen = &aset->items[item_idx];
                // Inner decision: choose multiple addrs based on chosen's dynamic max
                const unsigned addr_max = dyn_item_maxs[item_idx];
                dmn_assert(addr_max);
                for(unsigned addr_idx = 0; addr_idx < chosen->count; addr_idx++) {
                    const unsigned addr_rand = get_rand(threadnum, addr_max);
                    if(addr_rand < dyn_addr_weights[item_idx][addr_idx])
                        gdnsd_dynaddr_add_result_anysin(result, &chosen->as[addr_idx].addr);
                }
                break;
            }
        }
    }

    return dyn_items_sum < aset->up_weight ? false : rv;
}

bool plugin_weighted_resolve_dynaddr(unsigned threadnum, unsigned resnum, const client_info_t* cinfo V_UNUSED, dynaddr_result_t* result) {
    dmn_assert(result);

    const resource_t* resource = &resources[resnum];
    dmn_assert(resource);
    dmn_assert(resource->addrs_v4 || resource->addrs_v6);

    bool cut_ttl = false;
    bool rv = true;

    if(resource->addrs_v4) {
        rv &= resolve(threadnum, resource->addrs_v4, result, &cut_ttl);
        dmn_assert(result->count_v4);
    }

    if(resource->addrs_v6) {
        rv &= resolve(threadnum, resource->addrs_v6, result, &cut_ttl);
        dmn_assert(result->count_v6);
    }

    if(cut_ttl)
        result->ttl >>= 1;

    return rv;
}
