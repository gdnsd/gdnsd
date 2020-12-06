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
#include "dnswire.h"

#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

enum res_which {
    A_PRI = 0,
    A_SEC = 1
};

enum as_af {
    A_AUTO = 0,
    A_IPv4 = 1,
    A_IPv6 = 2,
};

static const char* which_str[2] = {
    "primary",
    "secondary"
};

struct addrstate {
    struct anysin addrs[2];
    unsigned num_svcs;
    unsigned* indices[2];
};

struct res {
    const char* name;
    struct addrstate* addrs_v4;
    struct addrstate* addrs_v6;
};

static struct res* resources = NULL;
static unsigned num_resources = 0;

static const char DEFAULT_SVCNAME[] = "up";

/*********************************/
/* Local, static functions       */
/*********************************/

F_NONNULL noreturn
static bool bad_res_opt(const char* key, unsigned klen V_UNUSED, vscf_data_t* d V_UNUSED, const void* resname_asvoid)
{
    const char* resname = resname_asvoid;
    log_fatal("plugin_simplefo: resource '%s': bad option '%s'", resname, key);
}

F_NONNULL
static enum as_af config_addrs(struct addrstate* as, enum as_af as_af, const char* resname, const char* stanza, vscf_data_t* cfg)
{
    unsigned num_svcs = 0;
    const char** svc_names = NULL;
    vscf_data_t* svctypes_data = vscf_hash_get_data_byconstkey(cfg, "service_types", true);
    if (svctypes_data) {
        num_svcs = vscf_array_get_len(svctypes_data);
        if (num_svcs) {
            svc_names = xmalloc_n(num_svcs, sizeof(*svc_names));
            for (unsigned i = 0; i < num_svcs; i++) {
                vscf_data_t* svctype_cfg = vscf_array_get_data(svctypes_data, i);
                if (!vscf_is_simple(svctype_cfg))
                    log_fatal("plugin_simplefo: resource %s (%s): 'service_types' value(s) must be strings", resname, stanza);
                svc_names[i] = vscf_simple_get_data(svctype_cfg);
            }
        }
    } else {
        num_svcs = 1;
        svc_names = xmalloc(sizeof(*svc_names));
        svc_names[0] = DEFAULT_SVCNAME;
    }

    as->num_svcs = num_svcs;

    const enum res_which both[2] = { A_PRI, A_SEC };
    for (unsigned i = 0; i < 2; i++) {
        enum res_which which = both[i];
        vscf_data_t* addrcfg = vscf_hash_get_data_bystringkey(cfg, which_str[which], true);
        if (!addrcfg || !vscf_is_simple(addrcfg))
            log_fatal("plugin_simplefo: resource %s (%s): '%s' must be defined as an IP address string", resname, stanza, which_str[which]);
        const char* addr_txt = vscf_simple_get_data(addrcfg);
        int addr_err = gdnsd_anysin_getaddrinfo(addr_txt, NULL, &as->addrs[which]);
        if (addr_err)
            log_fatal("plugin_simplefo: resource %s: parsing '%s' as an IP address failed: %s", resname, addr_txt, gai_strerror(addr_err));

        const bool ipv6 = as->addrs[which].sa.sa_family == AF_INET6;
        if (as_af == A_IPv6 && !ipv6)
            log_fatal("plugin_simplefo: resource %s (%s): '%s' is not an IPv6 address", resname, stanza, addr_txt);
        else if (as_af == A_IPv4 && ipv6)
            log_fatal("plugin_simplefo: resource %s (%s): '%s' is not an IPv4 address", resname, stanza, addr_txt);

        if (num_svcs) {
            as->indices[which] = xmalloc_n(num_svcs, sizeof(*as->indices[which]));
            for (unsigned j = 0; j < num_svcs; j++)
                as->indices[which][j] = gdnsd_mon_addr(svc_names[j], &as->addrs[which]);
        }
    }

    free(svc_names);

    if (as_af == A_AUTO) {
        if (as->addrs[A_PRI].sa.sa_family != as->addrs[A_SEC].sa.sa_family)
            log_fatal("plugin_simplefo: resource %s (%s): primary and secondary must be same address family (IPv4 or IPv6)", resname, stanza);
        return as->addrs[A_PRI].sa.sa_family == AF_INET6 ? A_IPv6 : A_IPv4;
    }

    vscf_hash_iterate_const(cfg, true, bad_res_opt, resname);

    return as_af;
}

static bool config_res(const char* resname, unsigned resname_len V_UNUSED, vscf_data_t* opts, void* data)
{
    unsigned* residx_ptr = data;
    unsigned rnum = *residx_ptr;
    (*residx_ptr)++;
    struct res* res = &resources[rnum];
    res->name = xstrdup(resname);

    if (!vscf_is_hash(opts))
        log_fatal("plugin_simplefo: resource %s: value must be a hash", resname);

    vscf_hash_bequeath_all(opts, "service_types", true, false);

    vscf_data_t* addrs_v4_cfg = vscf_hash_get_data_byconstkey(opts, "addrs_v4", true);
    vscf_data_t* addrs_v6_cfg = vscf_hash_get_data_byconstkey(opts, "addrs_v6", true);
    if (!addrs_v4_cfg && !addrs_v6_cfg) {
        struct addrstate* as = xmalloc(sizeof(*as));
        enum as_af which = config_addrs(as, A_AUTO, resname, "direct", opts);
        if (which == A_IPv4) {
            res->addrs_v4 = as;
        } else {
            gdnsd_assume(which == A_IPv6);
            res->addrs_v6 = as;
        }
    } else {
        if (addrs_v4_cfg) {
            if (!vscf_is_hash(addrs_v4_cfg))
                log_fatal("plugin_simplefo: resource %s: The value of 'addrs_v4', if defined, must be a hash", resname);
            struct addrstate* as = xmalloc(sizeof(*as));
            res->addrs_v4 = as;
            config_addrs(as, A_IPv4, resname, "addrs_v4", addrs_v4_cfg);
        }
        if (addrs_v6_cfg) {
            if (!vscf_is_hash(addrs_v6_cfg))
                log_fatal("plugin_simplefo: resource %s: The value of 'addrs_v6', if defined, must be a hash", resname);
            struct addrstate* as = xmalloc(sizeof(*as));
            res->addrs_v6 = as;
            config_addrs(as, A_IPv6, resname, "addrs_v6", addrs_v6_cfg);
        }
    }

    vscf_hash_iterate_const(opts, true, bad_res_opt, resname);
    return true;
}

/*********************************/
/* Exported callbacks start here */
/*********************************/

static void plugin_simplefo_load_config(vscf_data_t* config)
{
    if (!config)
        log_fatal("simplefo plugin requires a 'plugins' configuration stanza");

    gdnsd_assert(vscf_is_hash(config));

    num_resources = vscf_hash_get_len(config);

    // send service_types to either "resources" or the direct resources
    if (vscf_hash_bequeath_all(config, "service_types", true, false))
        num_resources--; // don't count parameter keys

    if (num_resources) {
        resources = xcalloc_n(num_resources, sizeof(*resources));
        unsigned residx = 0;
        vscf_hash_iterate(config, true, config_res, &residx);
        gdnsd_dyn_addr_max(1, 1); // simplefo only returns one address per family
    }
}

static int plugin_simplefo_map_res(const char* resname, const uint8_t* zone_name)
{
    if (resname) {
        if (zone_name) {
            log_err("plugin_simplefo: resource %s used from zone %s: DYNC cannot point to resources which can return IP address results!", resname, logf_dname(zone_name));
            return -1;
        }
        for (unsigned i = 0; i < num_resources; i++)
            if (!strcmp(resname, resources[i].name))
                return (int)i;
        log_err("plugin_simplefo: Unknown resource '%s'", resname);
    } else {
        log_err("plugin_simplfo: resource name required");
    }

    return -1;
}

// ---state chart-------------
// p    s    ttl      which fail_upstream?
// up   *    p        pri   no
// down up   min(p,s) sec   no
// down down s        pri   yes
// ----------------------------
F_NONNULL
static gdnsd_sttl_t resolve_addr(const gdnsd_sttl_t* sttl_tbl, const struct addrstate* as, struct dyn_result* result)
{
    const gdnsd_sttl_t p_sttl = gdnsd_sttl_min(sttl_tbl, as->indices[A_PRI], as->num_svcs);

    enum res_which which = A_PRI;

    gdnsd_sttl_t sttl_out;
    if (p_sttl & GDNSD_STTL_DOWN) {
        const gdnsd_sttl_t s_sttl = gdnsd_sttl_min(sttl_tbl, as->indices[A_SEC], as->num_svcs);
        if (s_sttl & GDNSD_STTL_DOWN) {
            // both are down...
            sttl_out = s_sttl;
        } else {
            // p is down, s is up...
            which = A_SEC;
            const unsigned p_ttl = p_sttl & GDNSD_STTL_TTL_MASK;
            sttl_out = s_sttl & GDNSD_STTL_TTL_MASK;
            if (p_ttl < sttl_out)
                sttl_out = p_ttl;
        }
    } else {
        // p is up, s is dontcare
        sttl_out = p_sttl;
    }

    gdnsd_result_add_anysin(result, &as->addrs[which]);
    assert_valid_sttl(sttl_out);
    return sttl_out;
}

static gdnsd_sttl_t plugin_simplefo_resolve(unsigned resnum, const unsigned qtype, const struct client_info* cinfo V_UNUSED, struct dyn_result* result)
{
    struct res* res = &resources[resnum];

    const gdnsd_sttl_t* sttl_tbl = gdnsd_mon_get_sttl_table();

    gdnsd_sttl_t rv = GDNSD_STTL_TTL_MAX;

    if (qtype == DNS_TYPE_A && res->addrs_v4)
        rv = resolve_addr(sttl_tbl, res->addrs_v4, result);
    else if (qtype == DNS_TYPE_AAAA && res->addrs_v6)
        rv = resolve_addr(sttl_tbl, res->addrs_v6, result);

    assert_valid_sttl(rv);
    return rv;
}

struct plugin plugin_simplefo_funcs = {
    .name = "simplefo",
    .config_loaded = false,
    .used = false,
    .load_config = plugin_simplefo_load_config,
    .map_res = plugin_simplefo_map_res,
    .pre_run = NULL,
    .iothread_init = NULL,
    .iothread_cleanup = NULL,
    .resolve = plugin_simplefo_resolve,
    .add_svctype = NULL,
    .add_mon_addr = NULL,
    .add_mon_cname = NULL,
    .init_monitors = NULL,
    .start_monitors = NULL,
};
