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

#include "conf.h"
#include "monio.h"
#include "dnsio_udp.h"
#include "dnsio_tcp.h"
#include "gdnsd/misc.h"
#include "gdnsd/log.h"
#include "gdnsd/paths.h"
#include "gdnsd/plugapi-priv.h"

#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <netinet/in.h>

static unsigned num_mon_lists = 0;
static mon_list_t** mon_lists = NULL;

static const char DEF_USERNAME[] = PACKAGE_NAME;

// just needs 16-bit rdlen followed by TXT strings with length byte prefixes...
static const uint8_t chaos_prefix[] = "\xC0\x0C\x00\x10\x00\x03\x00\x00\x00\x00";
static const unsigned chaos_prefix_len = 10;
static const char chaos_def[] = "gdnsd";

// Global config, readonly after loaded from conf file
global_config_t gconfig = {
    .dns_addrs = NULL,
    .http_addrs = NULL,
    .username = DEF_USERNAME,
    .chaos = NULL,
    .include_optional_ns = false,
    .realtime_stats = false,
    .lock_mem = false,
    .disable_text_autosplit = false,
    .edns_client_subnet = true,
    .monitor_force_v6_up = false,
    .zones_rfc1035_strict_startup = true,
    .zones_rfc1035_auto = true,
    .chaos_len = 0,
     // legal values are -20 to 20, so -21
     //  is really just an indicator that the user
     //  didn't explicitly set it.  The default
     //  behavior is dynamic...
    .priority = -21,
    .zones_default_ttl = 86400U,
    .log_stats = 3600U,
    .max_http_clients = 128U,
    .http_timeout = 5U,
    .num_dns_addrs = 0U,
    .num_http_addrs = 0U,
    .max_response = 16384U,
    .max_cname_depth = 16U,
    .max_addtl_rrsets = 64U,
    .zones_rfc1035_auto_interval = 31U,
    .zones_rfc1035_quiesce = 5.0,
    .zones_rfc1035_min_quiesce = 0.0,
};

F_NONNULL
static void set_chaos(const char* data) {
    dmn_assert(data);

    const unsigned dlen = strlen(data);
    if(dlen > 254)
        log_fatal("Option 'chaos_response' must be a string less than 255 characters long");

    const unsigned overall_len = chaos_prefix_len + 3 + dlen;
    char* combined = malloc(overall_len);
    memcpy(combined, chaos_prefix, chaos_prefix_len);
    combined[chaos_prefix_len] = 0;
    combined[chaos_prefix_len + 1] = dlen + 1;
    combined[chaos_prefix_len + 2] = dlen;
    memcpy(combined + chaos_prefix_len + 3, data, dlen);
    gconfig.chaos = (const uint8_t*)combined;
    gconfig.chaos_len = overall_len;
}

static void plugins_cleanup(void) {
    gdnsd_plugins_action_exit();
}

// Generic iterator for catching bad config hash keys in various places below
F_NONNULL
static bool bad_key(const char* key, unsigned klen V_UNUSED, const vscf_data_t* d V_UNUSED, void* data) {
    dmn_assert(data); dmn_assert(key);
    log_fatal("Invalid %s key '%s'", (const char*)data, key);
}

static void make_addr(const char* lspec_txt, const unsigned def_port, anysin_t* result) {
    dmn_assert(result);
    const int addr_err = gdnsd_anysin_fromstr(lspec_txt, def_port, result);
    if(addr_err)
        log_fatal("Could not process listen-address spec '%s': %s", lspec_txt, gai_strerror(addr_err));
}

F_NONNULLX(1)
static void plugin_load_and_configure(const char* name, const vscf_data_t* pconf) {
    dmn_assert(name);

    if(pconf && !vscf_is_hash(pconf))
        log_fatal("Config data for plugin '%s' must be a hash", name);

    if(!strcmp(name, "georeg"))
        log_fatal("plugin_georeg is DEAD, use the included plugin_geoip instead");

    const plugin_t* plugin = gdnsd_plugin_load(name);
    if(plugin->load_config) {
        mon_list_t* mlist = plugin->load_config(pconf);
        if(mlist) {
            for(unsigned i = 0; i < mlist->count; i++) {
                mon_info_t* m = &mlist->info[i];
                if(!m->desc)
                    log_fatal("Plugin '%s' bug: mon_info_t.desc is required", plugin->name);
                if(!m->addr)
                    log_fatal("Plugin '%s' bug: '%s' mon_info_t.addr is required", plugin->name, m->desc);
                if(!m->state_ptr)
                    log_fatal("Plugin '%s' bug: '%s' mon_info_t.state_ptr is required", plugin->name, m->desc);
            }
            const unsigned this_monio_idx = num_mon_lists++;
            mon_lists = realloc(mon_lists, num_mon_lists * sizeof(mon_list_t*));
            mon_lists[this_monio_idx] = mlist;
        }
    }
}

F_NONNULLX(1,3)
static bool load_plugin_iter(const char* name, unsigned namelen V_UNUSED, const vscf_data_t* pconf, void* data V_UNUSED) {
    dmn_assert(name); dmn_assert(pconf);
    plugin_load_and_configure(name, pconf);
    return true;
}

// These defines are for the repetitive case of simple checking/assignment
//  of certain types directly into simple gconfig variables

#define CFG_OPT_BOOL(_opt_set, _gconf_loc) \
    do { \
        const vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if(_opt_setting) { \
            if(!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_bool(_opt_setting, &gconfig._gconf_loc)) \
                log_fatal("Config option %s: Value must be 'true' or 'false'", #_gconf_loc); \
        } \
    } while(0)

#define CFG_OPT_BOOL_ALTSTORE(_opt_set, _gconf_loc, _store) \
    do { \
        const vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if(_opt_setting) { \
            if(!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_bool(_opt_setting, &_store)) \
                log_fatal("Config option %s: Value must be 'true' or 'false'", #_gconf_loc); \
        } \
    } while(0)

#define CFG_OPT_UINT(_opt_set, _gconf_loc, _min, _max) \
    do { \
        const vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if(_opt_setting) { \
            unsigned long _val; \
            if(!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_ulong(_opt_setting, &_val)) \
                log_fatal("Config option %s: Value must be a positive integer", #_gconf_loc); \
            if(_val < _min || _val > _max) \
                log_fatal("Config option %s: Value out of range (%lu, %lu)", #_gconf_loc, _min, _max); \
            gconfig._gconf_loc = (unsigned) _val; \
        } \
    } while(0)

#define CFG_OPT_DBL(_opt_set, _gconf_loc, _min, _max) \
    do { \
        const vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if(_opt_setting) { \
            double _val; \
            if(!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_double(_opt_setting, &_val)) \
                log_fatal("Config option %s: Value must be a valid floating-point number", #_gconf_loc); \
            if(_val < _min || _val > _max) \
                log_fatal("Config option %s: Value out of range (%.3g, %.3g)", #_gconf_loc, _min, _max); \
            gconfig._gconf_loc = _val; \
        } \
    } while(0)

#define CFG_OPT_INT(_opt_set, _gconf_loc, _min, _max) \
    do { \
        const vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if(_opt_setting) { \
            long _val; \
            if(!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_long(_opt_setting, &_val)) \
                log_fatal("Config option %s: Value must be an integer", #_gconf_loc); \
            if(_val < _min || _val > _max) \
                log_fatal("Config option %s: Value out of range (%li, %li)", #_gconf_loc, _min, _max); \
            gconfig._gconf_loc = (int) _val; \
        } \
    } while(0)

#define CFG_OPT_UINT_ALTSTORE(_opt_set, _gconf_loc, _min, _max, _store) \
    do { \
        const vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if(_opt_setting) { \
            unsigned long _val; \
            if(!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_ulong(_opt_setting, &_val)) \
                log_fatal("Config option %s: Value must be a positive integer", #_gconf_loc); \
            if(_val < _min || _val > _max) \
                log_fatal("Config option %s: Value out of range (%lu, %lu)", #_gconf_loc, _min, _max); \
            _store = (unsigned) _val; \
        } \
    } while(0)

#define CFG_OPT_UINT_ALTSTORE_0MIN(_opt_set, _gconf_loc, _max, _store) \
    do { \
        const vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if(_opt_setting) { \
            unsigned long _val; \
            if(!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_ulong(_opt_setting, &_val)) \
                log_fatal("Config option %s: Value must be a positive integer", #_gconf_loc); \
            if(_val > _max) \
                log_fatal("Config option %s: Value out of range (0, %lu)", #_gconf_loc, _max); \
            _store = (unsigned) _val; \
        } \
    } while(0)

#define CFG_OPT_STR(_opt_set, _gconf_loc) \
    do { \
        const vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if(_opt_setting) { \
            if(!vscf_is_simple(_opt_setting)) \
                log_fatal("Config option %s: Wrong type (should be string)", #_gconf_loc); \
            gconfig._gconf_loc = strdup(vscf_simple_get_data(_opt_setting)); \
        } \
    } while(0)

#define CFG_OPT_STR_NOCOPY(_opt_set, _name, _store_at) \
    do { \
        const vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_name, true); \
        if(_opt_setting) { \
            if(!vscf_is_simple(_opt_setting)) \
                log_fatal("Config option %s: Wrong type (should be string)", #_name); \
            _store_at = vscf_simple_get_data(_opt_setting); \
        } \
    } while(0)

static void process_http_listen(const vscf_data_t* http_listen_opt, const unsigned def_http_port) {
    if(!http_listen_opt || !vscf_array_get_len(http_listen_opt)) {
        const bool has_v6 = gdnsd_tcp_v6_ok();
        gconfig.num_http_addrs = has_v6 ? 2 : 1;
        gconfig.http_addrs = calloc(gconfig.num_http_addrs, sizeof(anysin_t));
        make_addr("0.0.0.0", def_http_port, gconfig.http_addrs);
        if(has_v6) make_addr("::", def_http_port, &gconfig.http_addrs[1]);
    }
    else {
        gconfig.num_http_addrs = vscf_array_get_len(http_listen_opt);
        gconfig.http_addrs = calloc(gconfig.num_http_addrs, sizeof(anysin_t));
        for(unsigned i = 0; i < gconfig.num_http_addrs; i++) {
            const vscf_data_t* lspec = vscf_array_get_data(http_listen_opt, i);
            if(!vscf_is_simple(lspec))
                log_fatal("Config option 'http_listen': all listen specs must be strings");
            make_addr(vscf_simple_get_data(lspec), def_http_port, &gconfig.http_addrs[i]);
        }
    }
}

F_NONNULL
static bool dns_addr_is_dupe(const anysin_t* new_addr) {
    dmn_assert(new_addr);
    dmn_assert(new_addr->sa.sa_family == AF_INET6 || new_addr->sa.sa_family == AF_INET);

    for(unsigned i = 0; i < gconfig.num_dns_addrs; i++)
        if(gconfig.dns_addrs[i].addr.sa.sa_family == new_addr->sa.sa_family)
            if(!memcmp(new_addr, &gconfig.dns_addrs[i].addr, new_addr->len))
                return true;

    return false;
}

static void process_listen(const vscf_data_t* listen_opt, const unsigned def_dns_port, const unsigned def_tcp_cps, const unsigned def_tcp_to, const bool def_tcp_disabled, const unsigned def_udp_recv_width, const unsigned def_udp_rcvbuf, const unsigned def_udp_sndbuf, const unsigned def_late_bind_secs) {

    anysin_t temp_asin;

    if(!listen_opt || !vscf_array_get_len(listen_opt)) {
        const bool has_v6 = gdnsd_tcp_v6_ok();
        bool v6_warned = false;

        struct ifaddrs* ifap;
        if(getifaddrs(&ifap))
            dmn_log_fatal("getifaddrs() for defaulted DNS listeners failed: %s", logf_errno());

        gconfig.num_dns_addrs = 0;
        for(;ifap;ifap = ifap->ifa_next) {
            if(!ifap->ifa_addr)
                continue;

            if(ifap->ifa_addr->sa_family == AF_INET6) {
                if(!has_v6) {
                    if(!v6_warned) {
                        dmn_log_info("Default interface-scanning (no explicit listen-address config) on this host detected one or more IPv6 interfaces, but IPv6 appears to be non-functional on this host in general, so they will be ignored...");
                        v6_warned = true;
                    }
                    continue;
                }
                memcpy(&temp_asin.sin6, ifap->ifa_addr, sizeof(struct sockaddr_in6));
                temp_asin.len = sizeof(struct sockaddr_in6);
            }
            else if(ifap->ifa_addr->sa_family == AF_INET) {
                memcpy(&temp_asin.sin, ifap->ifa_addr, sizeof(struct sockaddr_in));
                temp_asin.len = sizeof(struct sockaddr_in);
            }
            else { // unknown family...
                continue;
            }

            if(gdnsd_anysin_is_anyaddr(&temp_asin))
                continue;

            if(temp_asin.sa.sa_family == AF_INET6)
                temp_asin.sin6.sin6_port = htons(def_dns_port);
            else
                temp_asin.sin.sin_port = htons(def_dns_port);

            if(dns_addr_is_dupe(&temp_asin))
                continue;

            gconfig.dns_addrs = realloc(gconfig.dns_addrs, (gconfig.num_dns_addrs + 1) * sizeof(dns_addr_t));
            dns_addr_t* addrconf = &gconfig.dns_addrs[gconfig.num_dns_addrs++];

            memset(addrconf, 0, sizeof(dns_addr_t));
            memcpy(&addrconf->addr, &temp_asin, sizeof(anysin_t));

            addrconf->tcp_clients_per_socket = def_tcp_cps;
            addrconf->tcp_timeout = def_tcp_to;
            addrconf->tcp_disabled = def_tcp_disabled;
            addrconf->udp_recv_width = def_udp_recv_width;
            addrconf->udp_rcvbuf = def_udp_rcvbuf;
            addrconf->udp_sndbuf = def_udp_sndbuf;
            addrconf->late_bind_secs = def_late_bind_secs;
            addrconf->autoscan = true;
            dmn_log_info("DNS listener configured by default interface scanning for %s", logf_anysin(&addrconf->addr));
        }

        if(!gconfig.num_dns_addrs)
            dmn_log_fatal("No valid IP interfaces found to listen on!");

        freeifaddrs(ifap);
    }
    else {
        if(vscf_is_hash(listen_opt)) {
            gconfig.num_dns_addrs = vscf_hash_get_len(listen_opt);
            gconfig.dns_addrs = calloc(gconfig.num_dns_addrs, sizeof(dns_addr_t));
            for(unsigned i = 0; i < gconfig.num_dns_addrs; i++) {
                dns_addr_t* addrconf = &gconfig.dns_addrs[i];
                addrconf->tcp_clients_per_socket = def_tcp_cps;
                addrconf->tcp_timeout = def_tcp_to;
                addrconf->tcp_disabled = def_tcp_disabled;
                addrconf->udp_recv_width = def_udp_recv_width;
                addrconf->udp_rcvbuf = def_udp_rcvbuf;
                addrconf->udp_sndbuf = def_udp_sndbuf;
                const char* lspec = vscf_hash_get_key_byindex(listen_opt, i, NULL);
                const vscf_data_t* addr_opts = vscf_hash_get_data_byindex(listen_opt, i);
                if(!vscf_is_hash(addr_opts))
                    log_fatal("per-address options for listen address '%s' must be a hash", lspec);

                CFG_OPT_UINT_ALTSTORE(addr_opts, tcp_clients_per_socket, 1LU, 65535LU, addrconf->tcp_clients_per_socket);
                CFG_OPT_UINT_ALTSTORE(addr_opts, tcp_timeout, 3LU, 60LU, addrconf->tcp_timeout);
                CFG_OPT_BOOL_ALTSTORE(addr_opts, disable_tcp, addrconf->tcp_disabled);
                CFG_OPT_UINT_ALTSTORE(addr_opts, udp_recv_width, 1LU, 32LU, addrconf->udp_recv_width);
                CFG_OPT_UINT_ALTSTORE(addr_opts, udp_rcvbuf, 4096LU, 1048576LU, addrconf->udp_rcvbuf);
                CFG_OPT_UINT_ALTSTORE(addr_opts, udp_sndbuf, 4096LU, 1048576LU, addrconf->udp_sndbuf);
                CFG_OPT_UINT_ALTSTORE_0MIN(addr_opts, late_bind_secs, 300LU, addrconf->late_bind_secs);
                make_addr(lspec, def_dns_port, &addrconf->addr);
                vscf_hash_iterate(addr_opts, true, bad_key, (void*)"per-address listen option");
                dmn_log_info("DNS listener configured for %s", logf_anysin(&addrconf->addr));
            }
        }
        else {
            gconfig.num_dns_addrs = vscf_array_get_len(listen_opt);
            gconfig.dns_addrs = calloc(gconfig.num_dns_addrs, sizeof(dns_addr_t));
            for(unsigned i = 0; i < gconfig.num_dns_addrs; i++) {
                dns_addr_t* addrconf = &gconfig.dns_addrs[i];
                addrconf->tcp_clients_per_socket = def_tcp_cps;
                addrconf->tcp_timeout = def_tcp_to;
                addrconf->tcp_disabled = def_tcp_disabled;
                addrconf->udp_recv_width = def_udp_recv_width;
                addrconf->udp_rcvbuf = def_udp_rcvbuf;
                addrconf->udp_sndbuf = def_udp_sndbuf;
                addrconf->late_bind_secs = def_late_bind_secs;
                const vscf_data_t* lspec = vscf_array_get_data(listen_opt, i);
                if(!vscf_is_simple(lspec))
                    log_fatal("Config option 'listen': all listen specs must be strings");
                make_addr(vscf_simple_get_data(lspec), def_dns_port, &addrconf->addr);
                dmn_log_info("DNS listener configured for %s", logf_anysin(&addrconf->addr));
            }
        }
    }
}

static void assign_thread_nums(void) {
    unsigned tnum = 0;
    unsigned addr_ct = gconfig.num_dns_addrs;

    for(unsigned i = 0; i < addr_ct; i++)
        gconfig.dns_addrs[i].udp_threadnum = tnum++;

    for(unsigned i = 0; i < addr_ct; i++)
        if(!gconfig.dns_addrs[i].tcp_disabled)
            gconfig.dns_addrs[i].tcp_threadnum = tnum++;

    gconfig.num_io_threads = tnum;
}

static const vscf_data_t* conf_load_vscf(void) {
    const vscf_data_t* out = NULL;

    char* cfg_path = gdnsd_resolve_path_cfg("config", NULL);

    struct stat cfg_stat;
    if(!stat(cfg_path, &cfg_stat)) {
        log_info("Loading configuration from '%s'", cfg_path);
        char* vscf_err;
        out = vscf_scan_filename(cfg_path, &vscf_err);
        if(!out)
            log_fatal("Loading configuration from '%s' failed: %s", cfg_path, vscf_err);
        if(!vscf_is_hash(out)) {
            dmn_assert(vscf_is_array(out));
            log_fatal("Config file '%s' cannot be an '[ array ]' at the top level", cfg_path);
        }
    }
    else {
        log_info("No config file at '%s', using defaults", cfg_path);
    }

    free(cfg_path);
    return out;
}

void conf_load(void) {

    const vscf_data_t* cfg_root = conf_load_vscf();

#ifndef NDEBUG
    // in developer debug builds, exercise clone+destroy
    if(cfg_root) {
        const vscf_data_t* temp_cfg = vscf_clone(cfg_root, false);
        vscf_destroy(cfg_root);
        cfg_root = temp_cfg;
    }
#endif

    dmn_assert(!cfg_root || vscf_is_hash(cfg_root));

    const vscf_data_t* options = cfg_root ? vscf_hash_get_data_byconstkey(cfg_root, "options", true) : NULL;

    const vscf_data_t* listen_opt = NULL;
    const vscf_data_t* http_listen_opt = NULL;
    const vscf_data_t* psearch_array = NULL;
    const char* chaos_data = chaos_def;
    unsigned def_dns_port = 53U;
    unsigned def_http_port = 3506U;
    unsigned def_tcp_cps = 128U;
    unsigned def_tcp_to = 5U;
    unsigned def_udp_recv_width = 8U;
    unsigned def_udp_rcvbuf = 0U;
    unsigned def_udp_sndbuf = 0U;
    unsigned def_late_bind_secs = 0U;
    bool def_tcp_disabled = false;
    bool debug_tmp = false;

    if(options) {
        if(!vscf_is_hash(options))
            log_fatal("Config key 'options': wrong type (must be hash)");
        CFG_OPT_BOOL_ALTSTORE(options, debug, debug_tmp);
        dmn_set_debug(debug_tmp);
        CFG_OPT_INT(options, priority, -20L, 20L);
        CFG_OPT_BOOL(options, include_optional_ns);
        CFG_OPT_BOOL(options, realtime_stats);
        CFG_OPT_BOOL(options, lock_mem);
        CFG_OPT_BOOL(options, disable_text_autosplit);
        CFG_OPT_BOOL(options, edns_client_subnet);
        CFG_OPT_BOOL(options, monitor_force_v6_up);
        CFG_OPT_UINT(options, log_stats, 1LU, 2147483647LU);
        CFG_OPT_UINT(options, max_http_clients, 1LU, 65535LU);
        CFG_OPT_UINT(options, http_timeout, 3LU, 60LU);
        CFG_OPT_UINT_ALTSTORE_0MIN(options, late_bind_secs, 300LU, def_late_bind_secs);
        CFG_OPT_UINT_ALTSTORE(options, tcp_clients_per_socket, 1LU, 65535LU, def_tcp_cps);
        CFG_OPT_UINT_ALTSTORE(options, tcp_timeout, 3LU, 60LU, def_tcp_to);
        CFG_OPT_BOOL_ALTSTORE(options, disable_tcp, def_tcp_disabled);
        CFG_OPT_UINT_ALTSTORE(options, udp_recv_width, 1LU, 64LU, def_udp_recv_width);
        CFG_OPT_UINT_ALTSTORE(options, udp_rcvbuf, 4096LU, 1048576LU, def_udp_rcvbuf);
        CFG_OPT_UINT_ALTSTORE(options, udp_sndbuf, 4096LU, 1048576LU, def_udp_sndbuf);
        CFG_OPT_UINT_ALTSTORE(options, dns_port, 1LU, 65535LU, def_dns_port);
        CFG_OPT_UINT_ALTSTORE(options, http_port, 1LU, 65535LU, def_http_port);
        CFG_OPT_UINT(options, zones_default_ttl, 1LU, 2147483647LU);
        CFG_OPT_UINT(options, max_response, 4096LU, 64000LU);
        // Limit here (24) is critical, to ensure that when encode_rr_cname resets
        //  c->qname_comp in dnspacket.c, c->qname_comp must still be <16K into a packet.
        // Nobody should have even the default 16-depth CNAMEs anyways :P
        CFG_OPT_UINT(options, max_cname_depth, 4LU, 24LU);
        CFG_OPT_UINT(options, max_addtl_rrsets, 16LU, 256LU);
        CFG_OPT_BOOL(options, zones_rfc1035_strict_startup);
        CFG_OPT_BOOL(options, zones_rfc1035_auto);
        // it's important that auto_interval is never lower than 2s, or it could cause
        //   us to miss fast events on filesystems with 1-second mtime resolution.
        CFG_OPT_UINT(options, zones_rfc1035_auto_interval, 10LU, 600LU);
        CFG_OPT_DBL(options, zones_rfc1035_min_quiesce, 0.0, 5.0);
        CFG_OPT_DBL(options, zones_rfc1035_quiesce, 0.0, 60.0);
        CFG_OPT_STR(options, username);
        CFG_OPT_STR_NOCOPY(options, chaos_response, chaos_data);
        listen_opt = vscf_hash_get_data_byconstkey(options, "listen", true);
        http_listen_opt = vscf_hash_get_data_byconstkey(options, "http_listen", true);
        psearch_array = vscf_hash_get_data_byconstkey(options, "plugin_search_path", true);
        vscf_hash_iterate(options, true, bad_key, (void*)"options");
    }

    // set response string for CHAOS queries
    set_chaos(chaos_data);

    // Set up the http listener data
    process_http_listen(http_listen_opt, def_http_port);

    // Initial setup of the listener data, modding the per-key num_socks as it goes and referencing them in the dnsaddr_t's
    process_listen(listen_opt, def_dns_port, def_tcp_cps, def_tcp_to, def_tcp_disabled, def_udp_recv_width, def_udp_rcvbuf, def_udp_sndbuf, def_late_bind_secs);

    // Assign globally unique thread numbers for each socket-handling thread
    assign_thread_nums();

    gdnsd_plugins_set_search_path(psearch_array);

    // Load plugins
    const vscf_data_t* plugins_hash = cfg_root ? vscf_hash_get_data_byconstkey(cfg_root, "plugins", true) : NULL;
    if(plugins_hash) {
        if(!vscf_is_hash(plugins_hash))
            log_fatal("Config setting 'plugins' must have a hash value");
        // plugin_geoip is considered a special-case meta-plugin.  If it's present,
        //   it always gets loaded before others.  This is because it can create
        //   resource config for other plugins.  This is a poor way to do it, but I imagine
        //   the list of meta-plugins will remain short and in-tree.
        const vscf_data_t* geoplug = vscf_hash_get_data_byconstkey(plugins_hash, "geoip", true);
        if(geoplug)
            plugin_load_and_configure("geoip", geoplug);
        // ditto for "metafo"
        // Technically, geoip->metafo synthesis will work, but not metafo->geoip synthesis.
        // Both can reference each other directly (%plugin!resource)
        const vscf_data_t* metaplug = vscf_hash_get_data_byconstkey(plugins_hash, "metafo", true);
        if(metaplug)
            plugin_load_and_configure("metafo", metaplug);
        vscf_hash_iterate(plugins_hash, true, load_plugin_iter, NULL);
    }

    // Create servicetypes, which may reference already-loaded plugins, or autoload new ones
    // We only do this if we've actually got resources to monitor, because otherwise plugin_search_path
    //   might have to be correct unnecessarily, and it also avoids the unnecessary load of http_status
    //   and other work.  A consequence is that the service_types config stanza is not checked for
    //   syntax errors unless monitoring is actually in use.
    const vscf_data_t* stypes_cfg = cfg_root
        ? vscf_hash_get_data_byconstkey(cfg_root, "service_types", true)
        : NULL;
    if(num_mon_lists)
        monio_add_servicetypes(stypes_cfg);

    // Finally, process the mon_list_t's from plugins *after* servicetypes are available.
    // This order of operations wrt loading the plugins stanza, then the servicetypes,
    //   and then finally doing deferred processing of mon_list_t's from all plugin
    //   _load_config()s gaurantees things like having a single plugin take on both roles
    //   actually works, even with autoloaded plugins.
    // Technically, we could even allow autoloading of address/cname-resolving plugins as
    //   as well, assumming they needed no config at the plugin-global level, and it will
    //   actually happen in the case of an autoloaded dual-purpose module with no global
    //   plugins-stanza config.  It's not worth trying to explcitily support it in other
    //   cases though because (a) it will lead to a crash with older address/cname-only
    //   plugins that don't expect a NULL config argument, and (b) most addr/cname plugins
    //   are going to need *some* kind of config anyways.
    if(atexit(plugins_cleanup))
        log_fatal("atexit(plugins_cleanup) failed: %s", logf_errno());
    for(unsigned i = 0; i < num_mon_lists; i++) {
        mon_list_t* mlist = mon_lists[i];
        if(mlist) {
            for(unsigned j = 0; j < mlist->count; j++) {
                mon_info_t* m = &mlist->info[j];
                dmn_assert(m->desc && m->addr && m->state_ptr);
                monio_add_addr(m->svctype, m->desc, m->addr, m->state_ptr);
            }
        }
    }

    // Throw an error if there are any other unretrieved root config keys
    if(cfg_root) {
        vscf_hash_iterate(cfg_root, true, bad_key, (void*)"top-level config");
        vscf_destroy(cfg_root);
    }
}

bool dns_lsock_init(void) {
    bool need_caps = false;
    const unsigned num_addrs = gconfig.num_dns_addrs;
    for(unsigned i = 0; i < num_addrs; i++) {
        dns_addr_t* addrconf = &gconfig.dns_addrs[i];
        if(udp_sock_setup(addrconf))
            need_caps = true;
        if(!addrconf->tcp_disabled)
            if(tcp_dns_listen_setup(addrconf))
                need_caps = true;
    }

    return need_caps;
}
