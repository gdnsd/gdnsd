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
#include "dnsio_udp.h"
#include "dnsio_tcp.h"
#include <gdnsd/alloc.h>
#include <gdnsd/misc.h>
#include <gdnsd/log.h>
#include <gdnsd/paths.h>
#include <gdnsd/paths-priv.h>
#include <gdnsd/plugapi-priv.h>
#include <gdnsd/mon-priv.h>

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

#include "main.h"

static const char DEF_USERNAME[] = PACKAGE_NAME;

// just needs 16-bit rdlen followed by TXT strings with length byte prefixes...
static const uint8_t chaos_prefix[] = "\xC0\x0C\x00\x10\x00\x03\x00\x00\x00\x00";
static const unsigned chaos_prefix_len = 10;
static const char chaos_def[] = "gdnsd";

// Global config, readonly after loaded from conf file
global_config_t gconfig = {
    .dns_addrs = NULL,
    .dns_threads = NULL,
    .http_addrs = NULL,
    .username = DEF_USERNAME,
    .chaos = NULL,
    .include_optional_ns = false,
    .realtime_stats = false,
    .lock_mem = false,
    .disable_text_autosplit = false,
    .edns_client_subnet = true,
    .zones_strict_data = false,
    .zones_strict_startup = true,
    .zones_rfc1035_auto = true,
    .chaos_len = 0,
     // legal values are -20 to 20, so -21
     //  is really just an indicator that the user
     //  didn't explicitly set it.  The default
     //  behavior is dynamic...
    .priority = -21,
    .zones_default_ttl = 86400U,
    .max_ncache_ttl = 10800U,
    .max_ttl = 3600000U,
    .min_ttl = 5U,
    .log_stats = 3600U,
    .max_http_clients = 128U,
    .http_timeout = 5U,
    .max_edns_response = 1410U,
    .num_dns_addrs = 0U,
    .num_dns_threads = 0U,
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
    uint8_t* combined = xmalloc(overall_len);
    memcpy(combined, chaos_prefix, chaos_prefix_len);
    combined[chaos_prefix_len] = 0;
    combined[chaos_prefix_len + 1] = dlen + 1;
    combined[chaos_prefix_len + 2] = dlen;
    memcpy(combined + chaos_prefix_len + 3, data, dlen);
    gconfig.chaos = combined;
    gconfig.chaos_len = overall_len;
}

static void plugins_cleanup(void) {
    gdnsd_plugins_action_exit();
}

// Generic iterator for catching bad config hash keys in various places below
F_NONNULL
static bool bad_key(const char* key, unsigned klen V_UNUSED, vscf_data_t* d V_UNUSED, const void* which_asvoid) {
    dmn_assert(key); dmn_assert(d); dmn_assert(which_asvoid);
    const char* which = which_asvoid;
    log_fatal("Invalid %s key '%s'", which, key);
}

static void make_addr(const char* lspec_txt, const unsigned def_port, dmn_anysin_t* result) {
    dmn_assert(result);
    const int addr_err = gdnsd_anysin_fromstr(lspec_txt, def_port, result);
    if(addr_err)
        log_fatal("Could not process listen-address spec '%s': %s", lspec_txt, gai_strerror(addr_err));
}

F_NONNULLX(1)
static void plugin_load_and_configure(const char* name, vscf_data_t* pconf) {
    dmn_assert(name);

    if(pconf && !vscf_is_hash(pconf))
        log_fatal("Config data for plugin '%s' must be a hash", name);

    plugin_t* plugin = gdnsd_plugin_find_or_load(name);
    if(plugin->load_config) {
        plugin->load_config(pconf, gconfig.num_dns_threads);
        plugin->config_loaded = true;
    }
}

F_NONNULLX(1,3)
static bool load_plugin_iter(const char* name, unsigned namelen V_UNUSED, vscf_data_t* pconf, void* data V_UNUSED) {
    dmn_assert(name); dmn_assert(pconf);
    plugin_load_and_configure(name, pconf);
    return true;
}

// These defines are for the repetitive case of simple checking/assignment
//  of certain types directly into simple gconfig variables

#define CFG_OPT_BOOL(_opt_set, _gconf_loc) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if(_opt_setting) { \
            if(!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_bool(_opt_setting, &gconfig._gconf_loc)) \
                log_fatal("Config option %s: Value must be 'true' or 'false'", #_gconf_loc); \
        } \
    } while(0)

#define CFG_OPT_BOOL_ALTSTORE(_opt_set, _gconf_loc, _store) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if(_opt_setting) { \
            if(!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_bool(_opt_setting, &_store)) \
                log_fatal("Config option %s: Value must be 'true' or 'false'", #_gconf_loc); \
        } \
    } while(0)

#define CFG_OPT_UINT(_opt_set, _gconf_loc, _min, _max) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
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

#define CFG_OPT_UINT_NOMIN(_opt_set, _gconf_loc, _max) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if(_opt_setting) { \
            unsigned long _val; \
            if(!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_ulong(_opt_setting, &_val)) \
                log_fatal("Config option %s: Value must be a positive integer", #_gconf_loc); \
            if(_val > _max) \
                log_fatal("Config option %s: Value out of range (0, %lu)", #_gconf_loc, _max); \
            gconfig._gconf_loc = (unsigned) _val; \
        } \
    } while(0)

#define CFG_OPT_DBL(_opt_set, _gconf_loc, _min, _max) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
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
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
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
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
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

#define CFG_OPT_UINT_ALTSTORE_NOMIN(_opt_set, _gconf_loc, _max, _store) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
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
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if(_opt_setting) { \
            if(!vscf_is_simple(_opt_setting)) \
                log_fatal("Config option %s: Wrong type (should be string)", #_gconf_loc); \
            gconfig._gconf_loc = strdup(vscf_simple_get_data(_opt_setting)); \
        } \
    } while(0)

#define CFG_OPT_STR_NOCOPY(_opt_set, _name, _store_at) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_name, true); \
        if(_opt_setting) { \
            if(!vscf_is_simple(_opt_setting)) \
                log_fatal("Config option %s: Wrong type (should be string)", #_name); \
            _store_at = vscf_simple_get_data(_opt_setting); \
        } \
    } while(0)

static void process_http_listen(vscf_data_t* http_listen_opt, const unsigned def_http_port) {
    if(!http_listen_opt || !vscf_array_get_len(http_listen_opt)) {
        gconfig.num_http_addrs = 2;
        gconfig.http_addrs = xcalloc(gconfig.num_http_addrs, sizeof(dmn_anysin_t));
        make_addr("0.0.0.0", def_http_port, gconfig.http_addrs);
        make_addr("::", def_http_port, &gconfig.http_addrs[1]);
    }
    else {
        gconfig.num_http_addrs = vscf_array_get_len(http_listen_opt);
        gconfig.http_addrs = xcalloc(gconfig.num_http_addrs, sizeof(dmn_anysin_t));
        for(unsigned i = 0; i < gconfig.num_http_addrs; i++) {
            vscf_data_t* lspec = vscf_array_get_data(http_listen_opt, i);
            if(!vscf_is_simple(lspec))
                log_fatal("Config option 'http_listen': all listen specs must be strings");
            make_addr(vscf_simple_get_data(lspec), def_http_port, &gconfig.http_addrs[i]);
        }
    }
}

F_NONNULL F_PURE
static bool dns_addr_is_dupe(const dmn_anysin_t* new_addr) {
    dmn_assert(new_addr);
    dmn_assert(new_addr->sa.sa_family == AF_INET6 || new_addr->sa.sa_family == AF_INET);

    for(unsigned i = 0; i < gconfig.num_dns_addrs; i++) {
        if(gconfig.dns_addrs[i].addr.sa.sa_family == new_addr->sa.sa_family) {
            dmn_assert(new_addr->len == gconfig.dns_addrs[i].addr.len);
            if(!memcmp(new_addr, &gconfig.dns_addrs[i].addr, new_addr->len))
                return true;
        }
    }

    return false;
}

static void dns_listen_any(const dns_addr_t* addr_defs) {
    dmn_assert(addr_defs);

    gconfig.num_dns_addrs = 2;
    gconfig.dns_addrs = xcalloc(gconfig.num_dns_addrs, sizeof(dns_addr_t));
    dns_addr_t* ac_v4 = &gconfig.dns_addrs[0];
    memcpy(ac_v4, addr_defs, sizeof(dns_addr_t));
    make_addr("0.0.0.0", addr_defs->dns_port, &ac_v4->addr);
    dns_addr_t* ac_v6 = &gconfig.dns_addrs[1];
    memcpy(ac_v6, addr_defs, sizeof(dns_addr_t));
    make_addr("::", addr_defs->dns_port, &ac_v6->addr);
}

static void dns_listen_scan(const dns_addr_t* addr_defs) {
    dmn_assert(addr_defs);

    dmn_anysin_t temp_asin;

    struct ifaddrs* ifap;
    if(getifaddrs(&ifap))
        dmn_log_fatal("getifaddrs() for 'listen => scan' failed: %s", dmn_logf_errno());

    gconfig.num_dns_addrs = 0;
    for(;ifap;ifap = ifap->ifa_next) {
        if(!ifap->ifa_addr)
            continue;

        if(ifap->ifa_addr->sa_family == AF_INET6) {
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

        if(dmn_anysin_is_anyaddr(&temp_asin))
            continue;

        if(temp_asin.sa.sa_family == AF_INET6)
            temp_asin.sin6.sin6_port = htons(addr_defs->dns_port);
        else
            temp_asin.sin.sin_port = htons(addr_defs->dns_port);

        if(dns_addr_is_dupe(&temp_asin))
            continue;

        gconfig.dns_addrs = xrealloc(gconfig.dns_addrs, (gconfig.num_dns_addrs + 1) * sizeof(dns_addr_t));
        dns_addr_t* addrconf = &gconfig.dns_addrs[gconfig.num_dns_addrs++];
        memcpy(addrconf, addr_defs, sizeof(dns_addr_t));
        memcpy(&addrconf->addr, &temp_asin, sizeof(dmn_anysin_t));
        addrconf->autoscan = true;
    }

    freeifaddrs(ifap);

    if(!gconfig.num_dns_addrs)
        dmn_log_fatal("automatic interface scanning via 'listen => scan' found no valid addresses to listen on");
}

static void fill_dns_addrs(vscf_data_t* listen_opt, const dns_addr_t* addr_defs) {
    dmn_assert(addr_defs);

    if(!listen_opt)
        return dns_listen_any(addr_defs);
    if(vscf_is_simple(listen_opt)) {
        const char* simple_str = vscf_simple_get_data(listen_opt);
        if(!strcmp(simple_str, "any")) {
            return dns_listen_any(addr_defs);
        }
        else if(!strcmp(simple_str, "scan")) {
            return dns_listen_scan(addr_defs);
        }
    }

    if(vscf_is_hash(listen_opt)) {
        gconfig.num_dns_addrs = vscf_hash_get_len(listen_opt);
        gconfig.dns_addrs = xcalloc(gconfig.num_dns_addrs, sizeof(dns_addr_t));
        for(unsigned i = 0; i < gconfig.num_dns_addrs; i++) {
            dns_addr_t* addrconf = &gconfig.dns_addrs[i];
            memcpy(addrconf, addr_defs, sizeof(dns_addr_t));
            const char* lspec = vscf_hash_get_key_byindex(listen_opt, i, NULL);
            vscf_data_t* addr_opts = vscf_hash_get_data_byindex(listen_opt, i);
            if(!vscf_is_hash(addr_opts))
                log_fatal("DNS listen address '%s': per-address options must be a hash", lspec);

            CFG_OPT_UINT_ALTSTORE(addr_opts, udp_recv_width, 1LU, 64LU, addrconf->udp_recv_width);
            CFG_OPT_UINT_ALTSTORE(addr_opts, udp_rcvbuf, 4096LU, 1048576LU, addrconf->udp_rcvbuf);
            CFG_OPT_UINT_ALTSTORE(addr_opts, udp_sndbuf, 4096LU, 1048576LU, addrconf->udp_sndbuf);
            CFG_OPT_UINT_ALTSTORE_NOMIN(addr_opts, udp_threads, 1024LU, addrconf->udp_threads);

            CFG_OPT_UINT_ALTSTORE(addr_opts, tcp_clients_per_thread, 1LU, 65535LU, addrconf->tcp_clients_per_thread);
            CFG_OPT_UINT_ALTSTORE(addr_opts, tcp_timeout, 3LU, 60LU, addrconf->tcp_timeout);
            CFG_OPT_UINT_ALTSTORE_NOMIN(addr_opts, tcp_threads, 1024LU, addrconf->tcp_threads);

            if(!gdnsd_reuseport_ok()) {
                if(addrconf->udp_threads > 1) {
                    log_warn("DNS listen address '%s': option 'udp_threads' was reduced from the configured value of %u to 1 for lack of SO_REUSEPORT support", lspec, addrconf->udp_threads);
                    addrconf->udp_threads = 1;
                }
                if(addrconf->tcp_threads > 1) {
                    log_warn("DNS listen address '%s': option 'tcp_threads' was reduced from the configured value of %u to 1 for lack of SO_REUSEPORT support", lspec, addrconf->tcp_threads);
                    addrconf->tcp_threads = 1;
                }
            }

            make_addr(lspec, addrconf->dns_port, &addrconf->addr);
            vscf_hash_iterate_const(addr_opts, true, bad_key, "per-address listen option");
        }
    }
    else {
        gconfig.num_dns_addrs = vscf_array_get_len(listen_opt);
        gconfig.dns_addrs = xcalloc(gconfig.num_dns_addrs, sizeof(dns_addr_t));
        for(unsigned i = 0; i < gconfig.num_dns_addrs; i++) {
            dns_addr_t* addrconf = &gconfig.dns_addrs[i];
            memcpy(addrconf, addr_defs, sizeof(dns_addr_t));
            vscf_data_t* lspec = vscf_array_get_data(listen_opt, i);
            if(!vscf_is_simple(lspec))
                log_fatal("Config option 'listen': all listen specs must be strings");
            make_addr(vscf_simple_get_data(lspec), addr_defs->dns_port, &addrconf->addr);
        }
    }
}

static void process_listen(vscf_data_t* listen_opt, const dns_addr_t* addr_defs) {
    // this fills in gconfig.dns_addrs raw data
    fill_dns_addrs(listen_opt, addr_defs);

    if(!gconfig.num_dns_addrs)
        dmn_log_fatal("DNS listen addresses explicitly configured as an empty set - cannot continue without at least one address!");

    // use dns_addrs to populate dns_threads....

    gconfig.num_dns_threads = 0;
    for(unsigned i = 0; i < gconfig.num_dns_addrs; i++)
        gconfig.num_dns_threads += (gconfig.dns_addrs[i].udp_threads + gconfig.dns_addrs[i].tcp_threads);

    if(!gconfig.num_dns_threads)
        dmn_log_fatal("All listen addresses configured for zero UDP and zero TCP threads - cannot continue without at least one listener!");

    gconfig.dns_threads = xcalloc(gconfig.num_dns_threads, sizeof(dns_thread_t));

    unsigned tnum = 0;
    for(unsigned i = 0; i < gconfig.num_dns_addrs; i++) {
        dns_addr_t* a = &gconfig.dns_addrs[i];
        for(unsigned j = 0; j < a->udp_threads; j++) {
            dns_thread_t* t = &gconfig.dns_threads[tnum];
            t->ac = a;
            t->is_udp = true;
            t->threadnum = tnum++;
        }
        for(unsigned j = 0; j < a->tcp_threads; j++) {
            dns_thread_t* t = &gconfig.dns_threads[tnum];
            t->ac = a;
            t->is_udp = false;
            t->threadnum = tnum++;
        }
        if(!(a->udp_threads + a->tcp_threads))
            dmn_log_warn("DNS listen address %s explicitly configured with no UDP or TCP threads - nothing is actually listening on this address!",
                dmn_logf_anysin(&a->addr));
        else
            dmn_log_info("DNS listener threads (%u UDP + %u TCP) configured for %s",
                a->udp_threads, a->tcp_threads, dmn_logf_anysin(&a->addr));
    }

    dmn_assert(tnum == gconfig.num_dns_threads);
}

static vscf_data_t* conf_load_vscf(const char* cfg_file) {
    vscf_data_t* out = NULL;

    struct stat cfg_stat;
    if(!stat(cfg_file, &cfg_stat)) {
        log_info("Loading configuration from '%s'", cfg_file);
        char* vscf_err;
        out = vscf_scan_filename(cfg_file, &vscf_err);
        if(!out)
            log_fatal("Loading configuration from '%s' failed: %s", cfg_file, vscf_err);
        if(!vscf_is_hash(out)) {
            dmn_assert(vscf_is_array(out));
            log_fatal("Config file '%s' cannot be an '[ array ]' at the top level", cfg_file);
        }
    }
    else {
        log_info("No config file at '%s', using defaults", cfg_file);
    }

    return out;
}

void conf_load(const char* cfg_dir, const bool force_zss, const bool force_zsd, const conf_mode_t cmode) {

    gdnsd_set_config_dir(cfg_dir);
    char* cfg_file = gdnsd_resolve_path_cfg("config", NULL);
    vscf_data_t* cfg_root = conf_load_vscf(cfg_file);
    free(cfg_file);

#ifndef NDEBUG
    // in developer debug builds, exercise clone+destroy
    if(cfg_root) {
        vscf_data_t* temp_cfg = vscf_clone(cfg_root, false);
        vscf_destroy(cfg_root);
        cfg_root = temp_cfg;
    }
#endif

    dmn_assert(!cfg_root || vscf_is_hash(cfg_root));

    vscf_data_t* options = cfg_root ? vscf_hash_get_data_byconstkey(cfg_root, "options", true) : NULL;

    // daemon actions only need the rundir, so we process dirs first and bail
    //   early in those cases without doing the rest of the complex stuff
    {
        const char* cfg_run_dir = NULL;
        const char* cfg_state_dir = NULL;
        if(options) {
            if(!vscf_is_hash(options))
                log_fatal("Config key 'options': wrong type (must be hash)");
            CFG_OPT_STR_NOCOPY(options, run_dir, cfg_run_dir);
            CFG_OPT_STR_NOCOPY(options, state_dir, cfg_state_dir);
        }

        // only ask set_dirs to check/create run/state dirs if we're starting, as opposed
        // to stop/status/reload-zones (CONF_SIMPLE_ACTION) or checkconf (CONF_CHECK)
        gdnsd_set_runtime_dirs(cfg_run_dir, cfg_state_dir, cmode == CONF_START);
    }

    // fast-path exit for simple actions like stop/status/reload-zones, only
    //   needs run_dir configuration and nothing more
    if(cmode == CONF_SIMPLE_ACTION)
        return;

    vscf_data_t* listen_opt = NULL;
    vscf_data_t* http_listen_opt = NULL;
    vscf_data_t* psearch_array = NULL;
    const char* chaos_data = chaos_def;
    unsigned def_http_port = 3506U;

    dns_addr_t addr_defs = {
        .autoscan = false,
        .dns_port = 53U,
        .udp_recv_width = 8U,
        .udp_rcvbuf = 0U,
        .udp_sndbuf = 0U,
        .udp_threads = 1U,
        .tcp_clients_per_thread = 128U,
        .tcp_timeout = 5U,
        .tcp_threads = 1U,
    };

    if(options) {
        CFG_OPT_INT(options, priority, -20L, 20L);
        CFG_OPT_BOOL(options, include_optional_ns);
        CFG_OPT_BOOL(options, realtime_stats);
        CFG_OPT_BOOL(options, lock_mem);
        CFG_OPT_BOOL(options, disable_text_autosplit);
        CFG_OPT_BOOL(options, edns_client_subnet);
        CFG_OPT_UINT_NOMIN(options, log_stats, 86400LU);
        CFG_OPT_UINT(options, max_http_clients, 1LU, 65535LU);
        CFG_OPT_UINT(options, http_timeout, 3LU, 60LU);

        CFG_OPT_UINT_ALTSTORE(options, dns_port, 1LU, 65535LU, addr_defs.dns_port);
        CFG_OPT_UINT_ALTSTORE(options, udp_recv_width, 1LU, 64LU, addr_defs.udp_recv_width);
        CFG_OPT_UINT_ALTSTORE(options, udp_rcvbuf, 4096LU, 1048576LU, addr_defs.udp_rcvbuf);
        CFG_OPT_UINT_ALTSTORE(options, udp_sndbuf, 4096LU, 1048576LU, addr_defs.udp_sndbuf);
        CFG_OPT_UINT_ALTSTORE_NOMIN(options, udp_threads, 1024LU, addr_defs.udp_threads);
        CFG_OPT_UINT_ALTSTORE(options, tcp_timeout, 3LU, 60LU, addr_defs.tcp_timeout);

        CFG_OPT_UINT_ALTSTORE(options, tcp_clients_per_thread, 1LU, 65535LU, addr_defs.tcp_clients_per_thread);
        CFG_OPT_UINT_ALTSTORE_NOMIN(options, tcp_threads, 1024LU, addr_defs.tcp_threads);

        if(!gdnsd_reuseport_ok()) {
            if(addr_defs.udp_threads > 1) {
                log_warn("The global option 'udp_threads' was reduced from the configured value of %u to 1 for lack of SO_REUSEPORT support", addr_defs.udp_threads);
                addr_defs.udp_threads = 1;
            }
            if(addr_defs.tcp_threads > 1) {
                log_warn("The global option 'tcp_threads' was reduced from the configured value of %u to 1 for lack of SO_REUSEPORT support", addr_defs.tcp_threads);
                addr_defs.tcp_threads = 1;
            }
        }

        CFG_OPT_UINT_ALTSTORE(options, http_port, 1LU, 65535LU, def_http_port);
        CFG_OPT_UINT(options, zones_default_ttl, 1LU, 2147483647LU);
        CFG_OPT_UINT(options, min_ttl, 1LU, 86400LU);
        CFG_OPT_UINT(options, max_ttl, 3600LU, (unsigned long)GDNSD_STTL_TTL_MAX);
        if(gconfig.max_ttl < gconfig.min_ttl)
            log_fatal("The global option 'max_ttl' (%u) cannot be smaller than 'min_ttl' (%u)", gconfig.max_ttl, gconfig.min_ttl);
        CFG_OPT_UINT(options, max_ncache_ttl, 10LU, 86400LU);
        if(gconfig.max_ncache_ttl < gconfig.min_ttl)
            log_fatal("The global option 'max_ncache_ttl' (%u) cannot be smaller than 'min_ttl' (%u)", gconfig.max_ncache_ttl, gconfig.min_ttl);
        CFG_OPT_UINT(options, max_response, 4096LU, 64000LU);
        CFG_OPT_UINT(options, max_edns_response, 512LU, 64000LU);
        if(gconfig.max_edns_response > gconfig.max_response) {
            log_warn("The global option 'max_edns_response' was reduced from %u to the max_response size of %u", gconfig.max_edns_response, gconfig.max_response);
            gconfig.max_edns_response = gconfig.max_response;
        }
        // Limit here (24) is critical, to ensure that when encode_rr_cname resets
        //  c->qname_comp in dnspacket.c, c->qname_comp must still be <16K into a packet.
        // Nobody should have even the default 16-depth CNAMEs anyways :P
        CFG_OPT_UINT(options, max_cname_depth, 4LU, 24LU);
        CFG_OPT_UINT(options, max_addtl_rrsets, 16LU, 256LU);
        CFG_OPT_BOOL(options, zones_strict_data);
        CFG_OPT_BOOL(options, zones_strict_startup);
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
        vscf_hash_iterate_const(options, true, bad_key, "options");
    }

    // if cmdline forced, override any default or config setting
    if(force_zss)
        gconfig.zones_strict_startup = true;
    if(force_zsd)
        gconfig.zones_strict_data = true;

    // set response string for CHAOS queries
    set_chaos(chaos_data);

    // Set up the http listener data
    process_http_listen(http_listen_opt, def_http_port);

    // Initial setup of the listener data
    process_listen(listen_opt, &addr_defs);

    vscf_data_t* stypes_cfg = cfg_root
        ? vscf_hash_get_data_byconstkey(cfg_root, "service_types", true)
        : NULL;

    // setup plugin searching...
    gdnsd_plugins_set_search_path(psearch_array);

    // Phase 1 of service_types config
    gdnsd_mon_cfg_stypes_p1(stypes_cfg);

    // Load plugins
    vscf_data_t* plugins_hash = cfg_root ? vscf_hash_get_data_byconstkey(cfg_root, "plugins", true) : NULL;
    if(plugins_hash) {
        if(!vscf_is_hash(plugins_hash))
            log_fatal("Config setting 'plugins' must have a hash value");
        // plugin_geoip is considered a special-case meta-plugin.  If it's present,
        //   it always gets loaded before others.  This is because it can create
        //   resource config for other plugins.  This is a poor way to do it, but I imagine
        //   the list of meta-plugins will remain short and in-tree.
        vscf_data_t* geoplug = vscf_hash_get_data_byconstkey(plugins_hash, "geoip", true);
        if(geoplug)
            plugin_load_and_configure("geoip", geoplug);
        // ditto for "metafo"
        // Technically, geoip->metafo synthesis will work, but not metafo->geoip synthesis.
        // Both can reference each other directly (%plugin!resource)
        vscf_data_t* metaplug = vscf_hash_get_data_byconstkey(plugins_hash, "metafo", true);
        if(metaplug)
            plugin_load_and_configure("metafo", metaplug);
        vscf_hash_iterate(plugins_hash, true, load_plugin_iter, NULL);
    }

    // Any plugins loaded via the plugins hash above will already have had load_config() called
    //   on them.  This calls it (with a NULL config hash argument) for any plugins that were
    //   loaded only via service_types (in gdnsd_mon_cfg_stypes_p1() above) without an explicit config.
    // Because of the possibility of mixed plugins and the configuration ordering above for
    //    meta-plugins, this must happen at this sequential point (after plugins_hash processing,
    //    but before stypes_p2())
    gdnsd_plugins_configure_all(gconfig.num_dns_threads);

    // Phase 2 of service_types config
    gdnsd_mon_cfg_stypes_p2(stypes_cfg);

    // register a hook for plugin cleanup callbacks
    gdnsd_atexit_debug(plugins_cleanup);

    // Throw an error if there are any other unretrieved root config keys
    if(cfg_root) {
        vscf_hash_iterate_const(cfg_root, true, bad_key, "top-level config");
        vscf_destroy(cfg_root);
    }
}

void dns_lsock_init(void) {
    for(unsigned i = 0; i < gconfig.num_dns_threads; i++) {
        dns_thread_t* t = &gconfig.dns_threads[i];
        if(t->is_udp)
            udp_sock_setup(t);
        else
            tcp_dns_listen_setup(t);
    }
}
