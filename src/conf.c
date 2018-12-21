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
#include "conf.h"

#include "main.h"
#include "socks.h"
#include "cookie.h"

#include "plugins/mon.h"
#include <gdnsd/alloc.h>
#include <gdnsd/misc.h>
#include <gdnsd/log.h>
#include "plugins/plugapi.h"

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

// Global config, read-only
const cfg_t* gcfg = NULL;

// just needs 16-bit rdlen followed by TXT strings with length byte prefixes...
static const uint8_t chaos_prefix[] = "\xC0\x0C\x00\x10\x00\x03\x00\x00\x00\x00";
#define chaos_prefix_len 10U
static const char chaos_def[] = "gdnsd/3";

static const cfg_t cfg_defaults = {
    .chaos = NULL,
    .nsid = NULL,
    .cookie_key_file = NULL,
    .lock_mem = false,
    .disable_text_autosplit = false,
    .edns_client_subnet = true,
    .zones_strict_data = false,
    .disable_cookies = false,
    .max_nocookie_response = 0,
    .chaos_len = 0,
    .nsid_len = 0,
    .zones_default_ttl = 86400U,
    .max_ncache_ttl = 10800U,
    .max_ttl = 3600000U,
    .min_ttl = 5U,
    .max_edns_response = 1410U,
    .max_edns_response_v6 = 1212U,
    .acme_challenge_ttl = 600U,
};

F_NONNULL
static void set_chaos(cfg_t* cfg, const char* data)
{
    const unsigned dlen = strlen(data);
    if (dlen > 254)
        log_fatal("Option 'chaos_response' must be a string less than 255 characters long");

    const unsigned overall_len = chaos_prefix_len + 3 + dlen;
    uint8_t* combined = xmalloc(overall_len);
    memcpy(combined, chaos_prefix, chaos_prefix_len);
    combined[chaos_prefix_len] = 0;
    combined[chaos_prefix_len + 1] = dlen + 1;
    combined[chaos_prefix_len + 2] = dlen;
    memcpy(combined + chaos_prefix_len + 3, data, dlen);
    cfg->chaos = combined;
    cfg->chaos_len = overall_len;
}

static const uint8_t ahex[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
    0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
    0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, // @ABCDEFG
};

F_NONNULL
static void set_nsid(cfg_t* cfg, const char* data)
{
    const unsigned dlen = strlen(data);
    if (!dlen || dlen > 256U || dlen & 1U || dlen != strspn(data, "0123456789ABCDEFabcdef"))
        log_fatal("Option 'nsid' must be a hex string up to 256 characters (128 encoded bytes) long");
    cfg->nsid_len = dlen >> 1U;
    uint8_t* nsid;
    cfg->nsid = nsid = xmalloc(cfg->nsid_len);
    for (unsigned i = 0; i < dlen; i += 2)
        nsid[i >> 1] = (ahex[(data[i] & 0x1F) ^ 0x10] << 4)
                       | ahex[(data[i + 1] & 0x1F) ^ 0x10];
}

F_NONNULL
static void set_nsid_ascii(cfg_t* cfg, const char* data)
{
    const unsigned dlen = strlen(data);
    bool fail = false;
    if (!dlen || dlen > 128U) {
        fail = true;
    } else {
        for (size_t i = 0; i < dlen; i++)
            if (data[i] < 0x20 || data[i] > 0x7E)
                fail = true;
    }
    if (fail)
        log_fatal("Option 'nsid_ascii' must be a string of printable ASCII characters up to 128 bytes long");
    cfg->nsid_len = dlen;
    cfg->nsid = (uint8_t*)xstrdup(data);
}

// Generic iterator for catching bad config hash keys in various places below
F_NONNULL
static bool bad_key(const char* key, unsigned klen V_UNUSED, vscf_data_t* d V_UNUSED, const void* which_asvoid)
{
    const char* which = which_asvoid;
    log_fatal("Invalid %s key '%s'", which, key);
}

F_NONNULLX(2)
static void plugin_configure(const unsigned num_dns_threads, const char* name, vscf_data_t* pconf)
{
    if (pconf && !vscf_is_hash(pconf))
        log_fatal("Config data for plugin '%s' must be a hash", name);

    plugin_t* plugin = gdnsd_plugin_find(name);
    if (plugin->load_config) {
        plugin->load_config(pconf, num_dns_threads);
        plugin->config_loaded = true;
    }
}

F_NONNULL
static bool cfg_plugin_iter(const char* name, unsigned namelen V_UNUSED, vscf_data_t* pconf, const void* scfg_asvoid)
{
    const socks_cfg_t* socks_cfg = scfg_asvoid;
    plugin_configure(socks_cfg->num_dns_threads, name, pconf);
    return true;
}

// These defines are for the repetitive case of simple checking/assignment
//  of certain types directly into simple cfg variables

#define CFG_OPT_BOOL(_opt_set, _gconf_loc) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if (_opt_setting) { \
            if (!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_bool(_opt_setting, &cfg->_gconf_loc)) \
                log_fatal("Config option %s: Value must be 'true' or 'false'", #_gconf_loc); \
        } \
    } while (0)

#define CFG_OPT_UINT(_opt_set, _gconf_loc, _min, _max) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if (_opt_setting) { \
            unsigned long _val; \
            if (!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_ulong(_opt_setting, &_val)) \
                log_fatal("Config option %s: Value must be a positive integer", #_gconf_loc); \
            if (_val < _min || _val > _max) \
                log_fatal("Config option %s: Value out of range (%lu, %lu)", #_gconf_loc, _min, _max); \
            cfg->_gconf_loc = (unsigned) _val; \
        } \
    } while (0)

#define CFG_OPT_UINT_NOMIN(_opt_set, _gconf_loc, _max) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if (_opt_setting) { \
            unsigned long _val; \
            if (!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_ulong(_opt_setting, &_val)) \
                log_fatal("Config option %s: Value must be a positive integer", #_gconf_loc); \
            if (_val > _max) \
                log_fatal("Config option %s: Value out of range (0, %lu)", #_gconf_loc, _max); \
            cfg->_gconf_loc = (unsigned) _val; \
        } \
    } while (0)

#define CFG_OPT_DBL(_opt_set, _gconf_loc, _min, _max) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if (_opt_setting) { \
            double _val; \
            if (!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_double(_opt_setting, &_val)) \
                log_fatal("Config option %s: Value must be a valid floating-point number", #_gconf_loc); \
            if (_val < _min || _val > _max) \
                log_fatal("Config option %s: Value out of range (%.3g, %.3g)", #_gconf_loc, _min, _max); \
            cfg->_gconf_loc = _val; \
        } \
    } while (0)

#define CFG_OPT_INT(_opt_set, _gconf_loc, _min, _max) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if (_opt_setting) { \
            long _val; \
            if (!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_long(_opt_setting, &_val)) \
                log_fatal("Config option %s: Value must be an integer", #_gconf_loc); \
            if (_val < _min || _val > _max) \
                log_fatal("Config option %s: Value out of range (%li, %li)", #_gconf_loc, _min, _max); \
            cfg->_gconf_loc = (int) _val; \
        } \
    } while (0)

#define CFG_OPT_STR(_opt_set, _gconf_loc) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if (_opt_setting) { \
            if (!vscf_is_simple(_opt_setting)) \
                log_fatal("Config option %s: Wrong type (should be string)", #_gconf_loc); \
            cfg->_gconf_loc = xstrdup(vscf_simple_get_data(_opt_setting)); \
        } \
    } while (0)

#define CFG_OPT_STR_NOCOPY(_opt_set, _name, _store_at) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_name, true); \
        if (_opt_setting) { \
            if (!vscf_is_simple(_opt_setting)) \
                log_fatal("Config option %s: Wrong type (should be string)", #_name); \
            _store_at = vscf_simple_get_data(_opt_setting); \
        } \
    } while (0)

#define CFG_OPT_REMOVED(_opt_set, _gconf_loc) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if (_opt_setting) \
            log_warn("Config option %s is no longer supported, and will become a syntax error in a future major version upgrade", #_gconf_loc); \
    } while (0)


cfg_t* conf_load(const vscf_data_t* cfg_root, const socks_cfg_t* socks_cfg, const bool force_zsd)
{
    gdnsd_assert(!cfg_root || vscf_is_hash(cfg_root));

    cfg_t* cfg = xmalloc(sizeof(*cfg));
    memcpy(cfg, &cfg_defaults, sizeof(*cfg));

    const char* chaos_data = chaos_def;
    const char* nsid_data = NULL;
    const char* nsid_data_ascii = NULL;

    vscf_data_t* options = cfg_root ? vscf_hash_get_data_byconstkey(cfg_root, "options", true) : NULL;
    if (options) {
        CFG_OPT_REMOVED(options, username);
        CFG_OPT_REMOVED(options, weaker_security);
        CFG_OPT_REMOVED(options, include_optional_ns);
        CFG_OPT_REMOVED(options, realtime_stats);
        CFG_OPT_REMOVED(options, zones_strict_startup);
        CFG_OPT_REMOVED(options, zones_rfc1035_auto);
        CFG_OPT_REMOVED(options, any_mitigation);
        CFG_OPT_REMOVED(options, priority);
        CFG_OPT_REMOVED(options, log_stats);
        CFG_OPT_REMOVED(options, max_response);
        CFG_OPT_REMOVED(options, max_cname_depth);
        CFG_OPT_REMOVED(options, max_addtl_rrsets);
        CFG_OPT_REMOVED(options, zones_rfc1035_auto_interval);
        CFG_OPT_REMOVED(options, zones_rfc1035_quiesce);
        CFG_OPT_REMOVED(options, http_listen);
        CFG_OPT_REMOVED(options, max_http_clients);
        CFG_OPT_REMOVED(options, http_timeout);
        CFG_OPT_REMOVED(options, http_port);
        CFG_OPT_REMOVED(options, plugin_search_path);

        CFG_OPT_BOOL(options, lock_mem);
        CFG_OPT_BOOL(options, disable_text_autosplit);
        CFG_OPT_BOOL(options, edns_client_subnet);
        CFG_OPT_UINT(options, zones_default_ttl, 1LU, 2147483647LU);
        CFG_OPT_UINT(options, min_ttl, 1LU, 86400LU);
        CFG_OPT_UINT(options, max_ttl, 3600LU, (unsigned long)GDNSD_STTL_TTL_MAX);
        if (cfg->max_ttl < cfg->min_ttl)
            log_fatal("The global option 'max_ttl' (%u) cannot be smaller than 'min_ttl' (%u)", cfg->max_ttl, cfg->min_ttl);
        CFG_OPT_UINT(options, max_ncache_ttl, 10LU, 86400LU);
        if (cfg->max_ncache_ttl < cfg->min_ttl)
            log_fatal("The global option 'max_ncache_ttl' (%u) cannot be smaller than 'min_ttl' (%u)", cfg->max_ncache_ttl, cfg->min_ttl);
        CFG_OPT_UINT(options, max_edns_response, 512LU, 16384LU);
        CFG_OPT_UINT(options, max_edns_response_v6, 512LU, 16384LU);
        CFG_OPT_UINT(options, acme_challenge_ttl, 60LU, 3600LU);
        CFG_OPT_BOOL(options, zones_strict_data);
        CFG_OPT_BOOL(options, disable_cookies);
        CFG_OPT_UINT_NOMIN(options, max_nocookie_response, 1024LU);
        if (cfg->max_nocookie_response && cfg->max_nocookie_response < 128U)
            log_fatal("The global option 'max_nocookie_response' (%u) must be zero, or in the range 128 - 1024", cfg->max_nocookie_response);
        CFG_OPT_STR(options, cookie_key_file);

        CFG_OPT_STR_NOCOPY(options, chaos_response, chaos_data);
        CFG_OPT_STR_NOCOPY(options, nsid, nsid_data);
        CFG_OPT_STR_NOCOPY(options, nsid_ascii, nsid_data_ascii);
        vscf_hash_iterate_const(options, true, bad_key, "options");
    }

    // if cmdline forced, override any default or config setting
    if (force_zsd)
        cfg->zones_strict_data = true;

    // set response string for CHAOS queries
    set_chaos(cfg, chaos_data);

    // set nsid if set
    if (nsid_data && nsid_data_ascii)
        log_fatal("Only one of 'nsid_ascii' or 'nsid' can be set");
    if (nsid_data)
        set_nsid(cfg, nsid_data);
    if (nsid_data_ascii)
        set_nsid_ascii(cfg, nsid_data_ascii);

    vscf_data_t* stypes_cfg = cfg_root
                              ? vscf_hash_get_data_byconstkey(cfg_root, "service_types", true)
                              : NULL;

    // Phase 1 of service_types config
    gdnsd_mon_cfg_stypes_p1(stypes_cfg);

    // Load plugins
    vscf_data_t* plugins_hash = cfg_root ? vscf_hash_get_data_byconstkey(cfg_root, "plugins", true) : NULL;
    if (plugins_hash) {
        if (!vscf_is_hash(plugins_hash))
            log_fatal("Config setting 'plugins' must have a hash value");
        // plugin_geoip is considered a special-case meta-plugin.  If it's present,
        //   it always gets loaded before others.  This is because it can create
        //   resource config for other plugins.  This is a poor way to do it, but I imagine
        //   the list of meta-plugins will remain short and in-tree.
        vscf_data_t* geoplug = vscf_hash_get_data_byconstkey(plugins_hash, "geoip", true);
        if (geoplug)
            plugin_configure(socks_cfg->num_dns_threads, "geoip", geoplug);
        // ditto for "metafo"
        // Technically, geoip->metafo synthesis will work, but not metafo->geoip synthesis.
        // Both can reference each other directly (%plugin!resource)
        vscf_data_t* metaplug = vscf_hash_get_data_byconstkey(plugins_hash, "metafo", true);
        if (metaplug)
            plugin_configure(socks_cfg->num_dns_threads, "metafo", metaplug);
        vscf_hash_iterate_const(plugins_hash, true, cfg_plugin_iter, socks_cfg);
    }

    // Any plugins loaded via the plugins hash above will already have had load_config() called
    //   on them.  This calls it (with a NULL config hash argument) for any plugins that were
    //   loaded only via service_types (in gdnsd_mon_cfg_stypes_p1() above) without an explicit config.
    // Because of the possibility of mixed plugins and the configuration ordering above for
    //    meta-plugins, this must happen at this sequential point (after plugins_hash processing,
    //    but before stypes_p2())
    gdnsd_plugins_configure_all(socks_cfg->num_dns_threads);

    // Phase 2 of service_types config
    gdnsd_mon_cfg_stypes_p2(stypes_cfg);

    // Throw an error if there are any other unretrieved root config keys
    if (cfg_root)
        vscf_hash_iterate_const(cfg_root, true, bad_key, "top-level config");

    // admin_state checking, can fail fatally
    gdnsd_mon_check_admin_file();

    return cfg;
}
