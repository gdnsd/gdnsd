/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
 *
 * This file is part of gdnsd-plugin-geoip.
 *
 * gdnsd-plugin-geoip is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * gdnsd-plugin-geoip is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gdnsd.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// This source is a testing core for the gdmaps.c functionality,
//  to be re-used by the user-level gdnsd_geoip_test as well
//  as internal unit tests.
// It basically emulates a small portion of the initial setup code
//  from gdnsd, loading a real gdnsd config file, but only paying
//  attention to the plugin config and a few minor options bits.

#include "config.h"
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>

#include <gdnsd/dmn.h>
#include <gdnsd/log.h>
#include <gdnsd/vscf.h>
#include <gdnsd/plugapi.h>
#include <gdnsd/misc.h>

// be evil and use the private interface to set the cfdir,
//   since this is for test mocking and we're part of the main dist
#include "gdnsd/paths-priv.h"

#include "gdmaps.h"
#include "gdmaps_test.h"

static const vscf_data_t* conf_load_vscf(void) {
    const vscf_data_t* out = NULL;

    char* cfg_path = gdnsd_resolve_path_cfg("config", NULL);

    struct stat cfg_stat;
    if(!stat(cfg_path, &cfg_stat)) {
        log_debug("Loading configuration from '%s'", cfg_path);
        char* vscf_err;
        out = vscf_scan_filename(cfg_path, &vscf_err);
        if(!out)
            log_fatal("Configuration from '%s' failed: %s", cfg_path, vscf_err);
    }
    else {
        log_debug("No config file at '%s', using defaults + zones auto-scan", cfg_path);
    }

    free(cfg_path);
    return out;
}

static void conf_options(const vscf_data_t* cfg_root) {
    dmn_assert(cfg_root);

    // options stanza: set dmn_debug
    bool debug_tmp = false;
    const vscf_data_t* options = vscf_hash_get_data_byconstkey(cfg_root, "options", true);
    if(options) {
        if(!vscf_is_hash(options))
            log_fatal("Config stanza 'options' must be a hash");
        const vscf_data_t* debug_setting = vscf_hash_get_data_byconstkey(options, "debug", false);
        if(debug_setting
            && (!vscf_is_simple(debug_setting)
            || !vscf_simple_get_as_bool(debug_setting, &debug_tmp)))
                log_fatal("Config option 'debug': value must be 'true' or 'false'");
    }
    dmn_set_debug(debug_tmp);
}

F_NONNULL
static const vscf_data_t* conf_get_maps(const vscf_data_t* cfg_root) {
    dmn_assert(cfg_root);

    // plugins stanza
    const vscf_data_t* plugins = vscf_hash_get_data_byconstkey(cfg_root, "plugins", true);
    if(!plugins)
        log_fatal("Config file has no plugins stanza");
    if(!vscf_is_hash(plugins))
        log_fatal("Config stanza 'plugins' must be a hash");

    // plugins->geoip stanza
    const vscf_data_t* geoip = vscf_hash_get_data_byconstkey(plugins, "geoip", true);
    if(!geoip)
        log_fatal("Config file has no geoip plugin config");
    if(!vscf_is_hash(geoip))
        log_fatal("Plugin config for 'geoip' must be a hash");

    // plugins->geoip->maps stanza
    const vscf_data_t* maps = vscf_hash_get_data_byconstkey(geoip, "maps", true);
    if(!maps)
        log_fatal("Config file has no geoip maps defined");
    if(!vscf_is_hash(maps))
        log_fatal("Geoip plugin config for 'maps' must be a hash");

    return maps;
}

//***** Public funcs

void gdmaps_lookup_noop(const unsigned tnum, const gdmaps_t* gdmaps, const char* map_name, const char* addr_txt) {
    dmn_assert(gdmaps);
    dmn_assert(map_name);
    dmn_assert(addr_txt);

    log_info("Subtest %u starting", tnum);

    int map_idx = gdmaps_name2idx(gdmaps, map_name);
    if(map_idx < 0)
        log_fatal("Subtest %u failed: Map name '%s' not found in configuration", tnum, map_name);

    client_info_t cinfo;
    cinfo.edns_client_mask = 128U;
    unsigned scope = 175U;

    const int addr_err = gdnsd_anysin_getaddrinfo(addr_txt, NULL, &cinfo.edns_client);
    if(addr_err)
        log_fatal("Subtest %u failed: Cannot parse address '%s': %s", tnum, addr_txt, gai_strerror(addr_err));

    gdmaps_lookup(gdmaps, map_idx, &cinfo, &scope);
}

void gdmaps_test_lookup_check(const unsigned tnum, const gdmaps_t* gdmaps, const char* map_name, const char* addr_txt, const char* dclist_cmp, const unsigned scope_cmp) {
    dmn_assert(gdmaps);
    dmn_assert(map_name);
    dmn_assert(addr_txt);
    dmn_assert(dclist_cmp);

    log_info("Subtest %u starting", tnum);

    int map_idx = gdmaps_name2idx(gdmaps, map_name);
    if(map_idx < 0)
        log_fatal("Subtest %u failed: Map name '%s' not found in configuration", tnum, map_name);

    client_info_t cinfo;
    cinfo.edns_client_mask = 128U;
    unsigned scope = 175U;

    const int addr_err = gdnsd_anysin_getaddrinfo(addr_txt, NULL, &cinfo.edns_client);
    if(addr_err)
        log_fatal("Subtest %u failed: Cannot parse address '%s': %s", tnum, addr_txt, gai_strerror(addr_err));

    const uint8_t* dclist = gdmaps_lookup(gdmaps, map_idx, &cinfo, &scope);

    // w/ edns_client_mask set, scope_mask should *always* be set by gdmaps_lookup();
    // (and regardless, dclist should also always be set and contain something)
    if(!dclist)
        log_fatal("Subtest %u failed: gdmaps_lookup(%s, %s) returned NULL", tnum, map_name, addr_txt);
    if(scope == 175U)
        log_fatal("Subtest %u failed: gdmaps_lookup(%s, %s) failed to set the scope mask", tnum, map_name, addr_txt);

    if(strcmp((const char*)dclist, dclist_cmp))
        log_fatal("Subtest %u failed: Wanted dclist %s, got dclist %s", tnum,
            gdmaps_logf_dclist(gdmaps, map_idx, (const uint8_t*)dclist_cmp),
            gdmaps_logf_dclist(gdmaps, map_idx, dclist));

    if(scope != scope_cmp)
        log_fatal("Subtest %u failed: Wanted scope mask %u, got %u", tnum, scope_cmp, scope);
}

gdmaps_t* gdmaps_test_init(const char* input_rootdir) {

    dmn_init_log("gdmaps_test", true);

    gdnsd_set_rootdir(input_rootdir);
    const vscf_data_t* cfg_root = conf_load_vscf();
    conf_options(cfg_root);

    const vscf_data_t* maps_cfg = conf_get_maps(cfg_root);
    gdmaps_t* gdmaps = gdmaps_new(maps_cfg);
    vscf_destroy(cfg_root);

    gdmaps_load_databases(gdmaps);
    gdmaps_setup_watchers(gdmaps);

    return gdmaps;
}
