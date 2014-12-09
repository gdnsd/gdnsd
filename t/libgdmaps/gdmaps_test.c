/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
 *
 * This file is part of gdnsd.
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

#include <config.h>
#include "gdmaps_test.h"

#include <gdnsd/dmn.h>
#include <gdnsd/log.h>
#include <gdnsd/vscf.h>
#include <gdnsd/paths.h>

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <tap.h>

void gdmaps_test_lookup_noop(const gdmaps_t* gdmaps, const char* map_name, const char* addr_txt) {
    dmn_assert(gdmaps);
    dmn_assert(map_name);
    dmn_assert(addr_txt);

    const int rv = gdmaps_name2idx(gdmaps, map_name);
    if(rv < 0)
        log_fatal("Map name '%s' not found in configuration", map_name);
    const unsigned map_idx = (unsigned)rv;

    client_info_t cinfo;
    cinfo.edns_client_mask = 128U;
    unsigned scope = 175U;

    const int addr_err = gdnsd_anysin_getaddrinfo(addr_txt, NULL, &cinfo.edns_client);
    if(addr_err)
        log_fatal("Cannot parse address '%s': %s", addr_txt, gai_strerror(addr_err));

    gdmaps_lookup(gdmaps, map_idx, &cinfo, &scope);
    ok(1, "gdmaps_lookup(%s, %s) did not crash", map_name, addr_txt);
}

void gdmaps_test_lookup_check(const gdmaps_t* gdmaps, const char* map_name, const char* addr_txt, const char* dclist_cmp, const unsigned scope_cmp) {
    dmn_assert(gdmaps);
    dmn_assert(map_name);
    dmn_assert(addr_txt);
    dmn_assert(dclist_cmp);

    const int rv = gdmaps_name2idx(gdmaps, map_name);
    if(rv < 0)
        log_fatal("Map name '%s' not found in configuration", map_name);

    const unsigned map_idx = (unsigned)rv;

    client_info_t cinfo;
    cinfo.edns_client_mask = 128U;
    unsigned scope = 175U;

    const int addr_err = gdnsd_anysin_getaddrinfo(addr_txt, NULL, &cinfo.edns_client);
    if(addr_err)
        log_fatal("Cannot parse address '%s': %s", addr_txt, gai_strerror(addr_err));

    const uint8_t* dclist = gdmaps_lookup(gdmaps, map_idx, &cinfo, &scope);

    ok(!strcmp((const char*)dclist, dclist_cmp),
        "gdmaps_lookup(%s, %s) returns dclist %s (got %s)",
            map_name, addr_txt,
            gdmaps_logf_dclist(gdmaps, map_idx, (const uint8_t*)dclist_cmp),
            gdmaps_logf_dclist(gdmaps, map_idx, dclist));

    ok(scope == scope_cmp,
        "gdmaps_lookup(%s, %s) returns scope %u (got %u)",
            map_name, addr_txt, scope_cmp, scope);
}

void gdmaps_test_init(const char* cfg_dir) {
    dmn_assert(cfg_dir);
    dmn_init1(false, true, false, "gdmaps_test");
    gdnsd_initialize(cfg_dir, false);
}

gdmaps_t* gdmaps_test_load(const char* cfg_data) {
    dmn_assert(cfg_data);

    vscf_data_t* maps_cfg = vscf_scan_buf(strlen(cfg_data), cfg_data, "(test maps)", false);
    if(!maps_cfg)
        log_fatal("Test config load failed");
    if(!vscf_is_hash(maps_cfg))
        log_fatal("Geoip plugin config for 'maps' must be a hash");
    gdmaps_t* rv = gdmaps_new(maps_cfg);
    vscf_destroy(maps_cfg);

    gdmaps_load_databases(rv);

    return rv;
}

bool gdmaps_test_db_exists(const char* dbfile) {
    bool rv = false;
    char* fn = gdnsd_resolve_path_cfg(dbfile, "geoip");
    struct stat st;
    if(!stat(fn, &st) && !S_ISDIR(st.st_mode))
        rv = true;
    free(fn);
    return rv;
}
