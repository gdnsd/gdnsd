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

#include "config.h"
#include "dcinfo.h"
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/misc.h>
#include <gdnsd/mon.h>
#include <math.h>

/***************************************
 * dcinfo_t and related methods
 **************************************/

// The datacenter numbers are always 1-based, and only up to 254
//  datacenters are supported.  The first datacenter is always #1,
//  and in a 3-datacenter config they're 1, 2, 3.  The zero-value
//  is used to terminate datacenter lists that are implemented
//  as uint8_t* strings on which standard string ops work (e.g.
//  strcmp(), strcpy()).
// dcinfo_t holds a list of text datacenters names in the order
//  specified in the config, which is the default order.  Therefore
//  the default order, in dclist format, is e.g. for num_dcs == 3,
//  \1\2\3\0.
// dcinfo_t also holds auto_limit, which is the lesser of the
//  configured auto_dc_limit and the actual num_dcs, so that it's
//  always the correct limit for direct application even if num_dcs
//  is < auto_dc_limit.
// Finally, dcinfo_t also holds the list of coordinates for each
//  datacenter in the case that auto_dc_coords was used.  This
//  array of doubles is twice as long as the names array, and stores
//  a latitude follow by a longitude for each datacenter, in
//  radian units.

struct _dcinfo {
    unsigned num_dcs;    // count of datacenters
    unsigned auto_limit; // lesser of num_dcs and dc_auto_limit cfg
    char** names;        // #num_dcs, ordered map
    double* coords;      // #(num_dcs * 2, lat then lon, in radians)
    unsigned* indices;   // mon_admin indices for map-level forced state
};

// Technically we could/should check for duplicates here.  The plugin will
//  still fail later though: when a resource is defined, the datacenter
//  names go into a hash requiring uniqueness, and the count is required
//  to match (ditto for auto_dc_coords never succeeding with dupes in the
//  datacenters list).
dcinfo_t* dcinfo_new(vscf_data_t* dc_cfg, vscf_data_t* dc_auto_cfg, vscf_data_t* dc_auto_limit_cfg, const char* map_name) {
    dmn_assert(dc_cfg); dmn_assert(map_name);

    dcinfo_t* info = xmalloc(sizeof(dcinfo_t));

    const unsigned num_dcs = vscf_array_get_len(dc_cfg);
    unsigned num_auto = num_dcs;
    if(!num_dcs)
        log_fatal("plugin_geoip: map '%s': 'datacenters' must be an array of one or more strings", map_name);
    if(num_dcs > 254)
        log_fatal("plugin_geoip: map '%s': %u datacenters is too many, this code only supports up to 254", map_name, num_dcs);

    info->names = xmalloc(sizeof(char*) * num_dcs);
    info->indices = xmalloc(sizeof(unsigned) * num_dcs);
    info->num_dcs = num_dcs;
    for(unsigned i = 0; i < num_dcs; i++) {
        vscf_data_t* dcname_cfg = vscf_array_get_data(dc_cfg, i);
        if(!dcname_cfg || !vscf_is_simple(dcname_cfg))
            log_fatal("plugin_geoip: map '%s': 'datacenters' must be an array of one or more strings", map_name);
        info->names[i] = strdup(vscf_simple_get_data(dcname_cfg));
        if(!strcmp(info->names[i], "auto"))
            log_fatal("plugin_geoip: map '%s': datacenter name 'auto' is illegal", map_name);
        char* map_mon_desc = gdnsd_str_combine_n(4, "geoip/", map_name, "/", info->names[i]);
        info->indices[i] = gdnsd_mon_admin(map_mon_desc);
        free(map_mon_desc);
    }

    if(dc_auto_cfg) {
        if(!vscf_is_hash(dc_auto_cfg))
            log_fatal("plugin_geoip: map '%s': auto_dc_coords must be a key-value hash", map_name);
        num_auto = vscf_hash_get_len(dc_auto_cfg);
        info->coords = xmalloc(num_dcs * 2 * sizeof(double));
        for(unsigned i = 0; i < 2*num_dcs; i++)
            info->coords[i] = NAN;
        for(unsigned i = 0; i < num_auto; i++) {
            const char* dcname = vscf_hash_get_key_byindex(dc_auto_cfg, i, NULL);
            unsigned dcidx;
            for(dcidx = 0; dcidx < num_dcs; dcidx++) {
                if(!strcmp(dcname, info->names[dcidx]))
                    break;
            }
            if(dcidx == num_dcs)
                log_fatal("plugin_geoip: map '%s': auto_dc_coords key '%s' not matched from 'datacenters' list", map_name, dcname);
            if(!isnan(info->coords[(dcidx*2)]))
                log_fatal("plugin_geoip: map '%s': auto_dc_coords key '%s' defined twice", map_name, dcname);
            vscf_data_t* coord_cfg = vscf_hash_get_data_byindex(dc_auto_cfg, i);
            vscf_data_t* lat_cfg;
            vscf_data_t* lon_cfg;
            double lat, lon;
            if(
                !vscf_is_array(coord_cfg) || vscf_array_get_len(coord_cfg) != 2
                || !(lat_cfg = vscf_array_get_data(coord_cfg, 0))
                || !(lon_cfg = vscf_array_get_data(coord_cfg, 1))
                || !vscf_is_simple(lat_cfg)
                || !vscf_is_simple(lon_cfg)
                || !vscf_simple_get_as_double(lat_cfg, &lat)
                || !vscf_simple_get_as_double(lon_cfg, &lon)
                || lat > 90.0 || lat < -90.0
                || lon > 180.0 || lon < -180.0
            )
                log_fatal("plugin_geoip: map '%s': auto_dc_coords value for datacenter '%s' must be an array of two floating-point values representing a legal latitude and longitude in decimal degrees", map_name, dcname);
            info->coords[(dcidx * 2)] = lat * DEG2RAD;
            info->coords[(dcidx * 2) + 1] = lon * DEG2RAD;
        }
    }
    else {
        info->coords = NULL;
    }

    if(dc_auto_limit_cfg) {
        unsigned long auto_limit_ul;
        if(!vscf_is_simple(dc_auto_limit_cfg) || !vscf_simple_get_as_ulong(dc_auto_limit_cfg, &auto_limit_ul))
            log_fatal("plugin_geoip: map '%s': auto_dc_limit must be a single unsigned integer value", map_name);
        if(auto_limit_ul > num_auto || !auto_limit_ul)
            auto_limit_ul = num_auto;
        info->auto_limit = auto_limit_ul;
    }
    else {
        info->auto_limit = (num_auto > 3) ? 3 : num_auto;
    }

    return info;
}

unsigned dcinfo_get_count(const dcinfo_t* info) {
    dmn_assert(info);
    return info->num_dcs;
}

unsigned dcinfo_get_limit(const dcinfo_t* info) {
    dmn_assert(info);
    return info->auto_limit;
}

const double* dcinfo_get_coords(const dcinfo_t* info, const unsigned dcnum) {
    dmn_assert(info);
    dmn_assert(dcnum < info->num_dcs);
    return &info->coords[dcnum * 2];
}

unsigned dcinfo_name2num(const dcinfo_t* info, const char* dcname) {
    dmn_assert(info);
    if(dcname)
        for(unsigned i = 0; i < info->num_dcs; i++)
            if(!strcmp(dcname, info->names[i]))
                return i + 1;
    return 0;
}

const char* dcinfo_num2name(const dcinfo_t* info, const unsigned dcnum) {
    dmn_assert(info);

    if(!dcnum || dcnum > info->num_dcs)
        return NULL;

    return info->names[dcnum - 1];
}

unsigned dcinfo_map_mon_idx(const dcinfo_t* info, const unsigned dcnum) {
    dmn_assert(info);
    dmn_assert(dcnum && dcnum <= info->num_dcs);
    return info->indices[dcnum - 1];
}

void dcinfo_destroy(dcinfo_t* info) {
    dmn_assert(info);
    for(unsigned i = 0; i < info->num_dcs; i++)
        free(info->names[i]);
    free(info->names);
    free(info->indices);
    if(info->coords)
        free(info->coords);
    free(info);
}
