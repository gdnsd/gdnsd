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
#include "dcinfo.h"

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/misc.h>

#include <math.h>

// Technically we could/should check for duplicates here.  The plugin will
//  still fail later though: when a resource is defined, the datacenter
//  names go into a hash requiring uniqueness, and the count is required
//  to match (ditto for auto_dc_coords never succeeding with dupes in the
//  datacenters list).
void dcinfo_init(dcinfo_t* info, vscf_data_t* dc_cfg, vscf_data_t* dc_auto_cfg, vscf_data_t* dc_auto_limit_cfg, const char* map_name, monreg_func_t mrf)
{
    const unsigned num_dcs = vscf_array_get_len(dc_cfg);
    unsigned num_auto = num_dcs;
    if (!num_dcs)
        log_fatal("plugin_geoip: map '%s': 'datacenters' must be an array of one or more strings", map_name);
    if (num_dcs > MAX_NUM_DCS)
        log_fatal("plugin_geoip: map '%s': %u datacenters is too many, this code only supports up to %i", map_name, num_dcs, MAX_NUM_DCS);

    info->num_dcs = num_dcs;
    info->dcs = xmalloc_n(num_dcs, sizeof(*info->dcs));

    for (unsigned i = 0; i < num_dcs; i++) {
        vscf_data_t* dcname_cfg = vscf_array_get_data(dc_cfg, i);
        if (!dcname_cfg || !vscf_is_simple(dcname_cfg))
            log_fatal("plugin_geoip: map '%s': 'datacenters' must be an array of one or more strings", map_name);
        info->dcs[i].name = xstrdup(vscf_simple_get_data(dcname_cfg));
        if (!strcmp(info->dcs[i].name, "auto"))
            log_fatal("plugin_geoip: map '%s': datacenter name 'auto' is illegal", map_name);
        char* map_mon_desc = gdnsd_str_combine_n(4, "geoip/", map_name, "/", info->dcs[i].name);
        if (mrf)
            info->dcs[i].mon_index = mrf(map_mon_desc);
        free(map_mon_desc);
    }

    if (dc_auto_cfg) {
        if (!vscf_is_hash(dc_auto_cfg))
            log_fatal("plugin_geoip: map '%s': auto_dc_coords must be a key-value hash", map_name);
        num_auto = vscf_hash_get_len(dc_auto_cfg);
        for (unsigned i = 0; i < num_dcs; i++) {
            info->dcs[i].coords.lat = (double)NAN;
            info->dcs[i].coords.lon = (double)NAN;
            info->dcs[i].coords.cos_lat = (double)NAN;
        }
        for (unsigned i = 0; i < num_auto; i++) {
            const char* dcname = vscf_hash_get_key_byindex(dc_auto_cfg, i, NULL);
            unsigned dcidx;
            for (dcidx = 0; dcidx < num_dcs; dcidx++) {
                if (!strcmp(dcname, info->dcs[dcidx].name))
                    break;
            }
            if (dcidx == num_dcs)
                log_fatal("plugin_geoip: map '%s': auto_dc_coords key '%s' not matched from 'datacenters' list", map_name, dcname);
            GDNSD_DIAG_PUSH_IGNORED("-Wdouble-promotion")
            if (!isnan(info->dcs[dcidx].coords.lat))
                log_fatal("plugin_geoip: map '%s': auto_dc_coords key '%s' defined twice", map_name, dcname);
            GDNSD_DIAG_POP
            vscf_data_t* coord_cfg = vscf_hash_get_data_byindex(dc_auto_cfg, i);
            if (!vscf_is_array(coord_cfg) || vscf_array_get_len(coord_cfg) != 2)
                log_fatal("plugin_geoip: map '%s': auto_dc_coords value for datacenter '%s' must be an array of two values", map_name, dcname);
            vscf_data_t* lat_cfg = vscf_array_get_data(coord_cfg, 0);
            vscf_data_t* lon_cfg = vscf_array_get_data(coord_cfg, 1);
            gdnsd_assert(lat_cfg);
            gdnsd_assert(lon_cfg);

            double lat;
            double lon;
            if (!vscf_is_simple(lat_cfg)
                    || !vscf_is_simple(lon_cfg)
                    || !vscf_simple_get_as_double(lat_cfg, &lat)
                    || !vscf_simple_get_as_double(lon_cfg, &lon)
                    || lat > 90.0 || lat < -90.0
                    || lon > 180.0 || lon < -180.0
               )
                log_fatal("plugin_geoip: map '%s': auto_dc_coords value for datacenter '%s' must be a legal latitude and longitude in decimal degrees", map_name, dcname);
            info->dcs[dcidx].coords.lat = lat * DEG2RAD;
            info->dcs[dcidx].coords.lon = lon * DEG2RAD;
            info->dcs[dcidx].coords.cos_lat = cos(lat * DEG2RAD);
        }
    }

    if (dc_auto_limit_cfg) {
        unsigned long auto_limit_ul;
        if (!vscf_is_simple(dc_auto_limit_cfg) || !vscf_simple_get_as_ulong(dc_auto_limit_cfg, &auto_limit_ul))
            log_fatal("plugin_geoip: map '%s': auto_dc_limit must be a single unsigned integer value", map_name);
        if (auto_limit_ul > num_auto || !auto_limit_ul)
            auto_limit_ul = num_auto;
        info->auto_limit = auto_limit_ul;
    } else {
        info->auto_limit = (num_auto > 3) ? 3 : num_auto;
    }
}

unsigned dcinfo_get_count(const dcinfo_t* info)
{
    return info->num_dcs;
}

unsigned dcinfo_get_limit(const dcinfo_t* info)
{
    return info->auto_limit;
}

const dcinfo_coords_t* dcinfo_get_coords(const dcinfo_t* info, const unsigned dcnum)
{
    gdnsd_assert(dcnum < info->num_dcs);
    return &info->dcs[dcnum].coords;
}

unsigned dcinfo_name2num(const dcinfo_t* info, const char* dcname)
{
    if (dcname)
        for (unsigned i = 0; i < info->num_dcs; i++)
            if (!strcmp(dcname, info->dcs[i].name))
                return i + 1;
    return 0;
}

const char* dcinfo_num2name(const dcinfo_t* info, const unsigned dcnum)
{
    if (!dcnum || dcnum > info->num_dcs)
        return NULL;

    return info->dcs[dcnum - 1].name;
}

unsigned dcinfo_map_mon_idx(const dcinfo_t* info, const unsigned dcnum)
{
    gdnsd_assert(dcnum && dcnum <= info->num_dcs);
    return info->dcs[dcnum - 1].mon_index;
}
