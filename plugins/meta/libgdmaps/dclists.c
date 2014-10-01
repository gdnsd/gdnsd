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

// gdmaps = GeoIP -> Datacenter Mapping library code

#include "config.h"
#include "dclists.h"

#include <math.h>

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/vscf.h>

/***************************************
 * dclists_t and related methods
 **************************************/

// dclists_t is a storage container for unique ordered
//  lists of datacenters to be used for lookup results.
// It keeps a const pointer to this map's dcinfo_t for reference
//  because many of its operations require that data.
// Because city-auto mode needs to add lists to this very
//  late in the game (at db load time, which happens "late"
//  on initial load, and randomly later when geoip db's are
//  updated on the filesystem), we also have to be able
//  to update this structure when we create the ntree_t
//  later.
// So it has a clone operation which clones the list and
//  copies the string pointers, and various levels of
//  destroy operation that destroy only the newly-added
//  strings, all strings, or no strings.
// The idea is when a new tree is being constructed on the
//  side in the reload thread, it clones the current runtime
//  tree and adds new strings to it as necc (which won't
//  be often, most likely, since we've already stored most
//  likely orderings the first time).  The dclists_t is
//  "owned" by the new tree, and the old tree destructs
//  the old dclists_t without freeing the shared string
//  storage when it's destroyed after the locked tree swap.
// The destruct-only-new-strings destroy is used when
//  ntree construction fails partway through and has to
//  be aborted, and the destruct-all-strings form is
//  used on true shutdown of the whole gdmap (only debug
//  mode for the real plugin).

struct _dclists {
    unsigned count; // count of unique result lists
    unsigned old_count; // count from object we cloned from
    uint8_t** list;    // strings of dc numbers
    const dcinfo_t* info; // dclists_t doesn't own "info", just uses it for reference a lot
};

dclists_t* dclists_new(const dcinfo_t* info) {
    const unsigned num_dcs = dcinfo_get_count(info);
    uint8_t* deflist = xmalloc(num_dcs + 1);
    for(unsigned i = 0; i < num_dcs; i++)
        deflist[i] = i + 1;
    deflist[num_dcs] = 0;

    dclists_t* newdcl = xmalloc(sizeof(dclists_t));
    newdcl->count = 1;
    newdcl->old_count = 0;
    newdcl->list = xmalloc(sizeof(uint8_t*));
    newdcl->list[0] = deflist;
    newdcl->info = info;

    return newdcl;
}

dclists_t* dclists_clone(const dclists_t* old) {
    dclists_t* dcl_clone = xmalloc(sizeof(dclists_t));
    dcl_clone->info = old->info;
    dcl_clone->count = old->count;
    dcl_clone->old_count = old->count;
    dcl_clone->list = xmalloc(dcl_clone->count * sizeof(uint8_t*));
    memcpy(dcl_clone->list, old->list, dcl_clone->count * sizeof(uint8_t*));
    return dcl_clone;
}

unsigned dclists_get_count(const dclists_t* lists) {
    dmn_assert(lists);
    return lists->count;
}

const uint8_t* dclists_get_list(const dclists_t* lists, const unsigned idx) {
    dmn_assert(lists);
    dmn_assert(idx < lists->count);
    return lists->list[idx];
}

// Locates an existing dclist that matches newlist and returns its index, or if no match
//  it copies newlist to the storage area and returns the new index.
// If someone complains about load-time performance with large datecenter sets, this func
//  will probably be a profiling hotspot.  It could use a hashtable rather than linear
//  search for comparisons, and it could realloc the list by doubling instead of 1-at-a-time.
// Not terribly worried about this unless someone complains first.
F_NONNULL
static unsigned dclists_find_or_add_raw(dclists_t* lists, const uint8_t* newlist, const char* map_name) {
    dmn_assert(lists); dmn_assert(newlist); dmn_assert(map_name);

    for(unsigned i = 0; i < lists->count; i++)
        if(!strcmp((const char*)newlist, (const char*)(lists->list[i])))
            return i;

    // it's actually unsigned, but the top bit is reserved for nnode_t
    //   to use to flag the difference between node recursion and a
    //   terminal dclist, and the special value INT32_MAX - 1 (also
    //   with the top bit set), is used as an error signal in nnode_t.
    // Therefore the maximum legal index is INT32_MAX - 2
    if(lists->count == (INT32_MAX - 1))
        log_fatal("plugin_geoip: map '%s': too many unique dclists (>%u)", map_name, lists->count);

    const unsigned newidx = lists->count;
    lists->list = xrealloc(lists->list, (++lists->count) * sizeof(uint8_t*));
    lists->list[newidx] = (uint8_t*)strdup((const char*)newlist);
    return newidx;
}

// replace the first (default) dclist...
void dclists_replace_list0(dclists_t* lists, uint8_t* newlist) {
    dmn_assert(lists); dmn_assert(newlist);
    free(lists->list[0]);
    lists->list[0] = newlist;
}

// We should probably check for dupes in these map dclists, but really the fallout
//  is just some redundant lookup work if the user screws that up.
int dclists_xlate_vscf(dclists_t* lists, vscf_data_t* vscf_list, const char* map_name, uint8_t* newlist, const bool allow_auto) {
    dmn_assert(lists); dmn_assert(vscf_list); dmn_assert(lists); dmn_assert(newlist); dmn_assert(map_name);

    const unsigned count = vscf_array_get_len(vscf_list);

    for(unsigned i = 0; i < count; i++) {
        vscf_data_t* dcname_cfg = vscf_array_get_data(vscf_list, i);
        if(!dcname_cfg || !vscf_is_simple(dcname_cfg))
            log_fatal("plugin_geoip: map '%s': datacenter lists must be an array of one or more datacenter name strings", map_name);
        const char* dcname = vscf_simple_get_data(dcname_cfg);
        if(count == 1 && allow_auto && !strcmp(dcname, "auto"))
            return -1;
        const unsigned idx = dcinfo_name2num(lists->info, dcname);
        if(!idx)
            log_fatal("plugin_geoip: map '%s': datacenter name '%s' invalid ...", map_name, dcname);
        newlist[i] = idx;
    }
    newlist[count] = 0;

    return 0;
}

int dclists_find_or_add_vscf(dclists_t* lists, vscf_data_t* vscf_list, const char* map_name, const bool allow_auto) {
    dmn_assert(lists); dmn_assert(vscf_list); dmn_assert(lists); dmn_assert(map_name);
    uint8_t newlist[256];
    int status = dclists_xlate_vscf(lists,vscf_list,map_name,newlist,allow_auto);
    dmn_assert(status == 0 || (status == -1 && allow_auto));
    return status ? status : (int)dclists_find_or_add_raw(lists, newlist, map_name);
}

// Geographic distance between two lat/long points.
// Because we only care about rough distance comparison rather than
//  the precise values themselves, input is specified in radians
//  and output in units of the earth's diameter.
F_CONST
static double haversine(double lat1, double lon1, double lat2, double lon2) {
    double a = pow(sin((lat2 - lat1) * 0.5), 2.0)
        + cos(lat1) * cos(lat2) * pow(sin((lon2 - lon1) * 0.5), 2.0);
    return atan2(sqrt(a), sqrt(1.0 - a));
}

unsigned dclists_city_auto_map(dclists_t* lists, const char* map_name, const unsigned raw_lat, const unsigned raw_lon) {
    dmn_assert(lists);

    // Generally speaking, seems that almost all records
    //  in City DB have lat/lon with the exception of
    //  those in continent -- (countries --,O1,A1,A2)
    //  and the US Military regions AE/AP/AA, all of
    //  which show up as lat:0 lon:0.

    // default for 0/0 coords
    if(raw_lat == 1800000 && raw_lon == 1800000)
        return 0;

    // Copy the default datacenter list to local storage for sorting
    const unsigned num_dcs = dcinfo_get_count(lists->info);
    const unsigned store_len = num_dcs + 1;
    uint8_t sortlist[store_len];
    memcpy(sortlist, lists->list[0], store_len);

    // convert raw form to double radians
    const double lat_rad = (raw_lat - 1800000.0) / 10000.0 * DEG2RAD;
    const double lon_rad = (raw_lon - 1800000.0) / 10000.0 * DEG2RAD;

    // calculate the target's distance from each datacenter.
    // note the first element of 'dists' is unused, and
    //  storage is offset by one.  This is so that the actual
    //  1-based dcnums in 'sortlist' can be used as direct
    //  indices into 'dists'
    double dists[store_len];
    for(unsigned i = 0; i < num_dcs; i++) {
        const double* coords = dcinfo_get_coords(lists->info, i);
        if (!isnan(coords[0]))
            dists[i + 1] = haversine(lat_rad, lon_rad, coords[0], coords[1]);
        else
            dists[i + 1] = +INFINITY;
    }

    // Given the relatively small num_dcs of most configs,
    //  this simple insertion sort is probably reasonably quick
    for(unsigned i = 1; i < num_dcs; i++) {
        unsigned temp = sortlist[i];
        int j = i - 1;
        while(j >= 0 && (dists[temp] < dists[sortlist[j]])) {
            sortlist[j + 1] = sortlist[j];
            j--;
        }
        sortlist[j + 1] = temp;
    }

    // Cap the list at the auto_limit
    sortlist[dcinfo_get_limit(lists->info)] = 0;

    return dclists_find_or_add_raw(lists, sortlist, map_name);
}

void dclists_destroy(dclists_t* lists, dclists_destroy_depth_t depth) {
    dmn_assert(lists);
    switch(depth) {
        case KILL_ALL_LISTS:
            for(unsigned i = 0; i < lists->count; i++)
                free(lists->list[i]);
            break;
        case KILL_NEW_LISTS:
            for(unsigned i = lists->old_count; i < lists->count; i++)
                free(lists->list[i]);
            break;
        case KILL_NO_LISTS:
        default:
            break;
    }
    free(lists->list);
    free(lists);
}
