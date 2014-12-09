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

#include <config.h>
#include "dclists.h"

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/vscf.h>

#include <math.h>

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
    dmn_assert(lists->count <= (DCLIST_MAX + 1U));
    return lists->count;
}

const uint8_t* dclists_get_list(const dclists_t* lists, const uint32_t idx) {
    dmn_assert(lists);
    dmn_assert(idx < lists->count);
    dmn_assert(idx <= DCLIST_MAX);
    return lists->list[idx];
}

// Locates an existing dclist that matches newlist and returns its index, or if no match
//  it copies newlist to the storage area and returns the new index.
// If someone complains about load-time performance with large datecenter sets, this func
//  will probably be a profiling hotspot.  It could use a hashtable rather than linear
//  search for comparisons, and it could realloc the list by doubling instead of 1-at-a-time.
// Not terribly worried about this unless someone complains first.
F_NONNULL
static uint32_t dclists_find_or_add_raw(dclists_t* lists, const uint8_t* newlist, const char* map_name) {
    dmn_assert(lists); dmn_assert(newlist); dmn_assert(map_name);

    for(uint32_t i = 0; i < lists->count; i++)
        if(!strcmp((const char*)newlist, (const char*)(lists->list[i])))
            return i;

    if(lists->count > DCLIST_MAX)
        log_fatal("plugin_geoip: map '%s': too many unique dclists (>%u)", map_name, lists->count);

    const uint32_t newidx = lists->count;
    lists->list = xrealloc(lists->list, (++lists->count) * sizeof(uint8_t*));
    lists->list[newidx] = (uint8_t*)strdup((const char*)newlist);

    dmn_assert(newidx <= DCLIST_MAX);
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
bool dclists_xlate_vscf(dclists_t* lists, vscf_data_t* vscf_list, const char* map_name, uint8_t* newlist, const bool allow_auto) {
    dmn_assert(lists); dmn_assert(vscf_list); dmn_assert(lists); dmn_assert(newlist); dmn_assert(map_name);

    const unsigned count = vscf_array_get_len(vscf_list);

    for(unsigned i = 0; i < count; i++) {
        vscf_data_t* dcname_cfg = vscf_array_get_data(vscf_list, i);
        if(!dcname_cfg || !vscf_is_simple(dcname_cfg))
            log_fatal("plugin_geoip: map '%s': datacenter lists must be an array of one or more datacenter name strings", map_name);
        const char* dcname = vscf_simple_get_data(dcname_cfg);
        if(count == 1 && allow_auto && !strcmp(dcname, "auto"))
            return true;
        const unsigned idx = dcinfo_name2num(lists->info, dcname);
        if(!idx)
            log_fatal("plugin_geoip: map '%s': datacenter name '%s' invalid ...", map_name, dcname);
        newlist[i] = idx;
    }
    newlist[count] = 0;

    return false;
}

uint32_t dclists_find_or_add_vscf(dclists_t* lists, vscf_data_t* vscf_list, const char* map_name, const bool allow_auto) {
    dmn_assert(lists); dmn_assert(vscf_list); dmn_assert(lists); dmn_assert(map_name);
    uint8_t newlist[256];
    bool is_auto = dclists_xlate_vscf(lists,vscf_list,map_name,newlist,allow_auto);
    if(is_auto) {
        dmn_assert(allow_auto);
        return DCLIST_AUTO;
    }
    return dclists_find_or_add_raw(lists, newlist, map_name);
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

uint32_t dclists_city_auto_map(dclists_t* lists, const char* map_name, const double lat, const double lon) {
    dmn_assert(lists); dmn_assert(map_name);

    const double lat_rad = lat * DEG2RAD;
    const double lon_rad = lon * DEG2RAD;

    // Copy the default datacenter list to local storage for sorting
    const unsigned num_dcs = dcinfo_get_count(lists->info);
    const unsigned store_len = num_dcs + 1;
    uint8_t sortlist[store_len];
    memcpy(sortlist, lists->list[0], store_len);

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
        int j = (int)i - 1;
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
