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

// gdmaps = GeoIP -> Datacenter Mapping library code

#include "config.h"
#include "dclists.h"
#include "dcmap.h"
#include "gdgeoip.h"

#include <gdnsd/log.h>
#include <stdbool.h>

/***************************************
 * dcmap_t and related methods
 **************************************/

struct _dcmap {
    // All 3 below are allocated to num_children entries.
    // For each index, exactly one of the following must be true:
    //  child_dclist[i] is non-zero, indicating a direct dclist
    //  child_dcmap[i] is non-null, indicating another level of depth
    char** child_names;
    int* child_dclists;
    dcmap_t** child_dcmaps;
    unsigned def_dclist; // copied from parent if not specced in cfg, required at root
    unsigned num_children;
    bool skip_level; // at this level of dcmap, skip ahead one chunk of locstr...
};

typedef struct {
    dcmap_t* dcmap;
    dclists_t* dclists;
    const char* map_name;
    unsigned child_num;
    unsigned true_depth;
    bool allow_auto;
} dcmap_iter_data;

F_NONNULL
static bool _dcmap_new_iter(const char* key, unsigned klen V_UNUSED, const vscf_data_t* val, void* data) {
    dmn_assert(key); dmn_assert(val); dmn_assert(data);

    dcmap_iter_data* did = data;

    unsigned true_depth = did->true_depth + (did->dcmap->skip_level ? 1 : 0);
    if(true_depth == 0)
        validate_continent_code(key, did->map_name);
    else if(true_depth == 1)
        validate_country_code(key, did->map_name);

    did->dcmap->child_names[did->child_num] = strdup(key);
    if(vscf_is_hash(val))
        did->dcmap->child_dcmaps[did->child_num] = dcmap_new(val, did->dclists, did->dcmap->def_dclist, true_depth + 1, did->map_name, did->allow_auto);
    else
        did->dcmap->child_dclists[did->child_num] = dclists_find_or_add_vscf(did->dclists, val, did->map_name, did->allow_auto);

    did->child_num++;

    return true;
}

dcmap_t* dcmap_new(const vscf_data_t* map_cfg, dclists_t* dclists, const unsigned parent_def, const unsigned true_depth, const char* map_name, const bool allow_auto) {
    dmn_assert(map_cfg); dmn_assert(dclists); dmn_assert(map_name);
    dmn_assert(vscf_is_hash(map_cfg));

    dcmap_t* dcmap = calloc(1, sizeof(dcmap_t));
    unsigned nchild = vscf_hash_get_len(map_cfg);

    const vscf_data_t* def_cfg = vscf_hash_get_data_byconstkey(map_cfg, "default", true);
    if(def_cfg) {
        if(!true_depth) {
            uint8_t newlist[256];
            int status = dclists_xlate_vscf(dclists, def_cfg, map_name, newlist, allow_auto);
            if(status) {
                dmn_assert(status == -1 && allow_auto);
                dcmap->def_dclist = -1;
            }
            else {
                dcmap->def_dclist = 0;
                dclists_replace_list0(dclists, (uint8_t*)strdup((char*)newlist));
            }
        }
        else {
            dcmap->def_dclist = dclists_find_or_add_vscf(dclists, def_cfg, map_name, allow_auto);
        }
        nchild--; // don't iterate "default" later
    }
    else {
        if(!true_depth) {
            dcmap->def_dclist = allow_auto ? -1 : 0;
        }
        else {
            dcmap->def_dclist = parent_def;
        }
    }

    const vscf_data_t* skip_cfg = vscf_hash_get_data_byconstkey(map_cfg, "skip_level", true);
    if(skip_cfg) {
        if(!vscf_is_simple(skip_cfg) || !vscf_simple_get_as_bool(skip_cfg, &dcmap->skip_level))
            log_fatal("plugin_geoip: map '%s': 'skip_level' must be a boolean value ('true' or 'false')", map_name);
        nchild--; // don't iterate "skip_level" later
    }

    if(nchild) {
        dcmap->num_children = nchild;
        dcmap->child_names = calloc(nchild, sizeof(char*));
        dcmap->child_dclists = calloc(nchild, sizeof(int));
        dcmap->child_dcmaps = calloc(nchild, sizeof(dcmap_t*));
        dcmap_iter_data did = {
            .child_num = 0,
            .dcmap = dcmap,
            .dclists = dclists,
            .map_name = map_name,
            .true_depth = true_depth,
            .allow_auto = allow_auto
        };
        vscf_hash_iterate(map_cfg, true, _dcmap_new_iter, &did);
    }

    return dcmap;
}

int dcmap_lookup_loc(const dcmap_t* dcmap, const char* locstr) {
    dmn_assert(dcmap); dmn_assert(locstr);

    if(*locstr && dcmap->skip_level)
        locstr += strlen(locstr) + 1;

    if(*locstr) {
        for(unsigned i = 0; i < dcmap->num_children; i++) {
            if(!strcasecmp(locstr, dcmap->child_names[i])) {
                if(dcmap->child_dcmaps[i])
                    return dcmap_lookup_loc(dcmap->child_dcmaps[i], locstr + strlen(locstr) + 1);
                return dcmap->child_dclists[i];
            }
        }
    }

    return dcmap->def_dclist;
}

void dcmap_destroy(dcmap_t* dcmap) {
    dmn_assert(dcmap);

    if(dcmap->child_names) {
        for(unsigned i = 0; i < dcmap->num_children; i++) {
            if(dcmap->child_names[i])
                free(dcmap->child_names[i]);
        }
        free(dcmap->child_names);
    }
    if(dcmap->child_dcmaps) {
        for(unsigned i = 0; i < dcmap->num_children; i++) {
            if(dcmap->child_dcmaps[i])
                dcmap_destroy(dcmap->child_dcmaps[i]);
        }
        free(dcmap->child_dcmaps);
    }
    if(dcmap->child_dclists)
        free(dcmap->child_dclists);
    free(dcmap);
}
