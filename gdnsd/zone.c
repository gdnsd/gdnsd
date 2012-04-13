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

#include "zone.h"
#include "gdnsd-misc.h"

F_NONNULL
static const uint8_t* make_zone_dname(const char* zf_name, ltarena_t* arena) {
    dmn_assert(zf_name); dmn_assert(arena);

    unsigned zf_name_len = strlen(zf_name);
    uint8_t alter[zf_name_len + 1]; // Storage for making alterations...
    const uint8_t* rv = NULL;

    if(zf_name_len > 1004) {
        log_err("Zone file name '%s' is illegal", zf_name);
        goto out;
    }

    // check for root zone...
    if(unlikely(zf_name_len == 9 && !strncmp(zf_name, "ROOT_ZONE", 9))) {
        alter[0] = '.';
        alter[1] = 0;
        zf_name_len = 1;
    }
    else {
        // else copy the original, and...
        memcpy(alter, zf_name, zf_name_len);
        alter[zf_name_len] = 0;

        // convert all '@' to '/' for RFC2137 reverse delegation zones,
        //   and map uppercase alpha to lowercase.
        for(unsigned i = 0; i < zf_name_len; i++) {
            if(alter[i] <= 'Z' && alter[i] >= 'A')
                alter[i] |= 0x20;
            else if(unlikely(alter[i] == '@'))
                alter[i] = '/';
        }
    }

    // Convert to terminated-dname format and check for problems
    uint8_t dname[256];
    dname_status_t status = dname_from_string(dname, alter, zf_name_len);
    if(status == DNAME_INVALID) {
        log_err("Zone name '%s' is illegal", alter);
        goto out;
    }
    if(dname_iswild(dname)) {
        log_err("Zone '%s': Wildcard zone names not allowed", logf_dname(dname));
        goto out;
    }
    if(status == DNAME_PARTIAL)
        dname_terminate(dname);

    rv = lta_dnamedup(arena, dname);

    out:
    return rv;
}

zone_t* zone_new(const char* zfn) {
    dmn_assert(zfn);
    zone_t* rv = calloc(1, sizeof(zone_t));
    rv->fn = str_combine(ZONES_DIR, zfn, NULL);
    rv->arena = lta_new();
    rv->dname = make_zone_dname(zfn, rv->arena);
    if(!rv->dname) {
        lta_destroy(rv->arena);
        free(rv);
        rv = NULL;
    }
    else {
        rv->hash = dname_hash(rv->dname);
    }
    return rv;
}

void zone_delete(zone_t* zone) {
    dmn_assert(zone);
    if(zone->root)
        ltree_destroy(zone->root);
    lta_destroy(zone->arena);
    free(zone->fn);
    free(zone);
}
