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

#include "zsrc_rfc1035.h"
#include "gdnsd-misc.h"
#include "zscan_rfc1035.h"

#include <sys/types.h>
#include <dirent.h>

static const char RFC1035_DIR[] = "etc/zones/";

// list of all zone_t's we've created from files.
//   no check for duplicates or indexing, this
//   is just for cleanup at the end...
zone_t** zflist = NULL;
unsigned zflist_count = 0;
unsigned zflist_alloc = 0;

static void zflist_add(zone_t* z) {
    if(unlikely(zflist_count == zflist_alloc)) {
        if(zflist_alloc)
            zflist_alloc *= 2;
        else
            zflist_alloc = 8;
        zflist = realloc(zflist, zflist_alloc * sizeof(zone_t*));
    }

    zflist[zflist_count++] = z;
}

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

static bool process_zonefile(const char* zfn) {
    dmn_assert(zfn);
    zone_t* z = calloc(1, sizeof(zone_t));
    z->src = str_combine(RFC1035_DIR, zfn, NULL); // XXX not quite right
    // XXX missing mtime, too
    z->arena = lta_new();
    z->dname = make_zone_dname(zfn, z->arena);
    if(!z->dname) {
        lta_destroy(z->arena);
        free(z->src);
        free(z);
        return true;
    }

    z->hash = dname_hash(z->dname);
    ltree_init_zone(z);

    if(unlikely(scan_zone(z, z->src))) {
        lta_destroy(z->arena);
        free(z->src);
        free(z);
        return true;
    }

    lta_close(z->arena);
    if(unlikely(ltree_postproc_zone(z))) {
        lta_destroy(z->arena);
        free(z->src);
        free(z);
        return true;
    }

    zlist_update(NULL, z);
    zflist_add(z);
    return false;
}

static void zone_delete(zone_t* zone) {
    dmn_assert(zone);
    if(zone->root)
        ltree_destroy(zone->root);
    lta_destroy(zone->arena);
    free(zone->src);
    free(zone);
}

static void zsrc_rfc1035_unload_zones(void) {
    for(unsigned i = 0; i < zflist_count; i++) {
        zone_t* z = zflist[i];
        zlist_update(z, NULL);
        zone_delete(z);
    }
}

// XXX in the future when this merges with the non-inotify
//   reload scanner, we don't want directory errors to be fatal
void zsrc_rfc1035_load_zones(void) {
    DIR* zdhandle = opendir(RFC1035_DIR);
    if(!zdhandle)
        log_fatal("Cannot open zones directory '%s': %s", RFC1035_DIR, dmn_strerror(errno));

    unsigned success = 0;
    unsigned failure = 0;
    struct dirent* zfdi;
    while((zfdi = readdir(zdhandle))) {
        if(likely(zfdi->d_name[0] != '.')) {
            if(process_zonefile(zfdi->d_name))
                failure++;
            else
                success++;
        }
    }

    if(closedir(zdhandle))
        log_fatal("closedir(%s) failed: %s", RFC1035_DIR, dmn_strerror(errno));

    log_info("%u zones loaded successfully (%u failed)", success, failure);

    if(atexit(zsrc_rfc1035_unload_zones))
        log_fatal("atexit(zsrc_rfc1035_unload_zones) failed: %s", logf_errno());
}

void zsrc_rfc1035_runtime_init(struct ev_loop* zdata_loop) {
    dmn_assert(zdata_loop);
}
