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
#include "zsrc_rfc1035.h"

#include "zscan_rfc1035.h"
#include "conf.h"
#include "ztree.h"
#include "main.h"

#include <gdnsd/alloc.h>
#include <gdnsd/misc.h>
#include <gdnsd/log.h>
#include <gdnsd/paths.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <time.h>

static char* rfc1035_dir = NULL;

F_NONNULL
static char* make_zone_name(const char* zf_name)
{
    unsigned zf_name_len = strlen(zf_name);
    char* out = NULL;

    if (zf_name_len > 1004) {
        log_err("rfc1035: Zone file name '%s' is illegal", zf_name);
    } else {
        // check for root zone...
        if (unlikely(zf_name_len == 9 && !strncmp(zf_name, "ROOT_ZONE", 9))) {
            out = xmalloc(2);
            out[0] = '.';
            out[1] = 0;
        } else {
            // convert all '@' to '/' for RFC2317 reverse delegation zones
            out = xmalloc(zf_name_len + 1);
            for (unsigned i = 0; i <= zf_name_len; i++) {
                if (unlikely(zf_name[i] == '@'))
                    out[i] = '/';
                else
                    out[i] = zf_name[i];
            }
        }
    }

    return out;
}

F_NONNULL
static bool process_zonefile(ztree_t* tree, const char* fn, const char* full_fn)
{
    char* name = make_zone_name(fn);
    if (name) {
        char* src = gdnsd_str_combine("rfc1035:", fn, NULL);
        zone_t* z = zone_new(name, src);
        free(src);
        free(name);

        if (z) {
            if (zscan_rfc1035(z, full_fn) || zone_finalize(z))
                zone_delete(z);
            else if (!ztree_insert_zone(tree, z))
                return false;
        }
    }

    return true;
}

/*************************/
/*** Public interfaces ***/
/*************************/

bool zsrc_rfc1035_load_zones(ztree_t* tree)
{
    gdnsd_assert(rfc1035_dir);

    DIR* zdhandle = opendir(rfc1035_dir);
    if (!zdhandle) {
        if (errno == ENOENT) {
            log_debug("rfc1035: Zones directory '%s' does not exist", rfc1035_dir);
            return false;
        }
        log_err("rfc1035: Cannot open zones directory '%s': %s", rfc1035_dir, logf_errno());
        return true;
    }

    bool failed = false;
    unsigned zone_count = 0;
    struct dirent* result = NULL;
    do {
        errno = 0;
        // cppcheck-suppress readdirCalled
        result = readdir(zdhandle);
        if (likely(result)) {
            if (result->d_name[0] != '.') {
                struct stat st;
                const char* fn;
                char* full_fn = gdnsd_str_combine(rfc1035_dir, result->d_name, &fn);
                if (stat(full_fn, &st)) {
                    log_err("rfc1035: stat(%s) failed: %s", full_fn, logf_errno());
                    failed = true;
                } else if (S_ISREG(st.st_mode)) {
                    failed = process_zonefile(tree, fn, full_fn);
                    zone_count++;
                }
                free(full_fn);
                if (failed)
                    break;
            }
        } else if (errno) {
            log_err("rfc1035: readdir(%s) failed: %s", rfc1035_dir, logf_errno());
            failed = true;
            break;
        }
    } while (result);

    if (closedir(zdhandle)) {
        log_err("rfc1035: closedir(%s) failed: %s", rfc1035_dir, logf_errno());
        return true;
    }

    if (failed)
        return true;

    log_info("rfc1035: Loaded %u zonefiles from '%s'", zone_count, rfc1035_dir);
    return false;
}

void zsrc_rfc1035_init(void)
{
    rfc1035_dir = gdnsd_resolve_path_cfg("zones/", NULL);
}
