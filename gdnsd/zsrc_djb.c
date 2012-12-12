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

#include "zsrc_djb.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "conf.h"
#include "ltree.h"
#include "ltarena.h"
#include "ztree.h"
#include "gdnsd/misc.h"

static void unload_zones(void) {
    // for every zone_t created and sent to ztree earlier
    //   during zsrc_djb_load_zones:
    // zlist_update(z, NULL); // removes from runtime lookup
    // zone_delete(z); // destroys actual data inside
    // free other associated local data, if any
}

void zsrc_djb_load_zones(void) {
    // scan input file(s):
    //   create zone_t object for each local zone using
    //     ztree.h:zone_new("example.com", "djb:datafile")
    //   set zone_t->mtime from filesystem mtime.
    //   add records to the zone_t via ltree_add_rec_*.
    //   call zone_finalize(z) to do post-processing
    //   call zlist_update(NULL, z); for each zone created,
    //     which makes it available for runtime lookup
    //   keep track of the zone_t's you created, you're
    //   responsible for destroying them later.
    if(atexit(unload_zones))
        log_fatal("zsrc_djb: atexit(unload_zones) failed: %s", logf_errno());
}

void zsrc_djb_runtime_init(struct ev_loop* loop V_UNUSED) {
    // for runtime reloading based on FS updates,
    // can just no-op for now and load on startup only, above.
    return;
}
