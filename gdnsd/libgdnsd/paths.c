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

#include "config.h"

#include <gdnsd/paths.h>
#include <gdnsd/paths-priv.h>
#include <gdnsd/misc.h>
#include <gdnsd/log.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#include "cfg-dirs.h"

/* paths */

const char* gdnsd_get_default_config_dir(void) { return GDNSD_DEFPATH_CONFIG; }

F_NONNULL
static char* gdnsd_realdir(const char* dpath, const char* desc, const bool create, mode_t def_mode) {
    struct stat st;
    int stat_rv = stat(dpath, &st);

    if(stat_rv) {
        // if we can't create and doesn't exist, let the error fall through to whoever uses it...
        if(!create)
            return strdup(dpath);
        if(mkdir(dpath, def_mode))
            log_fatal("mkdir of %s directory '%s' failed: %s", desc, dpath, dmn_logf_strerror(errno));
        log_info("Created %s directory %s", desc, dpath);
    }
    else if(!S_ISDIR(st.st_mode)) {
        log_fatal("%s directory '%s' is not a directory (but should be)!", desc, dpath);
    }

    char* out = realpath(dpath, NULL);
    if(!out)
        log_fatal("Validation of %s directory '%s' failed: %s",
            desc, dpath, dmn_logf_strerror(errno));
    if(strcmp(dpath, out))
        log_info("%s directory '%s' cleaned up as '%s'", desc, dpath, out);
    return out;
}

typedef enum {
    RUN     = 0,
    STATE   = 1,
    CFG     = 2,
    LIBEXEC = 3,
} path_typ_t;

static const char* gdnsd_dirs[4] = { NULL, NULL, NULL, NULL };

void gdnsd_set_config_dir(const char* config_dir) {
    if(!config_dir)
        config_dir = GDNSD_DEFPATH_CONFIG;

    gdnsd_dirs[CFG] = gdnsd_realdir(config_dir, "config", false, 0);
}

void gdnsd_set_runtime_dirs(const char* run_dir, const char* state_dir, const bool check_create) {
    if(!run_dir)
        run_dir = GDNSD_DEFPATH_RUN;

    if(!state_dir)
        state_dir = GDNSD_DEFPATH_STATE;

    if(check_create) {
        gdnsd_dirs[RUN] = gdnsd_realdir(run_dir, "run", true, 0750);
        gdnsd_dirs[STATE] = gdnsd_realdir(state_dir, "state", true, 0755);
    }
    else {
        gdnsd_dirs[RUN] = strdup(run_dir);
        gdnsd_dirs[STATE] = strdup(state_dir);
    }

    // This is just fixed at compiletime, period
    gdnsd_dirs[LIBEXEC] = GDNSD_DEFPATH_LIBEXEC;
}

static char* gdnsd_resolve_path(const path_typ_t p, const char* inpath, const char* pfx) {
    dmn_assert(gdnsd_dirs[p]);

    char* out = NULL;

    if(inpath && inpath[0] == '/') {
        out = strdup(inpath);
    }
    else if(pfx) {
        if(inpath)
            out = gdnsd_str_combine_n(5, gdnsd_dirs[p], "/", pfx, "/", inpath);
        else
            out = gdnsd_str_combine_n(3, gdnsd_dirs[p], "/", pfx);
    }
    else {
        if(inpath)
            out = gdnsd_str_combine_n(3, gdnsd_dirs[p], "/", inpath);
        else
            out = strdup(gdnsd_dirs[p]);
    }

    return out;
}

char* gdnsd_resolve_path_run(const char* inpath, const char* pfx) {
    return gdnsd_resolve_path(RUN, inpath, pfx);
}

char* gdnsd_resolve_path_state(const char* inpath, const char* pfx) {
    return gdnsd_resolve_path(STATE, inpath, pfx);
}

char* gdnsd_resolve_path_cfg(const char* inpath, const char* pfx) {
    return gdnsd_resolve_path(CFG, inpath, pfx);
}

char* gdnsd_resolve_path_libexec(const char* inpath, const char* pfx) {
    return gdnsd_resolve_path(LIBEXEC, inpath, pfx);
}
