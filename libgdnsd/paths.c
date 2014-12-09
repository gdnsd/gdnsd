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
#include <gdnsd/paths.h>

#include "misc.h"
#include "net.h"

#include <gdnsd/vscf.h>
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
#include <fcntl.h>
#include <pthread.h>

/* paths */

// Anytime
const char* gdnsd_get_default_config_dir(void) { return GDNSD_DEFPATH_CONFIG; }

// ---------------------------
// Init-time stuff

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

static vscf_data_t* conf_load_vscf(const char* cfg_file) {
    vscf_data_t* out = NULL;

    struct stat cfg_stat;
    if(!stat(cfg_file, &cfg_stat)) {
        log_info("Loading configuration from '%s'", cfg_file);
        out = vscf_scan_filename(cfg_file);
        if(!out)
            log_fatal("Loading configuration from '%s' failed", cfg_file);
        if(!vscf_is_hash(out)) {
            dmn_assert(vscf_is_array(out));
            log_fatal("Config file '%s' cannot be an '[ array ]' at the top level", cfg_file);
        }
    }
    else {
        log_info("No config file at '%s', using defaults", cfg_file);
    }

    return out;
}

#define CFG_DIR(_opt_set, _name) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_name, true); \
        if(_opt_setting) { \
            if(!vscf_is_simple(_opt_setting)) \
                log_fatal("Config option %s: Wrong type (should be string)", #_name); \
            _name = vscf_simple_get_data(_opt_setting); \
        } \
    } while(0)

vscf_data_t* gdnsd_initialize(const char* config_dir, const bool check_create_dirs) {
    static bool has_run = false;
    if(has_run)
        log_fatal("BUG: gdnsd_initialize() should only be called once!");
    else
        has_run = true;

    // Initialize other areas of libgdnsd
    gdnsd_init_net();
    gdnsd_rand_meta_init();

    // set up config dir
    if(!config_dir)
        config_dir = GDNSD_DEFPATH_CONFIG;
    gdnsd_dirs[CFG] = gdnsd_realdir(config_dir, "config", false, 0);

    // parse config file
    char* cfg_file = gdnsd_resolve_path_cfg("config", NULL);
    vscf_data_t* cfg_root = conf_load_vscf(cfg_file);
    free(cfg_file);

#ifndef NDEBUG
    // in developer debug builds, exercise clone+destroy
    if(cfg_root) {
        vscf_data_t* temp_cfg = vscf_clone(cfg_root, false);
        vscf_destroy(cfg_root);
        cfg_root = temp_cfg;
    }
#endif

    // find run/state paths, possibly using config input
    const char* run_dir = GDNSD_DEFPATH_RUN;
    const char* state_dir = GDNSD_DEFPATH_STATE;
    if(cfg_root) {
        vscf_data_t* options = vscf_hash_get_data_byconstkey(cfg_root, "options", true);
        if(options) {
            if(!vscf_is_hash(options))
                log_fatal("Config key 'options': wrong type (must be hash)");
            CFG_DIR(options, run_dir);
            CFG_DIR(options, state_dir);
        }
    }

    // set them up
    if(check_create_dirs) {
        gdnsd_dirs[RUN] = gdnsd_realdir(run_dir, "run", true, 0750);
        gdnsd_dirs[STATE] = gdnsd_realdir(state_dir, "state", true, 0755);
    }
    else {
        gdnsd_dirs[RUN] = strdup(run_dir);
        gdnsd_dirs[STATE] = strdup(state_dir);
    }

    // This is just fixed at compiletime, period
    gdnsd_dirs[LIBEXEC] = GDNSD_DEFPATH_LIBEXEC;

    return cfg_root;
}

// ---------------------------
// Runtime stuff

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
