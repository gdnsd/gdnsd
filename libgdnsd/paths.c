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

// for OSX _NSGetExecutablePath()
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

// for FreeBSD-like sysctl(3)
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif

/* paths */

// ---------------------------
// Anytime stuff

F_NONNULL F_UNUSED
static char* readlink_wrapper(const char* linkpath) {
    dmn_assert(linkpath);

    size_t blen = 1024;
    char* buf = xmalloc(blen);
    while(1) {
        ssize_t rl_rv = readlink(linkpath, buf, blen);
        if(rl_rv < 0) {
            free(buf);
            return NULL;
        }
        if(((size_t)rl_rv + 1) >= blen) {
            // just in case, to prevent a runaway loop
            if(blen >= 4194304)
                dmn_log_fatal("BUG: readlink_wrapper(%s) wanted dynamic bufsize >4MB", linkpath);
            blen <<= 1;
            buf = xrealloc(buf, blen);
        }
        else { // success, but needs termination
            buf[rl_rv] = '\0';
            return buf;
        }
    }
}

F_UNUSED
static char* getcwd_wrapper(void) {
    size_t blen = 1024;
    char* buf = xmalloc(blen);
    while(1) {
        char* rv = getcwd(buf, blen);
        if(rv)
            return buf;
        if(errno != ERANGE)
            dmn_log_fatal("getcwd() failed: %s", dmn_logf_errno());
        // just in case, to prevent a runaway loop
        if(blen >= 4194304)
            dmn_log_fatal("BUG: getcwd_wrapper() wanted dynamic bufsize >4MB");
        blen <<= 1;
        buf = xrealloc(buf, blen);
    }

    return buf;
}

F_NONNULL F_UNUSED
static char* resolve_argv0_path(const char* argv0, const char* path) {
    dmn_assert(argv0); dmn_assert(path);

    const size_t argv0_len = strlen(argv0);

    const char* pptr = path;
    while(*pptr) {
        // find len of next path element
        size_t plen;
        const char* eptr = strchr(pptr, ':');
        if(eptr) {
            dmn_assert(eptr >= pptr);
            plen = (size_t)(eptr - pptr);
        }
        else { // last element, no trailing ':'
            plen = strlen(pptr);
        }

        // try this path element (if absolute!), return if good candidate found
        if(plen && *pptr == '/') {
            char* buf = xmalloc(plen + 1 + argv0_len + 1);
            memcpy(buf, pptr, plen);
            buf[plen] = '/';
            memcpy(&buf[plen + 1], argv0, argv0_len);
            buf[plen + 1 + argv0_len] = '\0';
            struct stat st;
            if(!stat(buf, &st) && S_ISREG(st.st_mode))
                return buf;
            free(buf);
        }

        // skip consumed (possibly zero-len no-op) path element
        pptr += plen;

        // if not yet at the end, should be ':' to skip
        if(*pptr) {
            dmn_assert(*pptr == ':');
            pptr++;
        }
    }

    return NULL;
}

F_NONNULL F_UNUSED
static char* resolve_argv0(const char* argv0) {
    dmn_assert(argv0);

    // absolutes need no resolution
    if(argv0[0] == '/')
        return strdup(argv0);

    // if it has some other '/', it's relative to getcwd()
    if(strchr(argv0, '/')) {
        char* cwd = getcwd_wrapper();
        size_t cwd_len = strlen(cwd);
        size_t argv0_len = strlen(argv0);
        char* buf = xmalloc(cwd_len + 1 + argv0_len + 1);
        memcpy(buf, cwd, cwd_len);
        buf[cwd_len] = '/';
        memcpy(&buf[cwd_len + 1], argv0, argv0_len);
        buf[cwd_len + 1 + argv0_len] = '\0';
        free(cwd);
        return buf;
    }

    // if we make it here, we need to search $PATH or confstr(_CS_PATH)...
    char* result = NULL;
    const char* path_env = getenv("PATH");
    if(path_env) {
        result = resolve_argv0_path(argv0, path_env);
    }
    else {
        size_t blen = confstr(_CS_PATH, NULL, 0);
        if(!blen)
            return NULL;
        char* buf = xmalloc(blen);
        confstr(_CS_PATH, buf, blen);
        result = resolve_argv0_path(argv0, buf);
        free(buf);
    }

    return result;
}

char* gdnsd_self_exe_path(const char* argv0 V_UNUSED) {
    char* best = NULL;

// OSX
#if defined(__APPLE__)
    uint32_t nsgep_len = 1024U;
    best = xmalloc(nsgep_len);
    if(_NSGetExecutablePath(best, &nsgep_len)) {
        best = xrealloc(best, nsgep_len);
        if(_NSGetExecutablePath(best, &nsgep_len))
            dmn_log_fatal("_NSGetExecutablePath() failed: %s", dmn_logf_errno());
    }

// FreeBSD (or similar for this purpose)
#elif defined(HAVE_SYS_SYSCTL_H) && defined(CTL_KERN) && defined(KERN_PROC) && defined(KERN_PROC_PATHNAME)
    int kpp_mib[4];
    kpp_mib[0] = CTL_KERN;
    kpp_mib[1] = KERN_PROC;
    kpp_mib[2] = KERN_PROC_PATHNAME;
    kpp_mib[3] = -1;
    size_t kpp_len = 0;
    const int scrv = sysctl(kpp_mib, 4, NULL, &kpp_len, NULL, 0);
    if(!kpp_len || (scrv && errno != ENOMEM))
        dmn_log_fatal("sysctl(KERN_PROC_PATHNAME) size check failed: %s", dmn_logf_errno);
    best = xmalloc(kpp_len);
    if(sysctl(kpp_mib, 4, best, &kpp_len, NULL, 0))
        dmn_log_fatal("sysctl(KERN_PROC_PATHNAME) failed: %s", dmn_logf_errno);

#else // Not OSX or FreeBSD-style

    // These should work on Linux and some BSDs
    const char* const rlpaths[3] = {
        "/proc/self/exe",
        "/proc/curproc/file",
        "/proc/curproc/exe",
    };
    unsigned i = 0;
    while(i < 3 && !best)
        best = readlink_wrapper(rlpaths[i++]);

    // final portable fallback: try to actually interpret argv0 if supplied,
    // possibly using $PATH or confstr(_CS_PATH).  Note that argv0 isn't
    // always reliable, as the invoker of execve() could set argv[0] to an
    // arbitrary string which differs from the actual binary executed, but by
    // convention argv[0] should match the executed binary path.
    if(!best && argv0)
        best = resolve_argv0(argv0);

    if(!best)
        dmn_log_fatal("Cannot find our own executable path via /proc or interpreting argv[0]!");

#endif // OSX vs FreeBSD vs Other

    if(best[0] != '/')
        dmn_log_fatal("BUG: our own executable path '%s' is not absolute!", best);

    struct stat st;
    if(stat(best, &st))
        dmn_log_fatal("Cannot stat our own executable path '%s': %s!", best, dmn_logf_errno());

    if(!S_ISREG(st.st_mode))
        dmn_log_fatal("Our own executable path '%s' is not a regular file", best);

    // We could do realpath() here just to clean up ".." and symlinks, and I'm
    // inclined to just for cleanliness, but it might screw up a scheme where
    // the binary path we execute from is intentionally a versioned symlink,
    // e.g. you upgrade from 3.2 to 3.3 by changing /usr/sbin/gdnsd's symlink
    // from /usr/sbin/gdnsd-3.2 to /usr/sbin/gdnsd-3.3.

    return best;
}

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
