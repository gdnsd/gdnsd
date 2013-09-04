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

#include "gdnsd/paths.h"
#include "gdnsd/paths-priv.h"
#include "gdnsd/log.h"

#include "cfg-dirs.h"

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

/* misc */

// this will be "system" or an absolute directory
static const char* const def_rootdir = GDNSD_DEF_ROOTDIR;

// "system" (or default unrooted) leaves this as NULL
static const char* rootdir = NULL;
static unsigned rootdir_len = 0;

// readonly private interfaces to core code
const char* gdnsd_get_rootdir(void) { return rootdir; }
const char* gdnsd_get_def_rootdir(void) { return def_rootdir; }

// this is for use after basic rootdir setting and chdir...
static void ensure_dir(const char* dpath) {
    struct stat st;
    if(lstat(dpath, &st)) {
        if(mkdir(dpath, 0755))
            log_fatal("mkdir(%s) failed: %s", logf_pathname(dpath), dmn_strerror(errno));
        log_info("Created directory %s", logf_pathname(dpath));
    }
    else if(!S_ISDIR(st.st_mode)) {
        log_fatal("'%s' is not a directory (but should be)!", logf_pathname(dpath));
    }
}

// as above for the initial rootdir check itself, note the use
//   of stat() rather than lstat() (so that a symlink to a directory
//   will work (which realpath will clean up afterwards)).
static void ensure_rootdir(const char* rpath) {
    struct stat st;
    if(stat(rpath, &st)) {
        if(mkdir(rpath, 0755))
            log_fatal("mkdir(%s) failed: %s", rpath, dmn_strerror(errno));
    }
    else if(!S_ISDIR(st.st_mode)) {
        log_fatal("'%s' is not a directory (but should be)!", rpath);
    }
}

char* gdnsd_realpath(const char* path_in, const char* desc) {
    char* out = realpath(path_in, NULL);
    if(!out)
        log_fatal("Cleanup/validation of %s pathname '%s' failed: %s",
            desc, path_in, dmn_strerror(errno));
    if(strcmp(path_in, out))
        log_info("%s path '%s' cleaned up as '%s'", desc, path_in, out);
    return out;
}

void gdnsd_set_rootdir(const char* rootdir_in) {
    dmn_assert(!rootdir);
    dmn_assert(def_rootdir);

    const char* rootdir_setting
        = rootdir_in ? rootdir_in : def_rootdir;

    dmn_assert(rootdir_setting);

    if(!strcmp(rootdir_setting, "system")) {
        // Not using a root directory, using system paths
        if(chdir("/"))
            log_fatal("Failed to chdir('/'): %s", dmn_strerror(errno));
        ensure_dir(GDNSD_RUNDIR);
    }
    else {
        // Using a root directory:
        // realpath() wants an extant file to reference,
        //  so we have to do our stat/mkdir on the original first
        ensure_rootdir(rootdir_setting);
        rootdir = gdnsd_realpath(rootdir_setting, "data root");
        if(chdir(rootdir))
            log_fatal("Failed to chdir('%s'): %s", rootdir, dmn_strerror(errno));
        rootdir_len = strlen(rootdir);

        // build basic/common directory structure if missing
        ensure_dir("etc");
        ensure_dir("etc/zones");
        ensure_dir("etc/geoip");
        ensure_dir("run");
    }
}

static const unsigned etc_len = sizeof(GDNSD_ETCDIR) - 1;

char* gdnsd_resolve_path_cfg(const char* inpath, const char* pfx) {
    dmn_assert(inpath);

    char* out = NULL;
    unsigned inlen = strlen(inpath);

    if(rootdir) { // rooted paths
        if(inpath[0] == '/') {
            out = malloc(inlen + 1);
            memcpy(out, inpath + 1, inlen); // includes NUL
        }
        else if(pfx) {
            const unsigned pfxlen = strlen(pfx);
            char* outptr = out = malloc(4 + pfxlen + 1 + inlen + 1);
            memcpy(outptr, "etc/", 4); outptr += 4;
            memcpy(outptr, pfx, pfxlen); outptr += pfxlen;
            *outptr++ = '/';
            memcpy(outptr, inpath, inlen + 1); // includes NUL
        }
        else {
            char* outptr = out = malloc(4 + inlen + 1);
            memcpy(outptr, "etc/", 4); outptr += 4;
            memcpy(outptr, inpath, inlen + 1); // includes NUL
        }
    }
    else { // system paths
        if(inpath[0] == '/') {
            out = malloc(inlen + 1);
            memcpy(out, inpath, inlen + 1); // includes NUL
        }
        else if(pfx) {
            const unsigned pfxlen = strlen(pfx);
            char* outptr = out = malloc(etc_len + 1 + pfxlen + 1 + inlen + 1);
            memcpy(outptr, GDNSD_ETCDIR, etc_len); outptr += etc_len;
            *outptr++ = '/';
            memcpy(outptr, pfx, pfxlen); outptr += pfxlen;
            *outptr++ = '/';
            memcpy(outptr, inpath, inlen + 1); // includes NUL
        }
        else {
            char* outptr = out = malloc(etc_len + 1 + inlen + 1);
            memcpy(outptr, GDNSD_ETCDIR, etc_len); outptr += etc_len;
            *outptr++ = '/';
            memcpy(outptr, inpath, inlen + 1); // includes NUL
        }
    }

    return out;
}

static const char* fixed_rooted_pidpath = "run/gdnsd.pid";
static const char* pidfile_fixed_str = "/gdnsd.pid";
static const unsigned pidfile_fixed_len = 11; // includes NUL
static const unsigned rundir_len = sizeof(GDNSD_RUNDIR) - 1;

// get a copy of the full pathname of where the pidfile should reside
// note in the future we'll probably have to genericize the concept
//   of gdnsd_resolve_path_cfg() above to the rundir, but this suffices
//   for now since only the pidfile is there yet.
char* gdnsd_get_pidpath(void) {
    char* out;
    if(rootdir) {
        out = strdup(fixed_rooted_pidpath);
    }
    else {
        char* outptr = out = malloc(rundir_len + pidfile_fixed_len);
        memcpy(outptr, GDNSD_RUNDIR, rundir_len); outptr += rundir_len;
        memcpy(outptr, pidfile_fixed_str, pidfile_fixed_len);
    }

    return out;
}
