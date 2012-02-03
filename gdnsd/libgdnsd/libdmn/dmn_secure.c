/* Copyright © 2011 Brandon L Black <blblack@gmail.com>
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

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <time.h>
#include <errno.h>

#include "dmn.h"

#define PERMS755 (S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH)
#define PERMS011 (S_IWGRP|S_IWOTH)

// State storage between secure_setup() and secure_me()
static uid_t secure_uid = 0;
static gid_t secure_gid = 0;
static char* secure_chroot = NULL;

// Status flag for accessor func
static bool is_secured = false;

void dmn_secure_setup(const char* username, const char* chroot_path, const bool chroot_fixup) {
    dmn_assert(username);

    // Get the user info, verify they don't have root's uid/gid, store them...
    errno = 0;
    struct passwd* p = getpwnam(username);
    if(!p) {
        if(errno)
            dmn_log_fatal("getpwnam('%s') failed: %s", username, dmn_strerror(errno));
        else
            dmn_log_fatal("User '%s' does not exist", username);
    }
    if(!p->pw_uid || !p->pw_gid) dmn_log_fatal("User '%s' has root's uid and/or gid", username);
    secure_uid = p->pw_uid;
    secure_gid = p->pw_gid;

    if(!chroot_path)
        return;

    // Make sure chroot_path exists and has appropriate
    //  permissions, creating nonrecursively if necessary.
    struct stat st;
    if(lstat(chroot_path, &st) == -1) {
        if(errno == ENOENT) {
            if(!chroot_fixup)
                dmn_log_fatal("chroot() path '%s' does not exist", chroot_path);
            if(mkdir(chroot_path, PERMS755) == -1)
                dmn_log_fatal("Failed to mkdir(%s, 0755) for chroot() path: %s", chroot_path, dmn_strerror(errno));
            if(lstat(chroot_path, &st) == -1)
                dmn_log_fatal("Failed to stat() chroot() path '%s' right after successful mkdir(): %s", chroot_path, dmn_strerror(errno));
        }
        else {
            dmn_log_fatal("Failed to stat() chroot() path '%s': %s", chroot_path, dmn_strerror(errno));
        }
    }

    if(!S_ISDIR(st.st_mode)) dmn_log_fatal("chroot() path '%s' is not a directory", chroot_path);

    if(st.st_uid != 0 || st.st_gid != 0) {
        if(!chroot_fixup)
            dmn_log_fatal("chroot() path '%s' is not owned by the root user/group", chroot_path);
        if(chown(chroot_path, 0, 0) == -1)
            dmn_log_fatal("Failed to chown(%s, 0, 0): %s", chroot_path, dmn_strerror(errno));
    }

    if((st.st_mode & PERMS011)) {
        if(!chroot_fixup)
            dmn_log_fatal("chroot() path '%s' is writable", chroot_path);
        mode_t new_perms = st.st_mode & (~PERMS011);
        if(chmod(chroot_path, new_perms) == -1) {
            dmn_log_fatal("Failed to chmod(%s, %o): %s", chroot_path, (unsigned)new_perms, dmn_strerror(errno));
        }
    }

    secure_chroot = strdup(chroot_path);
}

void dmn_secure_me(void) {
    if(!secure_uid || !secure_gid)
        dmn_log_fatal("BUG: secure_setup() must be called before secure_me()");

    // On most systems, this seems to get the timezone cached for vsyslog() to use inside chroot()
    tzset();

    if(secure_chroot) {
        if(chroot(secure_chroot) == -1) dmn_log_fatal("chroot(%s) failed: %s", secure_chroot, dmn_strerror(errno));
        if(chdir("/") == -1) dmn_log_fatal("chdir(/) inside chroot(%s) failed: %s", secure_chroot, dmn_strerror(errno));
    }
    if(setgid(secure_gid) == -1) dmn_log_fatal("setgid(%u) failed: %s", secure_gid, dmn_strerror(errno));
    if(setuid(secure_uid) == -1) dmn_log_fatal("setuid(%u) failed: %s", secure_uid, dmn_strerror(errno));

    if(secure_chroot)
        dmn_log_info("Security measures (chroot(%s), setgid(%u), setuid(%u)) completed successfully", secure_chroot, secure_gid, secure_uid);
    else
        dmn_log_info("Security measures (setgid(%u), setuid(%u)) completed successfully", secure_gid, secure_uid);

    is_secured = true;
}

bool dmn_is_secured(void) { return is_secured; }
const char* dmn_get_chroot(void) { return secure_chroot; }
