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

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <time.h>
#include <errno.h>

#include "dmn.h"

#define PERMS755 (S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH)
#define PERMS022 (S_IWGRP|S_IWOTH)

// State storage between secure_setup() and secure_me()
static uid_t secure_uid = 0;
static gid_t secure_gid = 0;
static char* secure_chroot = NULL;

// Status flag for accessor func
static bool is_secured = false;

void dmn_secure_setup(const char* username, const char* chroot_path) {
    dmn_assert(username);

    // This isn't really a security thing, we'd fail somewhere else along the line anyways,
    //   it's just a handy error bailout to point out developer bugs in using these interfaces.
    if(geteuid())
        dmn_log_fatal("BUG: dmn_secure_*() calls should only be executed when running as root");

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

    if(chroot_path) {
        secure_chroot = strdup(chroot_path);
        struct stat st;
        if(lstat(secure_chroot, &st))
            dmn_log_fatal("Cannot lstat(%s): %s", secure_chroot, dmn_strerror(errno));
        if(!S_ISDIR(st.st_mode))
            dmn_log_fatal("chroot() path '%s' is not a directory!", secure_chroot);
    }
}

void dmn_secure_me(const bool skip_chroot) {
    if(!secure_uid || !secure_gid)
        dmn_log_fatal("BUG: secure_setup() must be called before secure_me()");

    // lock self into the chroot directory
    if(secure_chroot && !skip_chroot) {
        // On most systems, this seems to get the timezone cached for vsyslog() to use inside chroot()
        tzset();
        if(chroot(secure_chroot)) dmn_log_fatal("chroot(%s) failed: %s", secure_chroot, dmn_strerror(errno));
        if(chdir("/")) dmn_log_fatal("chdir(/) inside chroot(%s) failed: %s", secure_chroot, dmn_strerror(errno));
    }

    // drop privs
    if(setgid(secure_gid))
        dmn_log_fatal("setgid(%u) failed: %s", secure_gid, dmn_strerror(errno));
    if(setuid(secure_uid))
        dmn_log_fatal("setuid(%u) failed: %s", secure_uid, dmn_strerror(errno));

    // verify that regaining root privs fails, and [e][ug]id values are as expected
    if(    !setegid(0)
        || !seteuid(0)
        || geteuid() != secure_uid
        || getuid() != secure_uid
        || getegid() != secure_gid
        || getgid() != secure_gid
    )
        dmn_log_fatal("Platform-specific BUG: setgid() and/or setuid() do not permanently drop privs as expected!");

    is_secured = true;
}

bool dmn_is_secured(void) { return is_secured; }
const char* dmn_get_chroot(void) { return secure_chroot; }
