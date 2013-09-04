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

/**************************************************************************
* Daemonization code
**************************************************************************/

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include "dmn.h"

// this simply trusts fcntl pid info
//  on the lock we hold for daemon lifetime
//  to inform us of a running daemon's pid.
// the string pid stored in the file is just
//  for reference for humans or other tools.

static const size_t pblen = 22;

static int status_finish_fd = -1;

static pid_t check_pidfile(const char* pidfile) {
    dmn_assert(pidfile);

    const int pidfd = open(pidfile, O_RDONLY);
    if(pidfd == -1) {
        if (errno == ENOENT) return 0;
        else dmn_log_fatal("open() of pidfile '%s' failed: %s", pidfile, dmn_strerror(errno));
    }

    struct flock pidlock_info;
    memset(&pidlock_info, 0, sizeof(struct flock));
    pidlock_info.l_type = F_WRLCK;
    pidlock_info.l_whence = SEEK_SET;

    // should not fail unless something's horribly wrong
    if(fcntl(pidfd, F_GETLK, &pidlock_info))
        dmn_log_fatal("bug: fcntl(%s, F_GETLK) failed: %s", pidfile, dmn_strerror(errno));

    close(pidfd);

    if(pidlock_info.l_type == F_UNLCK) {
        dmn_log_debug("Found stale pidfile at %s, ignoring", pidfile);
        return 0;
    }

    return pidlock_info.l_pid;
}

static bool pidrace_inner(const pid_t pid, const int pidfd) {
    bool rv = true; // cannot get lock

    char pidbuf[pblen];
    const ssize_t pidlen = snprintf(pidbuf, pblen, "%li\n", (long)pid);
    if(pidlen < 2)
        dmn_log_fatal("snprintf() for pidfile failed");

    struct flock pidlock_set;
    memset(&pidlock_set, 0, sizeof(struct flock));
    pidlock_set.l_type = F_WRLCK;
    pidlock_set.l_whence = SEEK_SET;
    if(fcntl(pidfd, F_SETLK, &pidlock_set)) {
        if(errno != EAGAIN && errno != EACCES)
            dmn_log_fatal("bug? fcntl(pidfile, F_SETLK) failed: %s", dmn_strerror(errno));
    }
    else {
        rv = false; // got lock
        if(ftruncate(pidfd, 0))
            dmn_log_fatal("truncating pidfile failed: %s", dmn_strerror(errno));
        if(write(pidfd, pidbuf, (size_t) pidlen) != pidlen)
            dmn_log_fatal("writing to pidfile failed: %s", dmn_strerror(errno));
    }

    return rv;
}

static pid_t startup_pidrace(const char* pidfile, const bool restart) {
    dmn_assert(pidfile);

    pid_t pid = getpid();

    int pidfd = open(pidfile, O_WRONLY | O_CREAT, 0666);
    if(pidfd == -1)
        dmn_log_fatal("open(%s, O_WRONLY|O_CREAT) failed: %s", pidfile, dmn_strerror(errno));
    if(fcntl(pidfd, F_SETFD, FD_CLOEXEC))
        dmn_log_fatal("fcntl(%s, F_SETFD, FD_CLOEXEC) failed: %s", pidfile, dmn_strerror(errno));

    if(restart) {
        dmn_log_info("restart: Stopping previous daemon instance, if any");
        struct timeval tv;
        unsigned tries = 1;
        unsigned maxtries = 10;
        while(tries++ <= maxtries) {
            const pid_t old_pid = check_pidfile(pidfile);
            if(old_pid && !kill(old_pid, SIGTERM)) {
                tv.tv_sec = 0;
                tv.tv_usec = 100000 * tries;
                select(0, NULL, NULL, NULL, &tv);
            }
            if(!pidrace_inner(pid, pidfd))
                return pid;
        }
        dmn_log_fatal("restart: failed, cannot shut down previous instance and acquire pidfile lock");
    }
    else if(pidrace_inner(pid, pidfd)) {
        dmn_log_fatal("start: failed, another instance of this daemon is already running");
    }

    // leak of pidfd here is intentional, it stays open/locked for the duration
    //   of the daemon's execution.  Daemon death by any means unlocks-on-close,
    //   signalling to other code that this instance is no longer running...
    return pid;
}

// original process (before any forks) waits on readpipe here to
//   see if final daemon child succeeded in pidfile locking and
//   startup, then exits with an appropriate exit value.
// the child itself will take care of string outputs, as it doesn't
//   close stdio descriptors until after the critical section
static void parent_status_wait(const int readpipe) {
    int exitval = 1;
    char statuschar;
    const int readrv = read(readpipe, &statuschar, 1);
    if(readrv == 1 && statuschar == '$')
        exitval = 0;
    _exit(exitval);
}

void dmn_daemonize(const char* pidfile, const bool restart) {
    dmn_assert(pidfile);

    // This pipe is used to communicate daemonization success
    //   (which must happen two forks later because fcntl() does
    //   not fork-inherit) back to the top-level parent for
    //   correct exit value.
    int statuspipe[2];
    if(pipe(statuspipe))
        dmn_log_fatal("pipe() failed: %s", dmn_strerror(errno));

    // Fork for the first time, closing the writer in the parent
    //  and the reader in the child, and sending the parent off
    //  to wait for status in parent_status_wait()
    const pid_t first_fork_pid = fork();
    if(first_fork_pid == -1)
        dmn_log_fatal("fork() failed: %s", dmn_strerror(errno));
    if(first_fork_pid) { // original parent proc
        if(close(statuspipe[1])) // close write-side
            dmn_log_fatal("close() of status pipe write-side failed in first parent: %s", dmn_strerror(errno));
        parent_status_wait(statuspipe[0]);
        dmn_assert(0); // above never returns control
    }

    if(close(statuspipe[0])) // close read-side
        dmn_log_fatal("close() of status pipe read-side failed in first child: %s", dmn_strerror(errno));

    // setsid() and ignore HUP/PIPE before the second fork
    if(setsid() == -1) dmn_log_fatal("setsid() failed: %s", dmn_strerror(errno));
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;

    if(sigaction(SIGHUP, &sa, NULL))
        dmn_log_fatal("sigaction to ignore SIGHUP failed: %s", dmn_strerror(errno));

    if(sigaction(SIGPIPE, &sa, NULL))
        dmn_log_fatal("sigaction to ignore SIGPIPE failed: %s", dmn_strerror(errno));

    // Fork again.  This time the intermediate parent exits immediately.
    const pid_t second_fork_pid = fork();
    if(second_fork_pid == -1)
        dmn_log_fatal("fork() failed: %s", dmn_strerror(errno));
    if(second_fork_pid) // intermediate parent proc
        _exit(0);

    // we're now in the final child daemon

    umask(022);

    const pid_t pid = startup_pidrace(pidfile, restart);

    if(!freopen("/dev/null", "r", stdin))
        dmn_log_fatal("Cannot open /dev/null: %s", dmn_strerror(errno));
    if(!freopen("/dev/null", "w", stdout))
        dmn_log_fatal("Cannot open /dev/null: %s", dmn_strerror(errno));
    if(!freopen("/dev/null", "r+", stderr))
        dmn_log_fatal("Cannot open /dev/null: %s", dmn_strerror(errno));
    dmn_log_info("Daemonized, final pid is %li", (long)pid);

    // track fd for later dmn_daemonize_finish()
    status_finish_fd = statuspipe[1];
}

void dmn_daemonize_finish(void) {
    dmn_assert(status_finish_fd != -1);

    // inform original parent of our success, but if for some reason
    //   it died before we could do so, carry on anyways...
    errno = 0;
    char successchar = '$';
    if(1 != write(status_finish_fd, &successchar, 1))
        dmn_log_err("Bug? failed to notify parent of daemonization success! Errno was %s", dmn_strerror(errno));
    close(status_finish_fd);

    // this shuts off our saved copy of stderr, which
    //  was kept open to inform the outer process/user
    //  of late initialzation failures post-daemonization.
    dmn_log_close_alt_stderr();
}

pid_t dmn_status(const char* pidfile) { dmn_assert(pidfile); return check_pidfile(pidfile); }

pid_t dmn_stop(const char* pidfile) {
    dmn_assert(pidfile);

    const pid_t pid = check_pidfile(pidfile);
    if(!pid) {
        dmn_log_info("Did not find a running daemon to stop!");
        return 0;
    }

    // This will basically do a kill/sleep
    //  loop for a total of 10 attempts over
    //  the course of 5.5 seconds before giving
    //  up, with the sleep delay increasing from
    //  100ms at the start up to 1s at the end.

    struct timeval tv;
    unsigned tries = 1;
    unsigned maxtries = 10;
    while(tries++ <= maxtries && !kill(pid, SIGTERM)) {
        tv.tv_sec = 0;
        tv.tv_usec = 100000 * tries;
        select(0, NULL, NULL, NULL, &tv);
    }

    if(!kill(pid, 0)) {
        dmn_log_err("Cannot stop daemon at pid %li", (long)pid);
        return pid;
    }

    dmn_log_info("Daemon instance at pid %li stopped", (long)pid);
    return 0;
}

int dmn_signal(const char* pidfile, int sig) {
    dmn_assert(pidfile);

    int rv = 1; // error
    const pid_t pid = check_pidfile(pidfile);
    if(!pid) {
        dmn_log_err("Did not find a running daemon to signal!");
    }
    else if(kill(pid, sig)) {
        dmn_log_err("Cannot signal daemon at pid %li", (long)pid);
    }
    else {
        dmn_log_info("SIGHUP sent to daemon instance at pid %li", (long)pid);
        rv = 0; // success
    }

    return rv;
}

