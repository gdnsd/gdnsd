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

static bool dmn_daemonized = false;

static const size_t pblen = 22;

static int check_pidfile(const char* pidfile) {
    dmn_assert(pidfile);

    char pidbuf[pblen];

    const int pidfd = open(pidfile, O_RDONLY);
    if(pidfd == -1) {
        if (errno == ENOENT) return 0;
        else dmn_log_fatal("open() of pidfile '%s' failed: %s", pidfile, dmn_strerror(errno));
    }

    const int readrv = read(pidfd, pidbuf, (size_t) 15);
    if(readrv == -1) {
        close(pidfd);
        dmn_log_fatal("read() from pidfile '%s' failed: %s", pidfile, dmn_strerror(errno));
    }

    close(pidfd);

    if(readrv == 0) {
        dmn_log_info("empty pidfile '%s', wiping it out", pidfile);
        unlink(pidfile);
        return 0;
    }
    pidbuf[readrv] = '\0';

    errno = 0;
    const int pidnum = strtol(pidbuf, NULL, 10);
    if(errno) {
        dmn_log_info("wiping out pidfile '%s': %s", pidfile, dmn_strerror(errno));
        unlink(pidfile);
        return 0;
    }

    if(pidnum <= 0) {
        dmn_log_info("invalid pid found in pidfile in '%s', wiping it out", pidfile);
        unlink(pidfile);
        return 0;
    }

    if(kill(pidnum, 0)) {
        dmn_log_info("Found stale pidfile for pid %i in %s, wiping it out", pidnum, pidfile);
        unlink(pidfile);
        return 0;
    }

    return pidnum;
}

static long make_pidfile(const char* pidfile) {
    dmn_assert(pidfile);

    long pid = (long)getpid();
    char pidbuf[pblen];

    int pidfd = open(pidfile, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if(pidfd == -1) dmn_log_fatal("creation of new pidfile %s failed: %s", pidfile, dmn_strerror(errno));

    const ssize_t pidlen = snprintf(pidbuf, pblen, "%li\n", pid);
    if(pidlen < 2) {
        close(pidfd);
        unlink(pidfile);
        dmn_log_fatal("snprintf() for pidfile failed");
    }
    if(write(pidfd, pidbuf, (size_t) pidlen) != pidlen) {
        close(pidfd);
        unlink(pidfile);
        dmn_log_fatal("writing to new pidfile %s failed: %s", pidfile, dmn_strerror(errno));
    }
    if(close(pidfd) == -1) {
        unlink(pidfile);
        dmn_log_fatal("closing new pidfile %s failed: %s", pidfile, dmn_strerror(errno));
    }

    return pid;
}

static int fork_and_exit(void) {
    const int mypid = fork();
    if (mypid == -1)     // parent: failure
        return 0;
    else if (mypid != 0) // parent: success
        _exit(0);
    else                 // child: success
        return 1;
}

void dmn_daemonize(const char* logname, const char* pidfile) {
    dmn_assert(pidfile);

    const int oldpid = check_pidfile(pidfile);
    if(oldpid)
        dmn_log_fatal("I am already running at pid %i in %s, failing", oldpid, pidfile);

    if(!fork_and_exit()) dmn_log_fatal("fork() failed: %s", dmn_strerror(errno));

    if(setsid() == -1) dmn_log_fatal("setsid() failed: %s", dmn_strerror(errno));

    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;

    if(sigaction(SIGHUP, &sa, NULL) == -1)
        dmn_log_fatal("sigaction to ignore SIGHUP failed: %s", dmn_strerror(errno));

    if(sigaction(SIGPIPE, &sa, NULL) == -1)
        dmn_log_fatal("sigaction to ignore SIGPIPE failed: %s", dmn_strerror(errno));

    if(!fork_and_exit())
        dmn_log_fatal("fork() failed: %s", dmn_strerror(errno));

    if(chdir("/") == -1)
        dmn_log_fatal("chdir(/) failed: %s", dmn_strerror(errno));

    umask(022);

    long pid = make_pidfile(pidfile);

    if(!freopen("/dev/null", "r", stdin))
        dmn_log_fatal("Cannot open /dev/null: %s", dmn_strerror(errno));
    if(!freopen("/dev/null", "w", stdout))
        dmn_log_fatal("Cannot open /dev/null: %s", dmn_strerror(errno));

    dmn_log_info("Daemonizing at pid %li ...", pid);

    if(!freopen("/dev/null", "r+", stderr))
        dmn_log_fatal("Cannot open /dev/null: %s", dmn_strerror(errno));
    openlog(logname, LOG_NDELAY|LOG_PID, LOG_DAEMON);
    dmn_daemonized = true;
    dmn_log_info("Daemonized succesfully, pid is %li", pid);
}

int dmn_status(const char* pidfile) { dmn_assert(pidfile); return check_pidfile(pidfile); }

int dmn_stop(const char* pidfile) {
    dmn_assert(pidfile);

    const int pid = check_pidfile(pidfile);
    if(!pid) {
        dmn_log_info("Did not find a running daemon to stop!");
        return 0;
    }

    struct timeval tv;

    // This will basically do a kill/sleep
    //  loop for a total of 10 attempts over
    //  the course of 5.5 seconds before giving
    //  up, with the sleep delay increasing from
    //  100ms at the start up to 1s at the end.

    unsigned tries = 1;
    unsigned maxtries = 10;
    while(tries++ <= maxtries && !kill(pid, SIGTERM)) {
        tv.tv_sec = 0;
        tv.tv_usec = 100000 * tries;
        select(0, NULL, NULL, NULL, &tv);
    }

    if(!kill(pid, 0)) {
        dmn_log_err("Cannot stop daemon at pid %i", pid);
        return pid;
    }

    unlink(pidfile);

    return 0;
}

void dmn_signal(const char* pidfile, int sig) {
    dmn_assert(pidfile);

    const int pid = check_pidfile(pidfile);
    if(!pid)
        dmn_log_err("Did not find a running daemon to signal!");
    if(kill(pid, sig))
        dmn_log_err("Cannot signal daemon at pid %i", pid);
}

bool dmn_is_daemonized(void) { return dmn_daemonized; }
