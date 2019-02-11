/* Copyright © 2014 Brandon L Black <blblack@gmail.com>
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

#include "daemon.h"

#include <gdnsd/compiler.h>
#include <gdnsd/log.h>
#include <gdnsd/net.h>

#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

// makes sides of int[] from pipe2() clearer
#define PIPE_RD 0
#define PIPE_WR 1

static int daemon_status_pipe = -1;
static bool daemonized = false;

#ifdef __linux__

/********** start systemd stuff *************/

F_NONNULL
static void sysd_notify_ready(void)
{
    const char* spath = getenv("NOTIFY_SOCKET");
    if (!spath)
        return;

    /* Must be an abstract socket, or an absolute path */
    if ((spath[0] != '@' && spath[0] != '/') || spath[1] == 0)
        log_fatal("Invalid NOTIFY_SOCKET path '%s'", spath);

    struct sockaddr_un sun;
    const socklen_t sun_len = gdnsd_sun_set_path(&sun, spath);

    if (sun.sun_path[0] == '@')
        sun.sun_path[0] = 0;

    char msg[64];
    int snp_rv = snprintf(msg, 64, "MAINPID=%lu\nREADY=1", (unsigned long)getpid());
    if (snp_rv < 0 || snp_rv >= 64)
        log_fatal("BUG: sprintf()=>%i in sysd_notify_ready()", snp_rv);

    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        log_fatal("Cannot create AF_UNIX socket");

    struct iovec iov = { .iov_base = msg, .iov_len = strlen(msg) };
    struct msghdr m = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_name = &sun,
        .msg_namelen = sun_len
    };

    ssize_t sm_rv = sendmsg(fd, &m, 0);
    if (sm_rv < 0)
        log_fatal("sendmsg() to systemd NOTIFY_SOCKET failed: %s", logf_errno());

    if (close(fd))
        log_fatal("close() of systemd NOTIFY_SOCKET failed: %s", logf_errno());
}

#endif // __linux__

/************ end systemd stuff *************/

F_NORETURN
static void daemon_fg_waiter(const pid_t middle_pid, const int readpipe)
{
    // First, reap the middle_pid
    int status;
    pid_t wp_rv;
    do {
        errno = 0;
        wp_rv = waitpid(middle_pid, &status, 0);
    } while (wp_rv < 0 && errno == EINTR);

    if (errno || wp_rv < 0)
        log_fatal("waitpid(%li) during daemonization forks failed: %s",
                  (long)middle_pid, logf_errno());
    if (wp_rv != middle_pid)
        log_fatal("waitpid(%li) during daemonization forks caught process %li instead",
                  (long)middle_pid, (long)wp_rv);
    if (status)
        log_fatal("waitpid(%li) returned bad status %i", (long)middle_pid, status);

    // Now wait on the real daemon to report success over the pipe (or not)
    char msg = '0';
    ssize_t read_rv;
    do {
        errno = 0;
        read_rv = read(readpipe, &msg, 1);
    } while (read_rv < 0 && errno == EINTR);

    if (errno || read_rv != 1)
        log_fatal("read() of daemonization status pipe failed with retval %zi: %s", read_rv, logf_errno());
    if (msg != 'X')
        log_fatal("read() of daemonization status pipe returned incorrect data '%c'", msg);

    _exit(0); // Success!
}

static void do_daemonize(void)
{
    // Set up a one-way pipe for foreground's exit status
    // determination.
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC))
        log_fatal("pipe() failed: %s", logf_errno());

    // Fork for the first time...
    const pid_t middle_pid = fork();
    if (middle_pid == -1)
        log_fatal("fork() failed: %s", logf_errno());

    if (middle_pid) { // parent
        close(pipefd[PIPE_WR]);
        daemon_fg_waiter(middle_pid, pipefd[PIPE_RD]); // noreturn
    }

    close(pipefd[PIPE_RD]);
    if (setsid() == -1)
        log_fatal("setsid() failed: %s", logf_errno());

    // Ignore SIGHUP before the second fork to avoid issues
    struct sigaction sa_ign;
    sigemptyset(&sa_ign.sa_mask);
    sa_ign.sa_flags = 0;
    sa_ign.sa_handler = SIG_IGN;
    if (sigaction(SIGHUP, &sa_ign, NULL))
        log_fatal("sigaction(SIGHUP, SIG_IGN) failed: %s", logf_errno());

    // Final fork of real daemon in new session
    const pid_t daemon_pid = fork();
    if (daemon_pid == -1)
        log_fatal("fork() failed: %s", logf_errno());

    // middle process exits immediately here, to be reaped
    // by the original foreground process
    if (daemon_pid)
        _exit(0);

    // --- From here down, we're in the final daemon process only

    // Switch to syslog output and close off stdio
    if (!freopen("/dev/null", "r", stdin))
        log_fatal("Cannot open /dev/null: %s", logf_errno());
    if (!freopen("/dev/null", "w", stdout))
        log_fatal("Cannot open /dev/null: %s", logf_errno());
    if (!freopen("/dev/null", "r+", stderr))
        log_fatal("Cannot open /dev/null: %s", logf_errno());
    gdnsd_log_set_syslog(true, NULL); // should be redundant, but JIC...

    // Save the write end of the pipe for gdnsd_daemon_notify_ready() later
    daemon_status_pipe = pipefd[PIPE_WR];
    daemonized = true;
}

void gdnsd_init_daemon(bool daemonize)
{
    // We never want SIGPIPE (and neither does any sane daemon, right?)
    struct sigaction sa_ign;
    sigemptyset(&sa_ign.sa_mask);
    sa_ign.sa_flags = 0;
    sa_ign.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa_ign, NULL))
        log_fatal("sigaction(SIGPIPE, SIG_IGN) failed: %s", logf_errno());

    if (daemonize)
        do_daemonize();
}

void gdnsd_daemon_notify_ready(void)
{
    if (daemonized) {
        gdnsd_assert(daemon_status_pipe > -1);
        const char msg = 'X';
        if (write(daemon_status_pipe, &msg, 1) != 1)
            log_fatal("write() to daemonization status pipe failed: %s", logf_errno());
        if (close(daemon_status_pipe))
            log_fatal("close() of daemonization status pipe failed: %s", logf_errno());
        daemon_status_pipe = -1;
#ifdef __linux__
    } else {
        sysd_notify_ready();
#endif
    }
}
