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

#include "extmon_comms.h"

#include <gdnsd/alloc.h>
#include <gdnsd/compiler.h>
#include <gdnsd/log.h>

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>

#include <ev.h>

// hopefully everyone defines this
#ifndef NSIG
#  define NSIG 100
#endif

typedef struct {
    extmon_cmd_t* cmd;
    ev_timer* interval_timer;
    ev_timer* cmd_timeout;
    ev_child* child_watcher;
    pid_t cmd_pid;
    bool result_pending;
} mon_t;

static unsigned num_mons = 0;
static mon_t* mons = NULL;

static unsigned num_proc = 0;

F_NONNULL F_NORETURN
static void syserr_for_ev(const char* msg) { dmn_assert(msg); log_fatal("%s: %s", msg, dmn_logf_errno()); }

static int plugin_read_fd = -1;
static int plugin_write_fd = -1;
static ev_io* plugin_write_watcher = NULL;
static ev_signal* sigterm_watcher = NULL;
static ev_signal* sigint_watcher = NULL;
static ev_signal* sighup_watcher = NULL;
static int killed_by = 0;

/*************************************************************************/
// This implements a simple unidirectional FIFO queue for buffering
//   monitoring results written via the pipe back to the main daemon.
// The queue is actually an array with moving head pointer that
//   wraps circularly, and is resized via re-allocation when necc.

static uint32_t* sendq = NULL;
static unsigned sendq_alloc = 0;
static unsigned sendq_len = 0;
static unsigned sendq_head = 0;

// must be power of 2!
#define SENDQ_INITSIZE 16
static void sendq_init(void) {
    sendq = xmalloc(SENDQ_INITSIZE * sizeof(uint32_t));
    sendq_alloc = SENDQ_INITSIZE;
}

static bool sendq_empty(void) { return !sendq_len; }

static void sendq_enq(uint32_t new_data) {
    if(likely(sendq_len < sendq_alloc)) {
        sendq[(sendq_head + sendq_len) & (sendq_alloc - 1)] = new_data;
    }
    else {
        // buffer too small, upsize first (we never downsize)
        const unsigned old_mask = sendq_alloc - 1;
        sendq_alloc <<= 1;
        uint32_t* newq = xmalloc(sendq_alloc * sizeof(uint32_t));
        for(unsigned i = 0; i < sendq_len; i++)
            newq[i] = sendq[(sendq_head + i) & old_mask];
        newq[sendq_len] = new_data;
        free(sendq);
        sendq = newq;
        sendq_head = 0;
    }
    sendq_len++;
}

// de-queue is split into a data-fetch (_peek()) and
//   a commit operation which actually deletes the
//   fetched item from the queue.  This allows for
//   temporary failure of network write of the
//   item being dequeued without having to push back
//   onto the queue.
// Callers must check _empty() before de-queueing since
//   _peek()'s return is a literal value and thus there's
//   no good way to signal emptiness from it.

static uint32_t sendq_deq_peek(void) {
    dmn_assert(!sendq_empty());
    return sendq[sendq_head];
}

static void sendq_deq_commit(void) {
    dmn_assert(!sendq_empty());
    sendq_head++;
    sendq_head &= (sendq_alloc - 1);
    sendq_len--;
}

/*************************************************************************/

static void mon_timeout_cb(struct ev_loop* loop, ev_timer* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_TIMER);

    mon_t* this_mon = w->data;
    dmn_assert(this_mon->result_pending);
    dmn_log_warn("Monitor child process for '%s' timed out after %u seconds.  Marking failed and sending SIGKILL...", this_mon->cmd->desc, this_mon->cmd->timeout);
    kill(this_mon->cmd_pid, SIGKILL);
    // note we don't stop the child_watcher because we still
    //   wait to reap the status below.  I suppose technically
    //   if SIGKILL doesn't work (e.g. stupid blocking NFS thing
    //   in child proc), eventually we'll hit a new interval
    //   and restart the child watcher for a new child, effectively
    //   giving up on waitpid() of this child.  Not much else we
    //   could do in that case anyways.
    if(!killed_by) {
        sendq_enq(emc_encode_mon(this_mon->cmd->idx, true));
        ev_io_start(loop, plugin_write_watcher);
    }
    if (num_proc > 0) {
        num_proc--;
    }
    this_mon->result_pending = false;
}

static void mon_child_cb(struct ev_loop* loop, ev_child* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_CHILD);

    ev_child_stop(loop, w); // always single-shot

    mon_t* this_mon = w->data;
    ev_timer_stop(loop, this_mon->cmd_timeout);
    this_mon->cmd_pid = 0;

    bool failed = true;
    int status = w->rstatus;
    if(WIFEXITED(status)) {
        if(!WEXITSTATUS(status))
           failed = false;
    }
    else {
        if(WIFSIGNALED(status))
            dmn_log_warn("Monitor child process for '%s' terminated by signal %u", this_mon->cmd->desc, WTERMSIG(status));
        else
            dmn_log_warn("Monitor child process for '%s' terminated abnormally...", this_mon->cmd->desc);
    }

    // If timeout already sent a failure, don't double-send
    //   here when we reap the SIGKILL'd child
    if(this_mon->result_pending) {
        if(!killed_by) {
            sendq_enq(emc_encode_mon(this_mon->cmd->idx, failed));
            ev_io_start(loop, plugin_write_watcher);
        }
        if (num_proc > 0) {
            num_proc--;
        }
        this_mon->result_pending = false;
    }
}

static void mon_interval_cb(struct ev_loop* loop, ev_timer* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_TIMER);

    mon_t* this_mon = w->data;
    dmn_assert(!this_mon->result_pending);

    if (this_mon->cmd->max_proc > 0 && num_proc >= this_mon->cmd->max_proc) {
        // If more than max_proc processes are running, reschedule excess
        //   checks to run 0.1 seconds later. After a few passes, this will
        //   smooth the schedule out to prevent a thundering herd.
        ev_timer_stop(loop, this_mon->interval_timer);
        ev_timer_set(this_mon->interval_timer, 0.1, this_mon->cmd->interval);
        ev_timer_start(loop, this_mon->interval_timer);
        return;
    }

    // Before forking, block all signals and save the old mask
    //   to avoid a race condition where local sighandlers execute
    //   in the child between fork and exec().
    sigset_t all_sigs;
    sigfillset(&all_sigs);
    sigset_t saved_mask;
    sigemptyset(&saved_mask);
    if(pthread_sigmask(SIG_SETMASK, &all_sigs, &saved_mask))
        log_fatal("pthread_sigmask() failed");

    this_mon->cmd_pid = fork();
    if(this_mon->cmd_pid == -1)
        log_fatal("fork() failed: %s", dmn_logf_strerror(errno));

    if(!this_mon->cmd_pid) { // child
        // reset all signal handlers to default before unblocking
        struct sigaction defaultme;
        sigemptyset(&defaultme.sa_mask);
        defaultme.sa_handler = SIG_DFL;
        defaultme.sa_flags = 0;

        // we really don't care about error retvals here
        for(int i = 0; i < NSIG; i++)
            (void)sigaction(i, &defaultme, NULL);

        // unblock all
        sigset_t no_sigs;
        sigemptyset(&no_sigs);
        if(pthread_sigmask(SIG_SETMASK, &no_sigs, NULL))
            log_fatal("pthread_sigmask() failed");

        // technically, we could go ahead and close off stdout/stderr
        //   here for the "startfg" case, but why bother?  If the user
        //   is debugging via startfg they might want to see this crap anyways.
        execv(this_mon->cmd->args[0], this_mon->cmd->args);
        log_fatal("execv(%s, ...) failed: %s", this_mon->cmd->args[0], dmn_logf_strerror(errno));
    }
    num_proc++;

    // restore previous signal mask from before fork in parent
    if(pthread_sigmask(SIG_SETMASK, &saved_mask, NULL))
        log_fatal("pthread_sigmask() failed");

    this_mon->result_pending = true;
    ev_timer_set(this_mon->cmd_timeout, this_mon->cmd->timeout, 0);
    ev_timer_start(loop, this_mon->cmd_timeout);
    ev_child_set(this_mon->child_watcher, this_mon->cmd_pid, 0);
    ev_child_start(loop, this_mon->child_watcher);
}

static void plugin_write_cb(struct ev_loop* loop, ev_io* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_WRITE);

    dmn_assert(plugin_write_fd > -1);
    while(!sendq_empty()) {
        const uint32_t data = sendq_deq_peek();
        ssize_t write_rv = write(plugin_write_fd, &data, 4);
        if(write_rv != 4) {
            if(write_rv < 0) {
                if(errno == EAGAIN || errno == EWOULDBLOCK)
                    return; // pipe full, wait for more libev notification of write-ready
                else if(errno == EINTR)
                    continue; // try this write again immediately
                else {
                    ev_break(loop, EVBREAK_ALL);
                    return;
                }
            }
            else if(write_rv == 0) {
                ev_break(loop, EVBREAK_ALL);
                return;
            }
            else {
                log_fatal("BUG: atomic pipe write of 4 bytes was not atomic, retval was %zi", write_rv);
            }
        }
        sendq_deq_commit();
    }
    ev_io_stop(loop, w); // queue now empty

    if(killed_by) { // we've sent our final message, close
        close(plugin_write_fd);
        plugin_write_fd = -1;
    }
}

F_NONNULL
static void die_gracefully(struct ev_loop* loop) {
    dmn_assert(loop);

    dmn_assert(killed_by);
    static bool done_once = false;
    if(!done_once) { // avoid repetition
        done_once = true;
        // send friendly death message to plugin
        sendq_enq(emc_encode_exit());
        ev_io_start(loop, plugin_write_watcher);
        // kill interval timers for future invocations
        //   and immediately clamp the remaining timeout
        //   for any running commands to 2.0s.
        for(unsigned i = 0; i < num_mons; i++) {
            ev_timer_stop(loop, mons[i].interval_timer);
            if(ev_is_active(mons[i].cmd_timeout)) {
                if(ev_timer_remaining(loop, mons[i].cmd_timeout) > 2.0) {
                    ev_timer_stop(loop, mons[i].cmd_timeout);
                    ev_timer_set(mons[i].cmd_timeout, 2.0, 0.);
                    ev_timer_start(loop, mons[i].cmd_timeout);
                }
            }
        }
    }
}

F_NONNULL
static void sig_cb(struct ev_loop* loop, ev_signal* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_SIGNAL);
    switch(w->signum) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
            killed_by = w->signum;
            dmn_log_info("Got terminal signal %i, starting graceful exit", killed_by);
            die_gracefully(loop);
            break;
        default:
            dmn_assert(0);
    }
}

int main(int argc, char** argv) {
    // Bail out early if we don't have the right argument
    //   count, and try to tell the user not to run us
    //   if stderr happens to be hooked up to a terminal
    if(argc != 5) {
        fprintf(stderr, "This binary is not for human execution!\n");
        exit(99);
    }

    bool debug = false;
    if(!strcmp(argv[1], "Y"))
        debug = true;

    bool use_syslog = false;
    if(!strcmp(argv[2], "S"))
        use_syslog = true;

    dmn_init(debug, true, use_syslog, "gdnsd_extmon_helper");
    // Note that gdnsd_initialize() would be standard here, but extmon_helper
    // is special: it doesn't actually make use of most of libgdnsd, just the
    // very basic compiler, allocator, and libdmn logging bits.

    // regardless, we seal off stdin now.  We don't need it,
    //   and this way we don't have to deal with it when
    //   execv()-ing child commands later.
    if(!freopen("/dev/null", "r", stdin))
        dmn_log_fatal("Cannot open /dev/null: %s", dmn_logf_strerror(errno));

    // Also unconditionally unset NOTIFY_SOCKET here so that children
    //   don't get any ideas about talking to systemd on our behalf.
    //   (we're done using it in this process for libdmn stuff at this point)
    unsetenv("NOTIFY_SOCKET");

    // these are the main communication pipes to the daemon/plugin
    plugin_read_fd = atoi(argv[3]);
    plugin_write_fd = atoi(argv[4]);

    if(plugin_read_fd < 3 || plugin_read_fd > 1000
        || plugin_write_fd < 3 || plugin_write_fd > 1000)
        log_fatal("Invalid pipe descriptors!");

    if(emc_read_exact(plugin_read_fd, "HELO"))
        log_fatal("Failed to read HELO from plugin");
    if(emc_write_string(plugin_write_fd, "HELO_ACK", 8))
        log_fatal("Failed to write HELO_ACK to plugin");

    uint8_t ccount_buf[7];
    if(emc_read_nbytes(plugin_read_fd, 7, ccount_buf)
        || strncmp((char*)ccount_buf, "CMDS:", 5))
        log_fatal("Failed to read command count from plugin");
    num_mons = ((unsigned)ccount_buf[5] << 8) + ccount_buf[6];
    if(!num_mons)
        log_fatal("Received command count of zero from plugin");
    mons = xcalloc(num_mons, sizeof(mon_t));

    if(emc_write_string(plugin_write_fd, "CMDS_ACK", 8))
        log_fatal("Failed to write CMDS_ACK to plugin");

    // Note, it's merely a happy coincidence that our mons[]
    //   indices exactly match cmd->idx numbers.  Always use
    //   the cmd->idx numbers as the official index when talking
    //   to the main daemon!
    for(unsigned i = 0; i < num_mons; i++) {
        mons[i].cmd = emc_read_command(plugin_read_fd);
        if(!mons[i].cmd)
            log_fatal("Failed to read command %u from plugin", i);
        if(i != mons[i].cmd->idx)
            log_fatal("BUG: plugin index issues, %u vs %u", i, mons[i].cmd->idx);
        if(emc_write_string(plugin_write_fd, "CMD_ACK", 7))
            log_fatal("Failed to write CMD_ACK for command %u to plugin", i);
    }

    if(emc_read_exact(plugin_read_fd, "END_CMDS"))
        log_fatal("Failed to read END_CMDS from plugin");
    if(emc_write_string(plugin_write_fd, "END_CMDS_ACK", 12))
        log_fatal("Failed to write END_CMDS_ACK to plugin");

    // done with the serial setup, close the readpipe and go nonblocking on write for eventloop...
    close(plugin_read_fd);
    if(fcntl(plugin_write_fd, F_SETFL, (fcntl(plugin_write_fd, F_GETFL, 0)) | O_NONBLOCK) == -1)
        log_fatal("Failed to set O_NONBLOCK on pipe: %s", dmn_logf_errno());

    // CLOEXEC the write fd so child scripts can't mess with it
    if(fcntl(plugin_write_fd, F_SETFD, FD_CLOEXEC))
        log_fatal("Failed to set FD_CLOEXEC on plugin write fd: %s", dmn_logf_strerror(errno));

    // init results-sending queue
    sendq_init();

    // Set up libev error callback
    ev_set_syserr_cb(&syserr_for_ev);

    // Construct the default loop for the main thread
    struct ev_loop* def_loop = ev_default_loop(EVFLAG_AUTO);
    if(!def_loop) log_fatal("Could not initialize the default libev loop");

    // Catch SIGINT/TERM/HUP, and do not let them prevent loop exit
    sigterm_watcher = xmalloc(sizeof(ev_signal));
    sigint_watcher = xmalloc(sizeof(ev_signal));
    sighup_watcher = xmalloc(sizeof(ev_signal));
    ev_signal_init(sigterm_watcher, sig_cb, SIGTERM);
    ev_signal_init(sigint_watcher, sig_cb, SIGINT);
    ev_signal_init(sighup_watcher, sig_cb, SIGHUP);
    ev_signal_start(def_loop, sigterm_watcher);
    ev_signal_start(def_loop, sigint_watcher);
    ev_signal_start(def_loop, sighup_watcher);
    ev_unref(def_loop);
    ev_unref(def_loop);
    ev_unref(def_loop);

    // set up primary read/write watchers on the pipe to the daemon's plugin
    plugin_write_watcher = xmalloc(sizeof(ev_io));
    ev_io_init(plugin_write_watcher, plugin_write_cb, plugin_write_fd, EV_WRITE);
    ev_set_priority(plugin_write_watcher, 1);

    // set up interval watchers for each monitor, initially for immediate firing
    //   for the daemon's monitoring init cycle, then repeating every interval.
    for(unsigned i = 0; i < num_mons; i++) {
        mon_t* this_mon = &mons[i];
        this_mon->interval_timer = xmalloc(sizeof(ev_timer));
        ev_timer_init(this_mon->interval_timer, mon_interval_cb, 0., this_mon->cmd->interval);
        this_mon->interval_timer->data = this_mon;
        ev_set_priority(this_mon->interval_timer, 0);
        ev_timer_start(def_loop, this_mon->interval_timer);

        // initialize the other watchers in the mon_t here as well,
        //   but do not start them (the interval callback starts them each interval)
        this_mon->cmd_timeout = xmalloc(sizeof(ev_timer));
        ev_timer_init(this_mon->cmd_timeout, mon_timeout_cb, 0, 0);
        ev_set_priority(this_mon->cmd_timeout, -1);
        this_mon->cmd_timeout->data = this_mon;

        this_mon->child_watcher = xmalloc(sizeof(ev_child));
        ev_child_init(this_mon->child_watcher, mon_child_cb, 0, 0);
        this_mon->child_watcher->data = this_mon;
    }

    log_info("gdnsd_extmon_helper running");
    ev_run(def_loop, 0);

    // graceful shutdown should have cleared out children, but
    // the hard kill/wait below is for (a) ungraceful shutdown
    // on unexpected pipe close and (b) anything else going wrong
    // during graceful shutdown.
    bool needs_wait = false;
    for(unsigned i = 0; i < num_mons; i++) {
        if(mons[i].cmd_pid) {
            log_debug("not-so-graceful shutdown: sending SIGKILL to %li", (long)mons[i].cmd_pid);
            kill(mons[i].cmd_pid, SIGKILL);
            needs_wait = true;
        }
    }

    if(needs_wait) {
        unsigned i = 500; // 5s for OS to give us all the SIGKILL'd zombies
        while(i--) {
            pid_t wprv = waitpid(-1, NULL, WNOHANG);
            if(wprv < 0) {
                if(errno == ECHILD)
                    break;
                else
                    log_fatal("waitpid(-1, NULL, WNOHANG) failed: %s", dmn_logf_errno());
            }
            if(wprv)
                log_debug("not-so-graceful shutdown: waitpid reaped %li", (long)wprv);
            const struct timespec ms_10 = { 0, 10000000 };
            nanosleep(&ms_10, NULL);
        }
    }

    // Bye!
    if(killed_by) {
        log_info("gdnsd_extmon_helper exiting gracefully due to signal %i", killed_by);
#ifdef COVERTEST_EXIT
        exit(0);
#else
        raise(killed_by);
#endif
    }
    else {
        log_info("gdnsd_extmon_helper exiting un-gracefully");
        exit(42);
    }
}
