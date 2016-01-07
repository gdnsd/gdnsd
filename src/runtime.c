/* Copyright © 2016 Brandon L Black <blblack@gmail.com>
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
#include "runtime.h"

#include "mcp.h"
#include "socks.h"
#include "conf.h"
#include "dnsio_tcp.h"
#include "dnsio_udp.h"
#include "dnspacket.h"
#include "statio.h"
#include "ztree.h"
#include "zsrc_rfc1035.h"
#include "zsrc_djb.h"

#include <gdnsd-prot/plugapi.h>
#include <gdnsd-prot/misc.h>
#include <gdnsd-prot/mon.h>
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/vscf.h>
#include <gdnsd/paths.h>
#include <gdnsd/misc.h>
#include <gdnsd/cs.h>

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <pwd.h>
#include <time.h>

// custom atexit-like stuff, only for resource
//   de-allocation in debug builds to check for leaks

#ifndef NDEBUG

static void (**exitfuncs)(void) = NULL;
static unsigned exitfuncs_pending = 0;

void gdnsd_atexit_debug(void (*f)(void)) {
    dmn_assert(f);
    exitfuncs = xrealloc(exitfuncs, (exitfuncs_pending + 1) * sizeof(void (*)(void)));
    exitfuncs[exitfuncs_pending++] = f;
}

static void atexit_debug_execute(void) {
    while(exitfuncs_pending--)
       exitfuncs[exitfuncs_pending]();
}

#else

void gdnsd_atexit_debug(void (*f)(void) V_UNUSED) { }
static void atexit_debug_execute(void) { }

#endif

// thread entry point for zone data reloader thread
static void* zone_data_runtime(void* unused V_UNUSED) {
    gdnsd_thread_setname("gdnsd-zones");

    struct ev_loop* zdata_loop = ev_loop_new(EVFLAG_AUTO);
    if(!zdata_loop)
        log_fatal("Could not initialize the zone data libev loop");

    zsrc_djb_runtime_init(zdata_loop);
    zsrc_rfc1035_runtime_init(zdata_loop);

    ev_run(zdata_loop, 0);

    dmn_assert(0); // should never be reached as loop never terminates
    ev_loop_destroy(zdata_loop);
    return NULL;
}

F_NONNULL
static void start_threads(socks_cfg_t* socks_cfg) {
    dmn_assert(socks_cfg);

    // Block all signals using the pthreads interface while starting threads,
    //  which causes them to inherit the same mask.
    sigset_t sigmask_all;
    sigfillset(&sigmask_all);
    sigset_t sigmask_prev;
    sigemptyset(&sigmask_prev);
    if(pthread_sigmask(SIG_SETMASK, &sigmask_all, &sigmask_prev))
        log_fatal("pthread_sigmask() failed");

    // system scope scheduling, detached threads
    pthread_attr_t attribs;
    pthread_attr_init(&attribs);
    pthread_attr_setdetachstate(&attribs, PTHREAD_CREATE_DETACHED);
    pthread_attr_setscope(&attribs, PTHREAD_SCOPE_SYSTEM);

    int pthread_err;

    for(unsigned i = 0; i < socks_cfg->num_dns_threads; i++) {
        dns_thread_t* t = &socks_cfg->dns_threads[i];
        if(t->is_udp)
            pthread_err = pthread_create(&t->threadid, &attribs, &dnsio_udp_start, t);
        else
            pthread_err = pthread_create(&t->threadid, &attribs, &dnsio_tcp_start, t);
        if(pthread_err)
            log_fatal("pthread_create() of DNS thread %u (for %s:%s) failed: %s",
                i, t->is_udp ? "UDP" : "TCP", dmn_logf_anysin(&t->ac->addr), dmn_logf_strerror(pthread_err));
    }

    pthread_t zone_data_threadid;
    pthread_err = pthread_create(&zone_data_threadid, &attribs, &zone_data_runtime, NULL);
    if(pthread_err)
        log_fatal("pthread_create() of zone data thread failed: %s", dmn_logf_strerror(pthread_err));

    // This waits for all of the stat structures to be allocated
    //  by the i/o threads before continuing on.  They must be ready
    //  before we enter monitoring code within the main thread later.
    dnspacket_wait_stats(socks_cfg);

    // Restore the original mask in the main thread, so
    //  we can continue handling signals like normal
    if(pthread_sigmask(SIG_SETMASK, &sigmask_prev, NULL))
        log_fatal("pthread_sigmask() failed");
    pthread_attr_destroy(&attribs);
}

typedef enum {
    RT_WRITING_MSG_2MCP_BIND_SOCKS,
    RT_WAITING_MSG_2RT_OK_TO_LISTEN,
    RT_WRITING_MSG_2MCP_LISTENING,
    RT_IDLE,
    RT_WRITING_MSG_2MCP_SHUTDOWN,
} rt_state_t;

static struct {
    rt_state_t state;
    int mcpsock;
    socks_cfg_t* socks_cfg;
    ev_io* w_mcpsock_read;
    ev_io* w_mcpsock_write;
    ev_signal* w_sigterm;
    ev_signal* w_sigint;
    ev_signal* w_sighup;
    struct ev_loop* loop;
    gdnsd_css_t* css;
} rt = {
    .state = RT_WRITING_MSG_2MCP_BIND_SOCKS,
    .mcpsock = -1,
    .socks_cfg = NULL,
    .w_mcpsock_read = NULL,
    .w_mcpsock_write = NULL,
    .w_sigterm = NULL,
    .w_sigint = NULL,
    .w_sighup = NULL,
    .loop = NULL,
    .css = NULL,
};

F_NONNULLX(1, 2)
static bool css_handler(uint8_t* buffer V_UNUSED, uint32_t* len V_UNUSED, void* data V_UNUSED) {
    dmn_assert(buffer); dmn_assert(len);
    // with no code here, will echo to client
    return false;
}

// final tasks for orderly shutdown - after this we send a confirmation to MCP
// before doing exit(0)
static void runtime_shutdown(void) {
    // Stop our control socket so we don't get new connections/requests while
    // running through the shutdown sequence internally and with the MCP
    gdnsd_css_delete(rt.css);

    // Ask statio thread to send final stats to the log
    statio_final_stats(rt.loop);

    // get rid of child procs (e.g. extmon helper)
    gdnsd_kill_registered_children();

    // deallocate resources in debug mode
    atexit_debug_execute();
}

static void rt_mcpsock_read(struct ev_loop* loop, ev_io* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_READ);

    char msg;
    int readrv = read(w->fd, &msg, 1);
    if(readrv != 1) {
        dmn_assert(readrv < 1);
        if(readrv < 0) {
            if(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            dmn_log_fatal("Runtime<-MCP comms: exiting on socket error: %s", dmn_logf_errno());
        }
        else {
            dmn_log_fatal("Runtime<-MCP comms: unexpected socket close");
        }
    }

    // note the reuseport/pidfile interactions in the cases below,
    // which affect the availabilty penalty on a true-restart:
    // if reuseport works, we bind->listen->kill-previous-daemon
    // if not, we kill-previous-daemon->bind->listen
    switch(rt.state) {
        case RT_WAITING_MSG_2RT_OK_TO_LISTEN:
            if(msg != MSG_2RT_OK_TO_LISTEN)
                dmn_log_fatal("Runtime<-MCP: unexpected input %c", msg);
            start_threads(rt.socks_cfg);
            statio_start(rt.loop, rt.socks_cfg);
            char* path = gdnsd_resolve_path_run("rt.sock", NULL);
            rt.css = gdnsd_css_new(path, css_handler, NULL, 100, 1024, 16, 300); // XXX tunables...
            free(path);
            log_info("DNS listeners started");
            rt.state = RT_WRITING_MSG_2MCP_LISTENING;
            ev_io_start(loop, rt.w_mcpsock_write);
            break;
        case RT_IDLE:
            if(msg != MSG_2RT_SHUTDOWN)
                dmn_log_fatal("Runtime<-MCP: unexpected input %c", msg);
            log_info("Runtime: shutting down on MCP request");
            runtime_shutdown();
            rt.state = RT_WRITING_MSG_2MCP_SHUTDOWN;
            ev_io_start(loop, rt.w_mcpsock_write);
            break;
        case RT_WRITING_MSG_2MCP_BIND_SOCKS: // fall-through intentional
        case RT_WRITING_MSG_2MCP_LISTENING:  // fall-through intentional
        case RT_WRITING_MSG_2MCP_SHUTDOWN:   // fall-through intentional
            dmn_log_fatal("Runtime<-MCP: unexpected input %c", msg);
            break;
        default:
            dmn_assert(0);
    }
}

static void rt_mcpsock_write(struct ev_loop* loop, ev_io* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_WRITE);

    char msg;
    rt_state_t next_state;
    switch(rt.state) {
        case RT_WRITING_MSG_2MCP_BIND_SOCKS:
            msg = MSG_2MCP_BIND_SOCKS;
            next_state = RT_WAITING_MSG_2RT_OK_TO_LISTEN;
            break;
        case RT_WRITING_MSG_2MCP_LISTENING:
            msg = MSG_2MCP_LISTENING;
            next_state = RT_IDLE;
            break;
        case RT_WRITING_MSG_2MCP_SHUTDOWN:
            msg = MSG_2MCP_SHUTDOWN;
            next_state = RT_WRITING_MSG_2MCP_SHUTDOWN; // no true next state...
            break;
        default:
            // In all other states, we don't have an active write watcher
            dmn_assert(0);
    }

    int writerv = write(w->fd, &msg, 1);
    if(writerv != 1) {
        dmn_assert(writerv < 0);
        if(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        log_fatal("Runtime->MCP comms error: %s", dmn_logf_errno());
    }
    dmn_log_debug("Runtime: MCP accepted message %c", msg);

    ev_io_stop(rt.loop, rt.w_mcpsock_write);
    rt.state = next_state;

    // special case: exit after successful send of shutdown confirmation
    if(rt.state == RT_WRITING_MSG_2MCP_SHUTDOWN)
        exit(0);

    // special case: accept csock connections on entering RT_IDLE
    if(rt.state == RT_IDLE)
        gdnsd_css_start(rt.css, rt.loop);
}

static void rt_sighandle(struct ev_loop* loop, ev_signal* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_SIGNAL);
    log_info("Runtime: ignoring signal %i (send it to the main process instead)", w->signum);
}

DMN_F_NORETURN
static void runtime_loop(const int mcpsock, socks_cfg_t* socks_cfg) {
    rt.mcpsock = mcpsock;
    rt.socks_cfg = socks_cfg;

    // non-block for mcpsock
    if(fcntl(rt.mcpsock, F_SETFL, (fcntl(rt.mcpsock, F_GETFL, 0)) | O_NONBLOCK) == -1)
        dmn_log_fatal("Failed to set O_NONBLOCK on mcp socket: %s", dmn_logf_errno());

    // Set up socket watchers
    rt.w_mcpsock_read = xmalloc(sizeof(ev_io));
    rt.w_mcpsock_write = xmalloc(sizeof(ev_io));
    rt.w_sigterm = xmalloc(sizeof(ev_signal));
    rt.w_sigint = xmalloc(sizeof(ev_signal));
    rt.w_sighup = xmalloc(sizeof(ev_signal));
    ev_io_init(rt.w_mcpsock_read, rt_mcpsock_read, rt.mcpsock, EV_READ);
    ev_io_init(rt.w_mcpsock_write, rt_mcpsock_write, rt.mcpsock, EV_WRITE);
    ev_signal_init(rt.w_sigterm, rt_sighandle, SIGTERM);
    ev_signal_init(rt.w_sigint, rt_sighandle, SIGINT);
    ev_signal_init(rt.w_sighup, rt_sighandle, SIGHUP);

    ev_io_start(rt.loop, rt.w_mcpsock_read);
    ev_io_start(rt.loop, rt.w_mcpsock_write);
    ev_signal_start(rt.loop, rt.w_sigterm);
    ev_signal_start(rt.loop, rt.w_sigint);
    ev_signal_start(rt.loop, rt.w_sighup);

    // Start the loop - does not return!
    ev_run(rt.loop, 0);
    dmn_assert(0);
}

void runtime(vscf_data_t* cfg_root, socks_cfg_t* socks_cfg, const bool force_zss, const bool force_zsd, const int mcp_sock) {
    dmn_assert(socks_cfg);
    dmn_assert(mcp_sock >= 0);

    // Process the bulk of the configuration, including loading plugins, etc...
    conf_load(cfg_root, socks_cfg, force_zss, force_zsd);
    vscf_destroy(cfg_root);

    // Load zone data.
    ztree_init(false);

    // Construct the runtime loop, which controls this main thread at runtime.
    // Note that monitoring and statio also re-use our primary thread/loop
    // note ev_default_loop() would create a SIGCHLD handler internal to
    // libev, so we're using ev_loop_new() to avoid that so that our waitpid()
    // logic works out...
    rt.loop = ev_loop_new(EVFLAG_AUTO);
    if(!rt.loop)
        log_fatal("Could not initialize the primary libev loop");

    // Initialize dnspacket stats stuff
    dnspacket_global_setup(socks_cfg);

    // set up monitoring, which expects an initially empty loop
    //  and needs the inter-thread stats pointers set up above
    gdnsd_mon_start(rt.loop);

    // Call plugin pre-run actions
    gdnsd_plugins_action_pre_run();

    // Runtime eventloop, never returns
    runtime_loop(mcp_sock, socks_cfg);
    dmn_assert(0);
}
