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

static struct {
    int mcpsock;
    socks_cfg_t* socks_cfg;
    ev_io* w_mcpsock_read;
    ev_signal* w_sigterm;
    ev_signal* w_sigint;
    ev_signal* w_sighup;
    struct ev_loop* loop;
} rt = {
    .mcpsock = -1,
    .socks_cfg = NULL,
    .w_mcpsock_read = NULL,
    .w_sigterm = NULL,
    .w_sigint = NULL,
    .w_sighup = NULL,
    .loop = NULL,
};

// final tasks for orderly shutdown - after this we send a confirmation to MCP
// before doing exit(0)
static void runtime_shutdown(void) {
    // Ask statio thread to send final stats to the log
    statio_final_stats(rt.loop);

    // get rid of child procs (e.g. extmon helper)
    gdnsd_kill_registered_children();

    // deallocate resources in debug mode
    atexit_debug_execute();
}

// Try to bump SO_SNDBUF to the expected transmit size, just in case
static void adjust_mcpsock_sndbuf(const unsigned datasize) {
    if(datasize < 4096U)
        return;
    int opt_size = (int)datasize;
    if(setsockopt(rt.mcpsock, SOL_SOCKET, SO_SNDBUF, &opt_size, sizeof(opt_size)))
        dmn_log_warn("Failed to set SO_SNDBUF to %i for anonymous socketpair: %s",
                     opt_size, dmn_logf_errno());
}

F_NONNULL
static void mcp_write(const char* data, const unsigned len) {
    dmn_assert(data); dmn_assert(len);

    // blocking write
    if(fcntl(rt.mcpsock, F_SETFL, (fcntl(rt.mcpsock, F_GETFL, 0)) & ~O_NONBLOCK) == -1)
        dmn_log_fatal("Failed to clear O_NONBLOCK on mcp socket: %s", dmn_logf_errno());

    int writerv = 0;
    do {
        errno = 0;
        writerv = write(rt.mcpsock, data, len);
    } while(writerv < 0 && errno == EINTR);

    if(writerv < 0 || (unsigned)writerv != len)
        log_fatal("Runtime->MCP comms error: %s", dmn_logf_errno());

    if(len == 1)
        dmn_log_debug("Runtime: MCP accepted message %c", data[0]);
    else
        dmn_log_debug("Runtime: MCP accepted %u bytes of data", len);

    // non-blocking for loop re-entry and next read
    if(fcntl(rt.mcpsock, F_SETFL, (fcntl(rt.mcpsock, F_GETFL, 0)) | O_NONBLOCK) == -1)
        dmn_log_fatal("Failed to set O_NONBLOCK on mcp socket: %s", dmn_logf_errno());
}

static void wait_and_listen(void) {
    // blocking read
    if(fcntl(rt.mcpsock, F_SETFL, (fcntl(rt.mcpsock, F_GETFL, 0)) & ~O_NONBLOCK) == -1)
        dmn_log_fatal("Failed to clear O_NONBLOCK on mcp socket: %s", dmn_logf_errno());

    char msg;
    int readrv = 0;
    do {
        errno = 0;
        readrv = read(rt.mcpsock, &msg, 1);
    } while(readrv < 0 && errno == EINTR);

    if(readrv != 1) {
        dmn_assert(readrv < 1);
        if(readrv < 0)
            dmn_log_fatal("Runtime<-MCP comms: exiting on socket error: %s", dmn_logf_errno());
        else
            dmn_log_fatal("Runtime<-MCP comms: unexpected socket close");
    }

    if(msg != MSG_2RT_OK_TO_LISTEN)
        dmn_log_fatal("Runtime<-MCP: unexpected input %c", msg);
    const unsigned max_json = statio_start(rt.loop, rt.socks_cfg->num_dns_threads);
    if(max_json > EXPECTED_MAX_JSON)
        dmn_log_fatal("BUG: Stats buffer size %u is larger than expected", max_json);
    adjust_mcpsock_sndbuf(max_json + 5);
    start_threads(rt.socks_cfg);
    log_info("DNS listeners started");
    mcp_write(&MSG_2MCP_LISTENING, 1);

    // non-blocking for loop re-entry and next read
    if(fcntl(rt.mcpsock, F_SETFL, (fcntl(rt.mcpsock, F_GETFL, 0)) | O_NONBLOCK) == -1)
        dmn_log_fatal("Failed to set O_NONBLOCK on mcp socket: %s", dmn_logf_errno());
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

    if(msg == MSG_2RT_SHUTDOWN) {
        log_info("Runtime: shutting down on MCP request");
        runtime_shutdown();
        mcp_write(&MSG_2MCP_SHUTDOWN, 1);
        exit(0);
    }

    if(msg == MSG_2RT_STATS) {
        unsigned jlen;
        const char* jdata = statio_get_json(&jlen);
        union {
            uint32_t u32;
            char i8;
        } jl;
        jl.u32 = jlen;
        mcp_write(&MSG_2MCP_STATS, 1);
        mcp_write(&jl.i8, 4);
        mcp_write(jdata, jlen);
        return;
    }

    dmn_log_fatal("Runtime<-MCP: unexpected input %c", msg);
}

static void rt_sighandle(struct ev_loop* loop, ev_signal* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_SIGNAL);
    log_info("Runtime: ignoring signal %i (send it to the main process instead)", w->signum);
}

void runtime(vscf_data_t* cfg_root, socks_cfg_t* socks_cfg, const bool force_zss, const bool force_zsd, const int mcp_sock) {
    dmn_assert(socks_cfg);
    dmn_assert(mcp_sock >= 0);

    // set these as rt-global data
    rt.mcpsock = mcp_sock;
    rt.socks_cfg = socks_cfg;

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

    // ask MCP to bind our DNS sockets
    mcp_write(&MSG_2MCP_BIND_SOCKS, 1);

    // Set up MCP socket and signal watchers
    rt.w_mcpsock_read = xmalloc(sizeof(ev_io));
    ev_io_init(rt.w_mcpsock_read, rt_mcpsock_read, rt.mcpsock, EV_READ);
    ev_io_start(rt.loop, rt.w_mcpsock_read);

    rt.w_sigterm = xmalloc(sizeof(ev_signal));
    ev_signal_init(rt.w_sigterm, rt_sighandle, SIGTERM);
    ev_signal_start(rt.loop, rt.w_sigterm);

    rt.w_sigint = xmalloc(sizeof(ev_signal));
    ev_signal_init(rt.w_sigint, rt_sighandle, SIGINT);
    ev_signal_start(rt.loop, rt.w_sigint);

    rt.w_sighup = xmalloc(sizeof(ev_signal));
    ev_signal_init(rt.w_sighup, rt_sighandle, SIGHUP);
    ev_signal_start(rt.loop, rt.w_sighup);

    // wait for MCP to finish binding, start DNS listeners...
    wait_and_listen();

    // Start the loop for normal runtime MCP requests + signals - no return!
    ev_run(rt.loop, 0);
    dmn_assert(0);
}
