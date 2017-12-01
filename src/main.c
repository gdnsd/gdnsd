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
#include "main.h"

#include "conf.h"
#include "socks.h"
#include "daemon.h"
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
#include <gdnsd/net.h>
#include <gdnsd/vscf.h>
#include <gdnsd/paths.h>
#include <gdnsd/misc.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <pwd.h>
#include <time.h>

// ev loop used for monitoring and statio
// (which shared a thread as well)
static struct ev_loop* mon_loop = NULL;

// custom atexit-like stuff, only for resource
//   de-allocation in debug builds to check for leaks

#ifndef NDEBUG

static void (**exitfuncs)(void) = NULL;
static unsigned exitfuncs_pending = 0;

void gdnsd_atexit_debug(void (*f)(void)) {
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

F_NONNULL F_NORETURN
static void syserr_for_ev(const char* msg) { log_fatal("%s: %s", msg, logf_errno()); }

F_NONNULL F_NORETURN
static void usage(const char* argv0) {
    const char* def_cfdir = gdnsd_get_default_config_dir();
    fprintf(stderr,
        PACKAGE_NAME " version " PACKAGE_VERSION "\n"
        "Usage: %s [-c %s] [-D] [-l] [-S] [-s] <action>\n"
        "  -c - Configuration directory, default '%s'\n"
        "  -D - Enable verbose debug output\n"
        "  -l - Send logs to syslog rather than stderr\n"
        "  -S - Force 'zones_strict_data = true' for this invocation\n"
        "  -s - Force 'zones_strict_startup = true' for this invocation\n"
        "Actions:\n"
        "  checkconf - Checks validity of config and zone files\n"
        "  start - Start as a regular foreground process\n"
        "  daemonize - Start as a background daemon (implies -l)\n"
        "\nFeatures: " BUILD_FEATURES
        "\nBuild Info: " BUILD_INFO
        "\nBug report URL: " PACKAGE_BUGREPORT
        "\nGeneral info URL: " PACKAGE_URL
        "\n",
        argv0, def_cfdir, def_cfdir
    );
    exit(2);
}

// thread entry point for zone data reloader thread
static void* zone_data_runtime(void* unused V_UNUSED) {
    gdnsd_thread_setname("gdnsd-zones");

    struct ev_loop* zdata_loop = ev_loop_new(EVFLAG_AUTO);
    if(!zdata_loop)
        log_fatal("Could not initialize the zone data libev loop");

    zsrc_djb_runtime_init(zdata_loop);
    zsrc_rfc1035_runtime_init(zdata_loop);

    ev_run(zdata_loop, 0);

    gdnsd_assert(0); // should never be reached as loop never terminates
    ev_loop_destroy(zdata_loop);
    return NULL;
}

// thread entry point for monitoring (+statio) thread
F_NONNULL
static void* mon_runtime(void* scfg_asvoid) {
    const socks_cfg_t* socks_cfg = scfg_asvoid;

    gdnsd_thread_setname("gdnsd-mon");

    // mon_start already queued up its events in mon_loop earlier...
    statio_start(mon_loop, socks_cfg);
    ev_run(mon_loop, 0);

    gdnsd_assert(0); // should never be reached as loop never terminates
    ev_loop_destroy(mon_loop);
    return NULL;
}

F_NONNULL
static void start_threads(socks_cfg_t* socks_cfg) {
    // Block all signals using the pthreads interface while starting threads,
    //  which causes them to inherit the same mask.
    sigset_t sigmask_all;
    sigfillset(&sigmask_all);
    sigset_t sigmask_prev;
    sigemptyset(&sigmask_prev);
    if(pthread_sigmask(SIG_SETMASK, &sigmask_all, &sigmask_prev))
        log_fatal("pthread_sigmask() failed");

    // system scope scheduling, joinable threads
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
                i, t->is_udp ? "UDP" : "TCP", logf_anysin(&t->ac->addr), logf_strerror(pthread_err));
    }

    pthread_t zone_data_threadid;
    pthread_err = pthread_create(&zone_data_threadid, &attribs, &zone_data_runtime, NULL);
    if(pthread_err)
        log_fatal("pthread_create() of zone data thread failed: %s", logf_strerror(pthread_err));

    // This waits for all of the stat structures to be allocated
    //  by the i/o threads before continuing on.  They must be ready
    //  before the monitoring thread starts below, as it will read
    //  those stat structures
    dnspacket_wait_stats(socks_cfg);

    pthread_t mon_threadid;
    pthread_err = pthread_create(&mon_threadid, &attribs, &mon_runtime, socks_cfg);
    if(pthread_err)
        log_fatal("pthread_create() of monitoring thread failed: %s", logf_strerror(pthread_err));

    // Restore the original mask in the main thread, so
    //  we can continue handling signals like normal
    if(pthread_sigmask(SIG_SETMASK, &sigmask_prev, NULL))
        log_fatal("pthread_sigmask() failed");
    pthread_attr_destroy(&attribs);
}

typedef enum {
    ACT_UNDEF = 0,
    ACT_CHECKCONF,
    ACT_START,
    ACT_DAEMONIZE
} cmdline_action_t;

typedef struct {
    const char* cfg_dir;
    bool force_zss;
    bool force_zsd;
    cmdline_action_t action;
} cmdline_opts_t;

F_NONNULL
static void parse_args(const int argc, char** argv, cmdline_opts_t* copts) {
    int optchar;
    while((optchar = getopt(argc, argv, "c:DlsS"))) {
        switch(optchar) {
            case 'c':
                copts->cfg_dir = optarg;
                break;
            case 'D':
                gdnsd_log_set_debug(true);
                break;
            case 'l':
                gdnsd_log_set_syslog(true);
                break;
            case 's':
                copts->force_zss = true;
                break;
            case 'S':
                copts->force_zsd = true;
                break;
            case -1:
                if(optind == (argc - 1)) {
                    if(!strcasecmp("checkconf", argv[optind])) {
                        copts->action = ACT_CHECKCONF;
                        return;
                    } else if(!strcasecmp("start", argv[optind])) {
                        copts->action = ACT_START;
                        return;
                    } else if(!strcasecmp("daemonize", argv[optind])) {
                        copts->action = ACT_DAEMONIZE;
                        gdnsd_log_set_syslog(true);
                        return;
                    }
                }
                // fall-through
            default:
                usage(argv[0]);
        }
    }
    usage(argv[0]);
}

int main(int argc, char** argv) {
    umask(022);
    // Parse args, getting the config path
    //   returning the action.  Exits on cmdline errors,
    //   does not use assert/log stuff.
    cmdline_opts_t copts = {
        .cfg_dir = NULL,
        .force_zss = false,
        .force_zsd = false,
        .action = ACT_UNDEF
    };

    parse_args(argc, argv, &copts);
    gdnsd_assert(copts.action != ACT_UNDEF);

    // Initialize libgdnsd basic paths/config stuff
    if(copts.action != ACT_CHECKCONF)
        gdnsd_init_daemon(copts.action == ACT_DAEMONIZE);
    vscf_data_t* cfg_root = gdnsd_init_paths(copts.cfg_dir, copts.action != ACT_CHECKCONF);

    // Load full configuration and expose through the globals
    socks_cfg_t* socks_cfg = socks_conf_load(cfg_root);
    cfg_t* cfg = conf_load(cfg_root, socks_cfg, copts.force_zss, copts.force_zsd);
    gcfg = cfg;
    vscf_destroy(cfg_root);

    // Load zone data (final step if checkconf)
    ztree_init(copts.action == ACT_CHECKCONF);
    if(copts.action == ACT_CHECKCONF)
        exit(0);

    // Initialize the network and PRNG bits of libgdnsd for runtime operation
    gdnsd_init_net();
    gdnsd_init_rand();

    // Initialize DNS listening sockets, but do not bind() them yet
    socks_dns_lsocks_init(socks_cfg);

    // init the stats summing/output code + listening sockets (again no bind yet)
    statio_init(socks_cfg);

    // Lock whole daemon into memory, including
    //  all future allocations.
    if(cfg->lock_mem)
        if(mlockall(MCL_CURRENT | MCL_FUTURE))
            log_fatal("mlockall(MCL_CURRENT|MCL_FUTURE) failed: %s (you may need to disabled the lock_mem config option if your system or your ulimits do not allow it)",
                logf_errno());

    // Initialize dnspacket stuff
    dnspacket_global_setup(socks_cfg);

    // Set up libev error callback
    ev_set_syserr_cb(&syserr_for_ev);

    // Construct the monitoring loop, for monitors + statio,
    //   which will be executed in another thread for runtime
    mon_loop = ev_loop_new(EVFLAG_AUTO);
    if(!mon_loop)
        log_fatal("Could not initialize the mon libev loop");

    // set up monitoring, which expects an initially empty loop
    gdnsd_mon_start(mon_loop);

    // Call plugin pre-run actions
    gdnsd_plugins_action_pre_run();

    // Bind sockets
    socks_bind_all(socks_cfg);

    // Start up all of the UDP and TCP threads, each of
    // which has all signals blocked and has its own
    // event loop (libev for TCP, manual blocking loop for UDP)
    // Also starts the zone data reload thread
    // and the statio+monitoring thread
    start_threads(socks_cfg);

    // Notify the user that the listeners are up
    log_info("DNS listeners started");

    // The signals we'll listen for below
    sigset_t mainthread_sigs;
    sigemptyset(&mainthread_sigs);
    sigaddset(&mainthread_sigs, SIGINT);
    sigaddset(&mainthread_sigs, SIGTERM);
    sigaddset(&mainthread_sigs, SIGUSR1);

    // Block the relevant signals before entering the sigwait() loop
    sigset_t sigmask_prev;
    sigemptyset(&sigmask_prev);
    if(pthread_sigmask(SIG_BLOCK, &mainthread_sigs, &sigmask_prev))
        log_fatal("pthread_sigmask() failed");

    // We wait to notify 3rd parties (e.g. systemd, or fg process if
    // daemonizing) that we're ready until after the block above, so that they
    // can reliably get the right signal actions from this point forward
    gdnsd_daemon_notify_ready();

    int killed_by = 0;
    while(!killed_by) {
        int rcvd_sig = 0;
        int sw_rv;
        if((sw_rv = sigwait(&mainthread_sigs, &rcvd_sig)))
            log_fatal("sigwait() failed with error %s", logf_strerror(sw_rv));

        switch(rcvd_sig) {
            case SIGTERM:
                log_info("Received TERM signal, exiting...");
                killed_by = SIGTERM;
                break;
            case SIGINT:
                log_info("Received INT signal, exiting...");
                killed_by = SIGINT;
                break;
            case SIGUSR1:
                log_info("Received USR1 signal");
                zsrc_djb_sigusr1();
                zsrc_rfc1035_sigusr1();
                break;
            default:
                gdnsd_assert(0);
                break;
        }
    }

    // Ask statio thread to send final stats to the log
    statio_final_stats();

    // get rid of child procs (e.g. extmon helper)
    gdnsd_kill_registered_children();

    // deallocate resources in debug mode
    atexit_debug_execute();

    // wait for stats thread to finish logging request
    statio_final_stats_wait();

    // Restore normal signal mask
    if(pthread_sigmask(SIG_SETMASK, &sigmask_prev, NULL))
        log_fatal("pthread_sigmask() failed");

#ifdef GDNSD_COVERTEST_EXIT
    // We have to use exit() when testing coverage, as raise()
    //   skips over writing out gcov data
    exit(0);
#else
    // kill self with same signal, so that our exit status is correct
    //   for any parent/manager/whatever process that may be watching
    raise(killed_by);
#endif

    // raise should not return
    gdnsd_assert(0);
}
