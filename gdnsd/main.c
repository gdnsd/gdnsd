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
#include "gdnsd.h"
#include "conf.h"

#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <pwd.h>
#include <time.h>

#if USE_LINUX_CAPS
#include <sys/types.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#endif

#include "dnsio_tcp.h"
#include "dnsio_udp.h"
#include "dnspacket.h"
#include "statio.h"
#include "monio.h"
#include "ltree.h"
#include "pkterr.h"
#include "gdnsd-plugapi-priv.h"
#include "gdnsd-net-priv.h"
#include "gdnsd-misc-priv.h"

F_NONNULL
static void syserr_for_ev(const char* msg) { dmn_assert(msg); log_fatal("%s: %s", msg, logf_errno()); }

static pthread_t* threadids = NULL;

static void threads_cleanup(void) {
    if(threadids) {
        unsigned num_threads = gconfig.num_io_threads;
        for(unsigned i = 0; i < num_threads; i++)
            pthread_cancel(threadids[i]);
        for(unsigned i = 0; i < num_threads; i++)
            pthread_join(threadids[i], NULL);
    }
}

F_NONNULL
static void terminal_signal(struct ev_loop* loop, struct ev_signal *w, const int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w);
    dmn_assert(revents == EV_SIGNAL);
    dmn_assert(w->signum == SIGTERM || w->signum == SIGINT);

    log_info("Received terminating signal %i, exiting", w->signum);
    ev_break(loop, EVBREAK_ALL);
}

F_NONNULL
static void lpe_signal(struct ev_loop* loop V_UNUSED, struct ev_signal *w, const int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w);
    dmn_assert(revents == EV_SIGNAL);
    dmn_assert(w->signum == SIGUSR1 || w->signum == SIGUSR2);

    if(w->signum == SIGUSR1) {
        log_info("Enabling log_packet_errors (SIGUSR1 received)");
        satom_set(&log_packet_errors, 1);
    }
    else {
        log_info("Disabling log_packet_errors (SIGUSR2 received)");
        satom_set(&log_packet_errors, 0);
    }
}

F_NONNULL F_NORETURN
static void usage(const char* argv0) {
    dmn_assert(argv0);
    fprintf(stderr,
        PACKAGE_NAME " version " PACKAGE_VERSION
#ifndef NDEBUG
        " (debug build)"
#endif
        "\n"
        "Usage: %s [-c /a/config/file] action\n"
        "  -c Use this configfile (default " ETCDIR "/" PACKAGE_NAME "/config)\n"
        "Actions:\n"
        "  checkconf - Checks validity of config/zone files\n"
        "  startfg - Start " PACKAGE_NAME " in foreground w/ logs to stderr\n"
        "  start - Start " PACKAGE_NAME " as a regular daemon\n"
        "  stop - Stops a running daemon previously started by 'start'\n"
        "  restart - Equivalent to checkconf && stop && start, but faster\n"
        "  status - Checks the status of the running daemon\n"
        "  lpe_on - Turns on log_packet_errors in the running daemon\n"
        "  lpe_off - Turns off log_packet_errors in the running daemon\n"
        "\nFor updates, bug reports, etc, please visit " PACKAGE_URL "\n",
        argv0
    );
    exit(99);
}

static ev_signal* sig_int;
static ev_signal* sig_term;
static ev_signal* sig_usr1;
static ev_signal* sig_usr2;

// Set up our terminal signal handlers via libev
F_NONNULL
static void setup_signals(struct ev_loop* def_loop) {
    dmn_assert(def_loop);

    sig_int = malloc(sizeof(ev_signal));
    sig_term = malloc(sizeof(ev_signal));
    sig_usr1 = malloc(sizeof(ev_signal));
    sig_usr2 = malloc(sizeof(ev_signal));

    // Set up the signal callback handlers via libev
    //  and start the signal watchers in the default loop
    ev_signal_init(sig_int, terminal_signal, SIGINT);
    ev_signal_start(def_loop, sig_int);
    ev_signal_init(sig_term, terminal_signal, SIGTERM);
    ev_signal_start(def_loop, sig_term);
    ev_signal_init(sig_usr1, lpe_signal, SIGUSR1);
    ev_signal_start(def_loop, sig_usr1);
    ev_signal_init(sig_usr2, lpe_signal, SIGUSR2);
    ev_signal_start(def_loop, sig_usr2);
}

// I know this looks stupid, but on Linux/glibc this forces
//  gcc_s to be loaded before chroot(), avoiding an otherwise
//  very late failure at shutdown time of pthread_cancel().
// In general it's not a bad idea to cycle the pthreads
//  interface for bugs/crashes before daemonization anyways.
static void* dummy_thread(void* x) { return x; }
static void ping_pthreads(void) {
    pthread_t threadid;
    int pthread_err = pthread_create(&threadid, NULL, &dummy_thread, NULL);
    if(pthread_err)
        log_fatal("pthread_create() of dummy thread failed: %s",
            logf_errnum(pthread_err));
    pthread_cancel(threadid);
    pthread_join(threadid, NULL);
}

static void start_threads(void) {
    // Block all signals using the pthreads interface while starting threads,
    //  which causes them to inherit the same mask.
    sigset_t sigmask_all, sigmask_prev;
    sigfillset(&sigmask_all);
    pthread_sigmask(SIG_SETMASK, &sigmask_all, &sigmask_prev);

    // system scope scheduling, joinable threads
    pthread_attr_t attribs;
    pthread_attr_init(&attribs);
    pthread_attr_setdetachstate(&attribs, PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&attribs, PTHREAD_SCOPE_SYSTEM);

    unsigned num_addrs = gconfig.num_dns_addrs;
    threadids = calloc(gconfig.num_io_threads, sizeof(pthread_t));

    // Start UDP threads
    for(uintptr_t i = 0; i < num_addrs; i++) {
        const dns_addr_t* addrconf = &gconfig.dns_addrs[i];
        int pthread_err = pthread_create(&threadids[addrconf->udp_threadnum], &attribs, &dnsio_udp_start, (void*)addrconf);
        if(pthread_err) log_fatal("pthread_create() of UDP DNS thread failed: %s", logf_errnum(pthread_err));
    }

    // Start TCP threads
    for(uintptr_t i = 0; i < num_addrs; i++) {
        const dns_addr_t* addrconf = &gconfig.dns_addrs[i];
        if(!addrconf->tcp_disabled) {
            int pthread_err = pthread_create(&threadids[addrconf->tcp_threadnum], &attribs, &dnsio_tcp_start, (void*)addrconf);
            if(pthread_err) log_fatal("pthread_create() of TCP DNS thread failed: %s", logf_errnum(pthread_err));
        }
    }

    // Invoke thread cleanup handlers at exit time
    if(atexit(threads_cleanup))
        log_fatal("atexit(threads_cleanup) failed: %s", logf_errno());

    // Restore the original mask in the main thread, so
    //  we can continue handling signals like normal
    pthread_sigmask(SIG_SETMASK, &sigmask_prev, NULL);
    pthread_attr_destroy(&attribs);
}

typedef enum {
    ACT_CHECKCFG   = 0,
    ACT_STARTFG,  // 1
    ACT_START,    // 2
    ACT_STOP,     // 3
    ACT_RESTART,  // 4
    ACT_STATUS,   // 5
    ACT_LPE_ON,   // 6
    ACT_LPE_OFF,  // 7
    ACT_UNDEF     // 8
} action_t;

static const char* act_strs[] = {
    "checkconf",      // 0
    "startfg",        // 1
    "start",          // 2
    "stop",           // 3
    "restart",        // 4
    "status",         // 5
    "lpe_on",         // 6
    "lpe_off",        // 7
};

F_NONNULL F_PURE
static action_t match_action(const char* arg) {
    dmn_assert(arg);

    unsigned i;
    for(i = 0; i < 8; i++)
        if(!strcasecmp(act_strs[i], arg))
            return i;
    return ACT_UNDEF;
}

static const char def_cfg_path[] = ETCDIR "/" PACKAGE_NAME "/config";

int main(int argc, char** argv) {
    action_t action = ACT_UNDEF;

    char* conf_arg = NULL;
    switch(argc) {
        case 4: // gdnsd -c x foo
            if(strcmp(argv[1], "-c")) usage(argv[0]);
            conf_arg = strdup(argv[2]);
            action = match_action(argv[3]);
            break;
        case 2: // gdnsd foo
            action = match_action(argv[1]);
            break;
    }

    if(action == ACT_UNDEF)
        usage(argv[0]);

    // cfg_file needs to be writeable storage
    //  for portability
    if(!conf_arg)
        conf_arg = strdup(def_cfg_path);

    // Initialize net stuff in libgdnsd (protoents, tcp_v6_ok)
    gdnsd_init_net();

    // Init meta-PRNG
    gdnsd_rand_meta_init();

    // Actually load the config
    log_info("Loading configuration");
    conf_load(conf_arg);
    free(conf_arg);

    // Take action
    if(action == ACT_STATUS) {
        const int oldpid = dmn_status(gconfig.pidfile);
        if(!oldpid) {
            log_info("Not running");
            exit(1);
        }
        log_info("Running at pid %i", oldpid);
        exit(0);
    }

    if(action == ACT_STOP) {
        dmn_stop(gconfig.pidfile);
        exit(0);
    }

    if(action == ACT_LPE_ON) {
        dmn_signal(gconfig.pidfile, SIGUSR1);
        exit(0);
    }

    if(action == ACT_LPE_OFF) {
        dmn_signal(gconfig.pidfile, SIGUSR2);
        exit(0);
    }

    // Call plugin full_config actions
    gdnsd_plugins_action_full_config(gconfig.num_io_threads);

    log_info("Loading zone data");
    ltree_load_zones();

    if(action == ACT_CHECKCFG) {
        log_info("Configuration and zone data loads just fine");
        exit(0);
    }

    if(action == ACT_RESTART) {
        log_info("Attempting to stop the running daemon instance for restart...");
        if(dmn_stop(gconfig.pidfile))
            log_fatal("...Running daemon failed to stop, cannot continue with restart...");
        log_info("...Previous daemon successfully shut down (or was not up), this instance coming online");
    }

    const bool started_as_root = !geteuid();

    if(started_as_root)
        dmn_secure_setup(gconfig.username, gconfig.chroot_path, true);

#ifdef RLIMIT_MEMLOCK
    // Die or inform about memlock ulimit here as applicable.
    if(gconfig.lock_mem) {
        struct rlimit rlim;
        if(getrlimit(RLIMIT_MEMLOCK, &rlim))
            log_fatal("getrlimit(RLIMIT_MEMLOCK) failed: %s", logf_errno());

        if(rlim.rlim_cur != RLIM_INFINITY) {
            if(!started_as_root) {
                // First, raise _cur to _max, which should never fail
                if(rlim.rlim_cur != rlim.rlim_max) {
                    rlim.rlim_cur = rlim.rlim_max;
                    if(setrlimit(RLIMIT_MEMLOCK, &rlim))
                        log_fatal("setrlimit(RLIMIT_MEMLOCK, cur = max) "
                            "failed: %s", logf_errno());
                }

                if(rlim.rlim_cur < 1048576)
                    log_fatal("Not started as root, lock_mem was set, "
                        "and the rlimit for locked memory is unreasonably "
                        "low (%li bytes), failing", (long)rlim.rlim_cur);

                log_info("The rlimit for locked memory is %li MB, and the "
                    "daemon can't do anything about that since it wasn't "
                    "started as root.  This may or may not be too small at "
                    "runtime, leading to failure.  You have been warned.",
                    (long)(rlim.rlim_cur >> 20));
            }
            else {
                // Luckily, root can do as he pleases with the ulimits, but
                //  we'll do it in two steps just in case any platforms
                //  are braindead about it.  This does open a hole in the
                //  sense that if someone were to remotely take control
                //  of the daemon via exploit, they can now lock large
                //  amounts of memory even though the daemon has dropped
                //  privileges for most other dangerous operations.
                //  The other alternatives are trying to pre-calculate
                //  all future memory usage (possible, but a PITA to
                //  maintain), or simply letting the code fail post-
                //  daemonization in an unfortunately rather common case.
                // Another option would be to offer a configfile parameter
                //  for the rlimit value in this case.
                // If the daemon gets compromised, even with privdrop
                //  and chroot in place, memlock is probably the least
                //  of your worries anyways.
                rlim.rlim_max = RLIM_INFINITY;
                if(setrlimit(RLIMIT_MEMLOCK, &rlim))
                    log_fatal("setrlimit(RLIMIT_MEMLOCK, max = INF) "
                        "failed: %s", logf_errno());

                rlim.rlim_cur = RLIM_INFINITY;
                if(setrlimit(RLIMIT_MEMLOCK, &rlim))
                    log_fatal("setrlimit(RLIMIT_MEMLOCK, cur = INF, "
                        "max = INF) failed: %s", logf_errno());
            }
        }
    }
#endif

    // Ping the pthreads implementation...
    ping_pthreads();

    // Daemonize if applicable
    if(action != ACT_STARTFG) {
        // so that the daemonization fork+exit pairs don't
        //   execute the plugins' exit handlers
        skip_plugins_cleanup = true;
        dmn_daemonize(PACKAGE_NAME, gconfig.pidfile);
        skip_plugins_cleanup = false;
    }

    // If root, or if user explicitly set a priority...
    if(started_as_root || gconfig.priority != -21) {
        // If root and no explicit value, use -11
        if(started_as_root && gconfig.priority == -21)
            gconfig.priority = -11;
        if(setpriority(PRIO_PROCESS, getpid(), gconfig.priority))
            log_warn("setpriority(%i) failed: %s", gconfig.priority, logf_errno());
    }

    // Lock whole daemon into memory, including
    //  all future allocations.
    if(gconfig.lock_mem)
        if(mlockall(MCL_CURRENT | MCL_FUTURE))
            log_fatal("mlockall(MCL_CURRENT|MCL_FUTURE) failed: %s (you may need to disabled the lock_mem config option if your system or your ulimits do not allow it)",
                logf_errno());

    // Set up libev error callback
    ev_set_syserr_cb(&syserr_for_ev);

    // Initialize dnspacket stuff
    dnspacket_global_setup();

    // Initialize DNS listening sockets
    const bool need_caps = dns_lsock_init();

    // init the stats summing/output code
    statio_init();

    // Call plugin pre-privdrop actions
    gdnsd_plugins_action_pre_privdrop();

    // Now that config is read, we're daemonized, the pidfile is written,
    //  and all listening sockets are open, we can chroot and drop privs
    if(started_as_root) {

#if USE_LINUX_CAPS

        if(need_caps) {
            const cap_value_t pre_caps[] = {
                CAP_NET_BIND_SERVICE,
                CAP_SYS_CHROOT,
                CAP_SETGID,
                CAP_SETUID,
            };
            dmn_log_debug("Attempting to use Linux capabilities to allow late binding of ports < 1024");
            cap_t mycaps = cap_init();
            if(cap_set_flag(mycaps, CAP_PERMITTED, 4, pre_caps, CAP_SET))
                dmn_log_fatal("cap_set_flag(PERMITTED, pre_caps) failed: %s", logf_errno());
            if(cap_set_flag(mycaps, CAP_EFFECTIVE, 4, pre_caps, CAP_SET))
                dmn_log_fatal("cap_set_flag(EFFECTIVE, pre_caps) failed: %s", logf_errno());
            if(cap_set_proc(mycaps))
                dmn_log_fatal("cap_set_proc(pre_caps) failed: %s", logf_errno());
            if(prctl(PR_SET_KEEPCAPS, 1))
                dmn_log_fatal("prctl(PR_SET_KEEPCAPS, 1) failed: %s", logf_errno());
            cap_free(mycaps);
        }
#else
        if(need_caps)
            dmn_log_warn("Some DNS listeners are configured for and attempting to use late binding (late_bind_secs) on privileged ports (< 1024), the daemon is dropping privs from root to a non-root user, and your build does not have Linux capabilities support.  Unless you have made some OS-specific arrangements to give this process the capability to bind these ports after dropping privileges, most likely the late bind(2) will fail fatally for lack of permissions...");
#endif

        dmn_secure_me();

#if USE_LINUX_CAPS
        if(need_caps) {
            const cap_value_t cap_netbind = CAP_NET_BIND_SERVICE;
            cap_t mycaps = cap_init();
            if(cap_set_flag(mycaps, CAP_PERMITTED, 1, &cap_netbind, CAP_SET))
                dmn_log_fatal("cap_set_flag(PERMITTED, NET_BIND) failed: %s", logf_errno());
            if(cap_set_flag(mycaps, CAP_EFFECTIVE, 1, &cap_netbind, CAP_SET))
                dmn_log_fatal("cap_set_flag(EFFECTIVE, NET_BIND) failed: %s", logf_errno());
            if(cap_set_proc(mycaps))
                dmn_log_fatal("cap_set_proc() (post-setuid) failed: %s", logf_errno());
            cap_free(mycaps);
        }
#endif

    }

    // Construct the default loop for the main thread
    struct ev_loop* def_loop = ev_default_loop(EVFLAG_AUTO);
    if(!def_loop) log_fatal("Could not initialize the default libev loop");
    ev_set_timeout_collect_interval(def_loop, 0.1);
    ev_set_io_collect_interval(def_loop, 0.01);

    // set up monio, which expects an initially empty loop
    monio_start(def_loop);

    // initialize the libev-based signal handlers
    setup_signals(def_loop);

    // Call plugin pre-run actions
    gdnsd_plugins_action_pre_run(def_loop);

    // Start up all of the UDP and TCP threads, each of
    // which has all signals blocked and has its own
    // event loop (libev for TCP, manual blocking loop for UDP)
    start_threads();

    // This waits for all of the stat structures to be allocated
    //  by the i/o threads before continuing on
    dnspacket_wait_stats();

    // Start up the statio event watchers in the main loop/thread
    // Note, this is down here because we depend on
    //  dnspacket_wait_stats() completion.
    statio_start(def_loop);

    // Notify the user that the listeners are up
    log_info("DNS listeners started");

    // Start the primary event loop in this thread, to handle
    // signals and statio stuff.  Should not return until we
    // receive a terminating signal.
    ev_run(def_loop, 0);

    // Final stats output on shutdown
    log_info("Final stats:");
    statio_log_uptime();
    statio_log_stats();

    // Bye!
    exit(0);
}
