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
#include "conf.h"

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

#ifdef USE_LINUX_CAPS
#include <sys/capability.h>
#include <sys/prctl.h>
#endif

#include "dnsio_tcp.h"
#include "dnsio_udp.h"
#include "dnspacket.h"
#include "statio.h"
#include "monio.h"
#include "ztree.h"
#include "zsrc_rfc1035.h"
#include "zsrc_djb.h"
#include "gdnsd/log.h"
#include "gdnsd/plugapi-priv.h"
#include "gdnsd/net-priv.h"
#include "gdnsd/misc-priv.h"
#include "gdnsd/paths-priv.h"

F_NONNULL
static void syserr_for_ev(const char* msg) { dmn_assert(msg); log_fatal("%s: %s", msg, logf_errno()); }

static pthread_t* io_threadids = NULL; // TCP/UDP threads
static pthread_t zone_data_threadid;

static void threads_cleanup(void) {
    dmn_assert(io_threadids);

    unsigned num_threads = gconfig.num_io_threads;

    pthread_cancel(zone_data_threadid);
    for(unsigned i = 0; i < num_threads; i++)
        pthread_cancel(io_threadids[i]);

    pthread_join(zone_data_threadid, NULL);
    for(unsigned i = 0; i < num_threads; i++)
        pthread_join(io_threadids[i], NULL);
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
static void hup_signal(struct ev_loop* loop V_UNUSED, struct ev_signal *w V_UNUSED, const int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w);
    dmn_assert(revents == EV_SIGNAL);
    dmn_assert(w->signum == SIGHUP);

    log_debug("Received SIGHUP");
    // these functions should log_info() that they're taking SIGHUP actions, as appropriate
    zsrc_rfc1035_sighup();
}

F_NONNULL F_NORETURN
static void usage(const char* argv0) {
    fprintf(stderr,
        PACKAGE_NAME " version " PACKAGE_VERSION "\n"
        "Usage: %s [-d <rootdir> ] <action>\n"
        "  -d <rootdir> - Use the given directory as the daemon chroot.  The\n"
        "     special value 'system' uses system default paths with no chroot.\n"
        "     The default for this build is '%s'.  See gdnsd(8) for more info.\n"
        "Actions:\n"
        "  checkconf - Checks validity of config and zone files\n"
        "  startfg - Start " PACKAGE_NAME " in foreground w/ logs to stderr\n"
        "  start - Start " PACKAGE_NAME " as a regular daemon\n"
        "  stop - Stops a running daemon previously started by 'start'\n"
        "  reload - Send SIGHUP to running daemon for zone data reload\n"
        "  restart - Equivalent to checkconf && stop && start, but faster\n"
        "  force-reload - Aliases 'restart'\n"
        "  condrestart - Does 'restart' action only if already running\n"
        "  try-restart - Aliases 'condrestart'\n"
        "  status - Checks the status of the running daemon\n\n"
        "Optional compile-time features:"

#       ifndef NDEBUG
            " debug"
#       endif
#       ifdef HAVE_QSBR
            " urcu"
#       endif
#       ifdef USE_SENDMMSG
            " mmsg"
#       endif
#       ifdef USE_INOTIFY
            " inotify"
#       endif
#       ifdef USE_LINUX_CAPS
            " libcap"
#       endif

#       if  defined NDEBUG \
        && !defined HAVE_QSBR \
        && !defined USE_SENDMMSG \
        && !defined USE_INOTIFY \
        && !defined USE_LINUX_CAPS
            " none"
#       endif

        "\nFor updates, bug reports, etc, please visit " PACKAGE_URL "\n",
        argv0, gdnsd_get_def_rootdir()
    );
    exit(2);
}

static ev_signal* sig_int;
static ev_signal* sig_term;
static ev_signal* sig_hup;

// Set up our terminal signal handlers via libev
F_NONNULL
static void setup_signals(struct ev_loop* def_loop) {
    dmn_assert(def_loop);

    sig_int = malloc(sizeof(ev_signal));
    sig_term = malloc(sizeof(ev_signal));
    sig_hup = malloc(sizeof(ev_signal));

    // Set up the signal callback handlers via libev
    //  and start the signal watchers in the default loop
    ev_signal_init(sig_int, terminal_signal, SIGINT);
    ev_signal_start(def_loop, sig_int);
    ev_signal_init(sig_term, terminal_signal, SIGTERM);
    ev_signal_start(def_loop, sig_term);
    ev_signal_init(sig_hup, hup_signal, SIGHUP);
    ev_signal_start(def_loop, sig_hup);
}

static void* zone_data_runtime(void* unused V_UNUSED) {
    struct ev_loop* zdata_loop = ev_loop_new(EVFLAG_AUTO);
    if(!zdata_loop)
        log_fatal("Could not initialize the zone data libev loop");
    // nothing happens faster than 10ms here...
    ev_set_timeout_collect_interval(zdata_loop, 0.01);
    ev_set_io_collect_interval(zdata_loop, 0.01);

    zsrc_djb_runtime_init(zdata_loop);
    zsrc_rfc1035_runtime_init(zdata_loop);

    ev_run(zdata_loop, 0);
    ev_loop_destroy(zdata_loop);

    return NULL;
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
    io_threadids = calloc(gconfig.num_io_threads, sizeof(pthread_t));

    // Start UDP threads
    for(uintptr_t i = 0; i < num_addrs; i++) {
        const dns_addr_t* addrconf = &gconfig.dns_addrs[i];
        int pthread_err = pthread_create(&io_threadids[addrconf->udp_threadnum], &attribs, &dnsio_udp_start, (void*)addrconf);
        if(pthread_err) log_fatal("pthread_create() of UDP DNS thread failed: %s", logf_errnum(pthread_err));
    }

    // Start TCP threads
    for(uintptr_t i = 0; i < num_addrs; i++) {
        const dns_addr_t* addrconf = &gconfig.dns_addrs[i];
        if(!addrconf->tcp_disabled) {
            int pthread_err = pthread_create(&io_threadids[addrconf->tcp_threadnum], &attribs, &dnsio_tcp_start, (void*)addrconf);
            if(pthread_err) log_fatal("pthread_create() of TCP DNS thread failed: %s", logf_errnum(pthread_err));
        }
    }

    int pthread_err = pthread_create(&zone_data_threadid, &attribs, &zone_data_runtime, NULL);
    if(pthread_err) log_fatal("pthread_create() of zone data thread failed: %s", logf_errnum(pthread_err));

    // Invoke thread cleanup handlers at exit time
    if(atexit(threads_cleanup))
        log_fatal("atexit(threads_cleanup) failed: %s", logf_errno());

    // Restore the original mask in the main thread, so
    //  we can continue handling signals like normal
    pthread_sigmask(SIG_SETMASK, &sigmask_prev, NULL);
    pthread_attr_destroy(&attribs);
}

static void memlock_rlimits(const bool started_as_root) {
#ifdef RLIMIT_MEMLOCK
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

static void caps_pre_secure(void) {
#ifdef USE_LINUX_CAPS
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
#else
    dmn_log_warn("Some DNS listeners are configured for and attempting to use late binding (late_bind_secs) on privileged ports (< 1024), the daemon is dropping privs from root to a non-root user, and your build does not have Linux capabilities support.  Unless you have made some OS-specific arrangements to give this process the capability to bind these ports after dropping privileges, most likely the late bind(2) will fail fatally for lack of permissions...");
#endif
}

static void caps_post_secure(void) {
#ifdef USE_LINUX_CAPS
    const cap_value_t cap_netbind = CAP_NET_BIND_SERVICE;
    cap_t mycaps = cap_init();
    if(cap_set_flag(mycaps, CAP_PERMITTED, 1, &cap_netbind, CAP_SET))
        dmn_log_fatal("cap_set_flag(PERMITTED, NET_BIND) failed: %s", logf_errno());
    if(cap_set_flag(mycaps, CAP_EFFECTIVE, 1, &cap_netbind, CAP_SET))
        dmn_log_fatal("cap_set_flag(EFFECTIVE, NET_BIND) failed: %s", logf_errno());
    if(cap_set_proc(mycaps))
        dmn_log_fatal("cap_set_proc() (post-setuid) failed: %s", logf_errno());
    cap_free(mycaps);
#endif
}

typedef enum {
    ACT_CHECKCFG   = 0,
    ACT_STARTFG,
    ACT_START,
    ACT_STOP,
    ACT_RELOAD,
    ACT_RESTART,
    ACT_CRESTART, // downgrades to ACT_RESTART after checking...
    ACT_STATUS,
    ACT_UNDEF
} action_t;

typedef struct {
    const char* cmdstring;
    action_t action;
} actmap_t;

static actmap_t actionmap[] = {
    { "checkconf",    ACT_CHECKCFG }, // 1
    { "startfg",      ACT_STARTFG },  // 2
    { "start",        ACT_START },    // 3
    { "stop",         ACT_STOP },     // 4
    { "reload",       ACT_RELOAD },   // 5
    { "restart",      ACT_RESTART },  // 6
    { "force-reload", ACT_RESTART },  // 7
    { "condrestart",  ACT_CRESTART }, // 8
    { "try-restart",  ACT_CRESTART }, // 9
    { "status",       ACT_STATUS },   // 10
};
#define ACTIONMAP_COUNT 10

F_NONNULL F_PURE
static action_t match_action(const char* arg) {
    dmn_assert(arg);

    unsigned i;
    for(i = 0; i < ACTIONMAP_COUNT; i++)
        if(!strcasecmp(actionmap[i].cmdstring, arg))
            return actionmap[i].action;
    return ACT_UNDEF;
}

static action_t parse_args(const int argc, char** argv, const char** rootdir_out) {
    action_t action = ACT_UNDEF;

    *rootdir_out = NULL;

    switch(argc) {
        case 4: // gdnsd -d x foo
            if(strcmp(argv[1], "-d")) usage(argv[0]);
            *rootdir_out = argv[2];
            action = match_action(argv[3]);
            break;
        case 2: // gdnsd foo
            action = match_action(argv[1]);
            break;
    }

    if(action == ACT_UNDEF)
        usage(argv[0]);

    return action;
}

static void init_config(const bool started_as_root) {
    // Initialize net stuff in libgdnsd (protoents, tcp_v6_ok)
    gdnsd_init_net();

    // Init meta-PRNG
    gdnsd_rand_meta_init();

    // Actually load the config
    conf_load();

    // Set up and validate privdrop info if necc
    if(started_as_root)
        dmn_secure_setup(gconfig.username, gdnsd_get_rootdir());

    // Call plugin full_config actions
    gdnsd_plugins_action_full_config(gconfig.num_io_threads);

    log_info("Loading zone data...");
    ztree_init();
    zsrc_djb_load_zones();
    zsrc_rfc1035_load_zones();
}

int main(int argc, char** argv) {

    // Parse args, getting the libgdnsd rootdir and
    //   returning the action.  Exits on cmdline errors,
    //   does not use libdmn assert/log stuff.
    const char* rootdir_arg = NULL;
    action_t action = parse_args(argc, argv, &rootdir_arg);

    // will we daemonize? startfg doesn't count...
    bool will_daemonize = false;
    switch(action) {
        case ACT_START:
        case ACT_RESTART:
        case ACT_CRESTART:
            will_daemonize = true;
            break;
        default:
            break;
    }

    // Init the log subsystem, which initially only sends
    //   to stderr.  Second arg is "stderr_info", which controls
    //   whether info-level messages are sent to stderr or not
    //   (all are sent regardless in debug builds).
    dmn_init_log(PACKAGE_NAME, !will_daemonize);

    // set the rootdir
    gdnsd_set_rootdir(rootdir_arg);

    // Start syslog (in addition to stderr) logging immediately
    //   in cases leading to daemonized daemon start
    if(will_daemonize)
        dmn_start_syslog();

    char* pid_path = gdnsd_get_pidpath();

    // Take action
    if(action == ACT_STATUS) {
        const pid_t oldpid = dmn_status(pid_path);
        if(!oldpid) {
            log_info("status: not running, based on pidfile '%s'", logf_pathname(pid_path));
            exit(3);
        }
        log_info("status: running at pid %li in pidfile %s", (long)oldpid, logf_pathname(pid_path));
        exit(0);
    }
    else if(action == ACT_STOP) {
        exit(dmn_stop(pid_path) ? 1 : 0);
    }
    else if(action == ACT_RELOAD) {
        exit(dmn_signal(pid_path, SIGHUP));
    }

    if(action == ACT_CRESTART) {
        const pid_t oldpid = dmn_status(pid_path);
        if(!oldpid) {
            log_info("condrestart: not running, will not restart");
            exit(0);
        }
        action = ACT_RESTART;
    }

    // Did we start as root?  This determines whether we try to chroot(),
    //   how we handle memlock rlimits, capabilities, etc...
    const bool started_as_root = !geteuid();

    // Initializes basic libgdnsd stuff, loads config file, loads zones,
    //   configures plugins all the way through full_config()
    init_config(started_as_root);

    if(action == ACT_CHECKCFG) {
        log_info("Configuration and zone data loads just fine");
        exit(0);
    }

    // from here out, all actions are attempting startup...
    dmn_assert(action == ACT_STARTFG
            || action == ACT_START
            || action == ACT_RESTART
    );

    // Check/set rlimits for mlockall() if necessary and possible
    if(gconfig.lock_mem)
        memlock_rlimits(started_as_root);

    // Ping the pthreads implementation...
    ping_pthreads();

    // Daemonize if applicable
    if(action != ACT_STARTFG)
        dmn_daemonize(pid_path, (action == ACT_RESTART));

    // free pid_path, done with it
    free(pid_path);

    // Call plugin pre-privdrop actions
    gdnsd_plugins_action_post_daemonize();

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
        if(need_caps) caps_pre_secure();
        dmn_secure_me(false);
        if(need_caps) caps_post_secure();
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
    // Also starts the zone data reload thread
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

    // Report success back to whoever invoked "start" or "restart" command...
    if(action != ACT_STARTFG)
       dmn_daemonize_finish();

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
