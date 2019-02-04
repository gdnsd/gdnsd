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
#include "ltree.h"
#include "css.h"
#include "csc.h"
#include "chal.h"
#include "cookie.h"

#include "plugins/plugapi.h"
#include "plugins/mon.h"
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

// Signal we were killed by, for final raise()
static int killed_by = 0;

// primary/default libev loop for main thread
static struct ev_loop* def_loop = NULL;

// libev watchers for signals+async
static ev_signal sig_int;
static ev_signal sig_term;
static ev_signal sig_usr1;
static ev_async async_reloadz;

// custom atexit-like stuff for resource deallocation

static void (**exitfuncs)(void) = NULL;
static unsigned exitfuncs_pending = 0;

void gdnsd_atexit(void (*f)(void))
{
    exitfuncs = xrealloc_n(exitfuncs, exitfuncs_pending + 1, sizeof(*exitfuncs));
    exitfuncs[exitfuncs_pending++] = f;
}

static void atexit_execute(void)
{
    while (exitfuncs_pending--)
        exitfuncs[exitfuncs_pending]();
}

F_NONNULL F_NORETURN
static void syserr_for_ev(const char* msg)
{
    log_fatal("%s: %s", msg, logf_errno());
}

static pthread_t zones_reloader_threadid;

static bool join_zones_reloader_thread(void)
{
    void* raw_exit_status = (void*)42U;
    int pthread_err = pthread_join(zones_reloader_threadid, &raw_exit_status);
    if (pthread_err)
        log_err("pthread_join() of zone data loading thread failed: %s", logf_strerror(pthread_err));
    return !!raw_exit_status;
}

// Spawns a new thread to reload zone data.  Initial loading at startup sets
// the "initial" flag for the thread, which means it doesn't send an async
// notification back to us on completion, as we'll be waiting for it
// synchronously in this case.
static void spawn_zones_reloader_thread(const bool initial)
{
    // Block all signals using the pthreads interface while starting threads,
    //  which causes them to inherit the same mask.
    sigset_t sigmask_all;
    sigfillset(&sigmask_all);
    sigset_t sigmask_prev;
    sigemptyset(&sigmask_prev);
    if (pthread_sigmask(SIG_SETMASK, &sigmask_all, &sigmask_prev))
        log_fatal("pthread_sigmask() failed");

    pthread_attr_t attribs;
    pthread_attr_init(&attribs);
    pthread_attr_setdetachstate(&attribs, PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&attribs, PTHREAD_SCOPE_SYSTEM);

    int pthread_err = pthread_create(&zones_reloader_threadid, &attribs, &ztree_zones_reloader_thread, (void*)initial);
    if (pthread_err)
        log_fatal("pthread_create() of zone data thread failed: %s", logf_strerror(pthread_err));

    // Restore the original mask in the main thread, so
    //  we can continue handling signals like normal
    if (pthread_sigmask(SIG_SETMASK, &sigmask_prev, NULL))
        log_fatal("pthread_sigmask() failed");
    pthread_attr_destroy(&attribs);
}

static bool initialize_zones(void)
{
    spawn_zones_reloader_thread(true);
    return join_zones_reloader_thread();
}

void spawn_async_zones_reloader_thread(void)
{
    spawn_zones_reloader_thread(false);
}

F_NONNULL
static void terminal_signal(struct ev_loop* loop, struct ev_signal* w, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_SIGNAL);
    gdnsd_assert(w->signum == SIGTERM || w->signum == SIGINT);
    css_t* css = w->data;
    if (!css_stop_ok(css)) {
        log_err("Ignoring terminating signal %i because a replace attempt is in progress!", w->signum);
    } else {
        log_info("Exiting cleanly on receipt of terminating signal %i", w->signum);
        killed_by = w->signum;
        ev_break(loop, EVBREAK_ALL);
    }
}

F_NONNULL
static void usr1_signal(struct ev_loop* loop V_UNUSED, struct ev_signal* w V_UNUSED, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_SIGNAL);
    gdnsd_assert(w->signum == SIGUSR1);
    log_err("Ignoring SIGUSR1 - use 'gdnsdctl reload-zones' to reload zone data!");
}

F_NONNULL
static void reload_zones_done(struct ev_loop* loop V_UNUSED, struct ev_async* a V_UNUSED, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_ASYNC);
    css_t* css = a->data;
    const bool failed = join_zones_reloader_thread();

    if (failed)
        log_err("Reloading zone data failed");
    else
        log_info("Reloading zone data successful");

    if (css_notify_zone_reloaders(css, failed))
        spawn_async_zones_reloader_thread();
}

// called by ztree reloader thread just before it exits
void notify_reload_zones_done(void)
{
    ev_async* p_async_reloadz = &async_reloadz;
    ev_async_send(def_loop, p_async_reloadz);
}

static void setup_reload_zones(css_t* css)
{
    ev_async* p_async_reloadz = &async_reloadz;
    ev_async_init(p_async_reloadz, reload_zones_done);
    p_async_reloadz->data = css;
    ev_async_start(def_loop, p_async_reloadz);
}

F_NONNULL F_NORETURN
static void usage(const char* argv0)
{
    const char* def_cfdir = gdnsd_get_default_config_dir();
    fprintf(stderr,
            PACKAGE_NAME " version " PACKAGE_VERSION "\n"
            "Usage: %s [-c %s] [-D] [-l] [-S] [-R | -i] <action>\n"
            "  -c - Configuration directory, default '%s'\n"
            "  -D - Enable verbose debug output\n"
            "  -l - Send logs to syslog rather than stderr\n"
            "  -S - Force 'zones_strict_data = true' for this invocation\n"
            "  -R - Attempt downtimeless replace of another instance\n"
            "  -i - Idempotent mode for start/daemonize: exit 0 if already running\n"
            "       (-R and -i cannot be used together)\n"
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

F_NONNULL
static void start_threads(socks_cfg_t* socks_cfg)
{
    dnsio_udp_init(getpid());
    size_t num_tcp_threads = 0;
    for (size_t i = 0; i < socks_cfg->num_dns_threads; i++)
        if (!socks_cfg->dns_threads[i].is_udp)
            num_tcp_threads++;
    dnsio_tcp_init(num_tcp_threads);

    // Block all signals using the pthreads interface while starting threads,
    //  which causes them to inherit the same mask.
    sigset_t sigmask_all;
    sigfillset(&sigmask_all);
    sigset_t sigmask_prev;
    sigemptyset(&sigmask_prev);
    if (pthread_sigmask(SIG_SETMASK, &sigmask_all, &sigmask_prev))
        log_fatal("pthread_sigmask() failed");

    // system scope scheduling, joinable threads
    pthread_attr_t attribs;
    pthread_attr_init(&attribs);
    pthread_attr_setdetachstate(&attribs, PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&attribs, PTHREAD_SCOPE_SYSTEM);

    int pthread_err;

    for (unsigned i = 0; i < socks_cfg->num_dns_threads; i++) {
        dns_thread_t* t = &socks_cfg->dns_threads[i];
        if (t->is_udp)
            pthread_err = pthread_create(&t->threadid, &attribs, &dnsio_udp_start, t);
        else
            pthread_err = pthread_create(&t->threadid, &attribs, &dnsio_tcp_start, t);
        if (pthread_err)
            log_fatal("pthread_create() of DNS thread %u (for %s:%s) failed: %s",
                      i, t->is_udp ? "UDP" : "TCP", logf_anysin(&t->ac->addr), logf_strerror(pthread_err));
    }

    // Restore the original mask in the main thread, so
    //  we can continue handling signals like normal
    if (pthread_sigmask(SIG_SETMASK, &sigmask_prev, NULL))
        log_fatal("pthread_sigmask() failed");
    pthread_attr_destroy(&attribs);
}

static void request_io_threads_stop(socks_cfg_t* socks_cfg)
{
    dnsio_tcp_request_threads_stop();
    for (unsigned i = 0; i < socks_cfg->num_dns_threads; i++) {
        dns_thread_t* t = &socks_cfg->dns_threads[i];
        if (t->is_udp)
            pthread_kill(t->threadid, SIGUSR2);
    }
}

static void do_tak1(csc_t* csc)
{
    // During some release >= 3.1.0, we can remove 2.99.x-beta compat here by
    // assuming all daemons with listening control sockets have a major >= 3
    // and support TAK1.
    if (csc_server_version_gte(csc, 2, 99, 200)) {
        csbuf_t req;
        csbuf_t resp;
        memset(&req, 0, sizeof(req));
        req.key = REQ_TAK1;
        req.d = (uint32_t)getpid();
        if (csc_txn(csc, &req, &resp) != CSC_TXN_OK)
            log_fatal("REPLACE[new daemon]: takeover phase 1 notification attempt failed (possibly lost race against another)");
    }
}

static void do_tak2(struct ev_loop* loop, csc_t* csc)
{
    // As above for compat
    if (csc_server_version_gte(csc, 2, 99, 200)) {
        uint8_t* chal_data = NULL;
        csbuf_t req;
        csbuf_t resp;
        memset(&req, 0, sizeof(req));
        req.key = REQ_TAK2;
        req.d = (uint32_t)getpid();
        if (csc_txn_getdata(csc, &req, &resp, (char**)&chal_data) != CSC_TXN_OK)
            log_fatal("REPLACE[new daemon]: takeover phase 2 notification attempt failed");
        const size_t chal_count = csbuf_get_v(&resp);
        const size_t chal_dlen = resp.d;
        log_devdebug("TAK1 challenge handoff got count %zu dlen %zu", chal_count, chal_dlen);
        size_t offset = 0;
        for (size_t i = 0; i < chal_count; i++) {
            if (offset + 5U > chal_dlen)
                log_fatal("REPLACE[new daemon]: corrupt challenge data size");
            size_t cset_dlen = gdnsd_get_una16(&chal_data[offset]);
            offset += 2U;
            size_t ttl_remain = gdnsd_get_una16(&chal_data[offset]);
            offset += 2U;
            size_t cset_count = chal_data[offset++];
            if (offset + cset_dlen > chal_dlen)
                log_fatal("REPLACE[new daemon]: corrupt challenge data size");
            if (cset_create(loop, ttl_remain, cset_count, cset_dlen, &chal_data[offset]))
                log_fatal("REPLACE[new daemon]: illegal challenge handoff data");
            offset += cset_dlen;
        }
        free(chal_data);
    }
}

typedef enum {
    ACT_UNDEF = 0,
    ACT_CHECKCONF,
    ACT_START,
    ACT_DAEMONIZE
} cmdline_action_t;

typedef struct {
    const char* cfg_dir;
    bool force_zsd;
    bool replace_ok;
    bool idempotent;
    bool deadopt_f;
    bool deadopt_s;
    bool deadopt_x;
    cmdline_action_t action;
} cmdline_opts_t;

F_NONNULL
static void parse_args(const int argc, char** argv, cmdline_opts_t* copts)
{
    int optchar;
    while ((optchar = getopt(argc, argv, "c:DlSRifsx"))) {
        switch (optchar) {
        case 'c':
            copts->cfg_dir = optarg;
            break;
        case 'D':
            gdnsd_log_set_debug(true);
            break;
        case 'l':
            gdnsd_log_set_syslog(true, NULL);
            break;
        case 'S':
            copts->force_zsd = true;
            break;
        case 'R':
            copts->replace_ok = true;
            break;
        case 'i':
            copts->idempotent = true;
            break;
        case 'f':
            copts->deadopt_f = true;
            break;
        case 's':
            copts->deadopt_s = true;
            break;
        case 'x':
            copts->deadopt_x = true;
            break;
        case -1:
            if (optind == (argc - 1)) {
                if (!strcasecmp("checkconf", argv[optind])) {
                    copts->action = ACT_CHECKCONF;
                    return;
                } else if (!strcasecmp("start", argv[optind])) {
                    copts->action = ACT_START;
                    return;
                } else if (!strcasecmp("daemonize", argv[optind])) {
                    copts->action = ACT_DAEMONIZE;
                    gdnsd_log_set_syslog(true, NULL);
                    return;
                }
            }
            S_FALLTHROUGH; // FALLTHROUGH
        default:
            usage(argv[0]);
        }
    }
    usage(argv[0]);
}

int main(int argc, char** argv)
{
    umask(022);
    // Parse args, getting the config path
    //   returning the action.  Exits on cmdline errors,
    //   does not use assert/log stuff.
    cmdline_opts_t copts = {
        .cfg_dir = NULL,
        .force_zsd = false,
        .replace_ok = false,
        .idempotent = false,
        .deadopt_s = false,
        .deadopt_x = false,
        .action = ACT_UNDEF
    };

    parse_args(argc, argv, &copts);
    gdnsd_assert(copts.action != ACT_UNDEF);

    if (copts.deadopt_f)
        log_err("The commandline option '-f' has been removed.  This will be an error in a future major version update!");
    if (copts.deadopt_s)
        log_err("The commandline option '-s' has been removed.  This will be an error in a future major version update!");
    if (copts.deadopt_x)
        log_err("The commandline option '-x' has been removed.  This will be an error in a future major version update!");

    if (copts.replace_ok && copts.idempotent)
        usage(argv[0]);

    // Init daemon code if starting
    if (copts.action != ACT_CHECKCONF)
        gdnsd_init_daemon(copts.action == ACT_DAEMONIZE);

    log_info("gdnsd version " PACKAGE_VERSION " @ pid %li", (long)getpid());

    // Load and init basic pathname config (but no mkdir/chmod if checkconf)
    vscf_data_t* cfg_root = gdnsd_init_paths(copts.cfg_dir, copts.action != ACT_CHECKCONF);

    // Load (but do not act on) socket config
    socks_cfg_t* socks_cfg = socks_conf_load(cfg_root);

    // init locked control socket if starting, can fail if concurrent daemon,
    // or begin a takeover process if CLI flag allows
    csc_t* csc = NULL;
    css_t* css = NULL;
    if (copts.action != ACT_CHECKCONF) {
        css = css_new(argv[0], socks_cfg, NULL);
        if (!css) {
            if (copts.idempotent) {
                log_info("Another instance is already running, success");
                exit(0);
            }
            if (!copts.replace_ok)
                log_fatal("Another instance is running and has the control socket locked, failing");
            csc = csc_new(13, "REPLACE[new daemon]: ");
            if (!csc)
                log_fatal("Another daemon appears to be running, but cannot establish a connection to its control socket for takeover, exiting!");
            do_tak1(csc);
            log_info("REPLACE[new daemon]: Connected to old daemon version %s at PID %li for takeover",
                     csc_get_server_version(csc), (long)csc_get_server_pid(csc));
        }
    }

    // Load full configuration and expose through the global "gcfg"
    gcfg = conf_load(cfg_root, socks_cfg, copts.force_zsd);
    vscf_destroy(cfg_root);

    // Basic init for the acme challenge code
    chal_init();

    // Set up libev error callback
    ev_set_syserr_cb(&syserr_for_ev);

    // default ev loop in main process to handle statio, monitors, control
    // socket, signals, etc.
    def_loop = ev_default_loop(EVFLAG_AUTO);
    if (!def_loop)
        log_fatal("Could not initialize the default libev loop");

    // import challenge data in takeover case
    if (csc)
        do_tak2(def_loop, csc);

    // init DYNA packet sizing stuff
    ltree_init();

    // Load zone data (final step if checkconf) synchronously
    ztree_init();
    if (initialize_zones())
        log_fatal("Initial load of zone data failed");

    if (copts.action == ACT_CHECKCONF)
        exit(0);

    // init the stats code
    statio_init(socks_cfg->num_dns_threads);

    // Lock whole daemon into memory, including all future allocations.
    if (gcfg->lock_mem && mlockall(MCL_CURRENT | MCL_FUTURE))
        log_fatal("mlockall(MCL_CURRENT|MCL_FUTURE) failed: %s (you may need to disabled the lock_mem config option if your system or your ulimits do not allow it)", logf_errno());

    // init cookie support and load key, if any
    if (!gcfg->disable_cookies)
        cookie_config(gcfg->cookie_key_file);

    // Initialize dnspacket stuff
    dnspacket_global_setup(socks_cfg);

    // set up monitoring, which expects an initially empty loop
    gdnsd_mon_start(def_loop);

    // Set up timer hook in the default loop for cookie key rotation
    if (!gcfg->disable_cookies)
        cookie_runtime_init(def_loop);

    // Call plugin pre-run actions
    gdnsd_plugins_action_pre_run();

    // Now that we're past potentially long-running operations like zone
    // loading, initial monitoring, plugin pre_run actions, initiate the
    // true takeover handoff sequence via css_new.
    if (!css)
        css = css_new(argv[0], socks_cfg, &csc);

    // setup main thread signal handlers
    ev_signal* p_sig_int = &sig_int;
    ev_signal* p_sig_term = &sig_term;
    ev_signal* p_sig_usr1 = &sig_usr1;
    ev_signal_init(p_sig_int, terminal_signal, SIGINT);
    p_sig_int->data = css;
    ev_signal_start(def_loop, p_sig_int);
    ev_signal_init(p_sig_term, terminal_signal, SIGTERM);
    p_sig_term->data = css;
    ev_signal_start(def_loop, p_sig_term);
    ev_signal_init(p_sig_usr1, usr1_signal, SIGUSR1);
    ev_signal_start(def_loop, p_sig_usr1);

    // Initialize+bind DNS listening sockets
    socks_dns_lsocks_init(socks_cfg);

    // Start up all of the UDP and TCP i/o threads
    start_threads(socks_cfg);

    // This waits for all of the stat structures to be allocated by the i/o
    //  threads before continuing on.  They must be ready before ev_run()
    //  below, because statio event handlers hit them.
    // This also incidentally waits for all TCP threads to have hit their
    //  listen() call as well, whereas UDP is already at least buffering queued
    //  requests at the socket layer from the time it's bound.
    dnspacket_wait_stats(socks_cfg);

    // Notify 3rd parties of readiness (systemd, or fg process if daemonizing)
    gdnsd_daemon_notify_ready();

    // Notify the user that the listeners are up
    log_info("DNS listeners started");

    // Stop old daemon after establishing the new one's listeners, and import
    // the final stats from it
    if (csc) {
        if (!csc_stop_server(csc)) {
            uint64_t* stats_raw = NULL;
            const size_t dlen = csc_get_stats_handoff(csc, &stats_raw);
            if (dlen) {
                gdnsd_assert(stats_raw);
                statio_deserialize(stats_raw, dlen);
            }
            free(stats_raw);
        }
        csc_delete(csc);
        csc = NULL;
    }

    // Set up zone reload mechanism and control socket handlers in the loop
    setup_reload_zones(css);
    css_start(css, def_loop);

    // The daemon stays in this libev loop for life,
    // until there's a reason to cleanly exit
    ev_run(def_loop, 0);

    // request i/o threads to exit
    request_io_threads_stop(socks_cfg);

    // get rid of child procs (e.g. extmon helper)
    gdnsd_kill_registered_children();

    // wait for i/o threads to exit
    for (unsigned i = 0; i < socks_cfg->num_dns_threads; i++) {
        dns_thread_t* t = &socks_cfg->dns_threads[i];
        void* raw_exit_status = (void*)42U;
        int pthread_err = pthread_join(t->threadid, &raw_exit_status);
        if (pthread_err)
            log_err("pthread_join() of DNS thread failed: %s", logf_strerror(pthread_err));
        if (raw_exit_status != NULL)
            log_err("pthread_join() of DNS thread returned %p", raw_exit_status);
    }

    // deallocate resources
    atexit_execute();

    // If we were replaced, this sends a final dump of stats to the new daemon
    // for stats counter continuity
    css_send_stats_handoff(css);

    // We delete this last, because in the case of "gdnsdctl stop" or "gdnsdctl
    // replace" this is where the active connection to gdnsdctl will be broken,
    // sending it into a loop waiting on our PID to cease existing.
    css_delete(css);

    // Stop the terminal signal handlers very late in the game.  Any terminal
    // signal received since ev_run() returned above will simply not be
    // processed because we never re-entered the eventloop since the handlers
    // saw it.  ev_signal_stop() will restore default signal behavior, which
    // will be to terminate the process, which we'll rely on in raise() below.
    // Regardless of our reason for exiting, it doesn't cause a problem if a
    // new terminal signal races us from here through exit()/raise() below.  It
    // is kinda problematic if we do this earlier (e.g. above i/o thread exit)
    // as it could abort our clean shutdown sequence.
    ev_signal_stop(def_loop, p_sig_term);
    ev_signal_stop(def_loop, p_sig_int);

#ifdef GDNSD_COVERTEST_EXIT
    // We have to use exit() when testing coverage, as raise()
    //   skips over writing out gcov data
    exit(0);
#else
    // kill self with same signal, so that our exit status is correct
    //   for any parent/manager/whatever process that may be watching
    if (killed_by)
        raise(killed_by);
    else
        exit(0);
#endif

    // raise should not return
    gdnsd_assert(0);
}
