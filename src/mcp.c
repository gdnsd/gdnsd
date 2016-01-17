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
#include "mcp.h"

#include "runtime.h"
#include "socks.h"
#include "conf.h"
#include "dnsio_tcp.h"
#include "dnsio_udp.h"
#include "dnspacket.h"
#include "statio.h"
#include "ztree.h"

#include <gdnsd-prot/misc.h>
#include <gdnsd-prot/mon.h>
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/vscf.h>
#include <gdnsd/paths.h>
#include <gdnsd/misc.h>
#include <gdnsd/cs.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <pwd.h>
#include <time.h>
#include <ev.h>

F_NONNULL F_NORETURN
static void usage(const char* argv0) {
    fprintf(stderr,
        PACKAGE_NAME " version " PACKAGE_VERSION "\n"
        "Usage: %s [-fxsSD] [-c %s] <action>\n"
        "  -f - Foreground mode for 'start'\n"
        "  -x - No syslog output for 'start' (requires -f)\n"
        "  -s - Force 'zones_strict_startup = true' for this invocation\n"
        "  -S - Force 'zones_strict_data = true' for this invocation\n"
        "  -D - Enable verbose debug output\n"
        "  -c - Configuration directory\n"
        "Actions:\n"
        "  checkconf - Checks validity of config and zone files\n"
        "  start - Start " PACKAGE_NAME " as a regular daemon\n"
        "\nFeatures: " BUILD_FEATURES
        "\nBuild Info: " BUILD_INFO
        "\nBug report URL: " PACKAGE_BUGREPORT
        "\nGeneral info URL: " PKG_URL
        "\n",
        argv0, gdnsd_get_default_config_dir()
    );
    exit(2);
}

static pid_t runtime_pid = -1;

typedef struct {
    const char* cfg_dir;
    bool force_zss;
    bool force_zsd;
    bool debug;
    bool foreground;
    bool use_syslog;
    bool starting;
} cmdline_opts_t;

F_NONNULL
static void parse_args(const int argc, char** argv, cmdline_opts_t* copts) {
    dmn_assert(argc); dmn_assert(argv); dmn_assert(copts);

    int optchar;
    while((optchar = getopt(argc, argv, "c:xDfsS"))) {
        switch(optchar) {
            case 'c':
                copts->cfg_dir = optarg;
                break;
            case 'x':
                copts->use_syslog = false;
                break;
            case 'D':
                copts->debug = true;
                break;
            case 'f':
                copts->foreground = true;
                break;
            case 's':
                copts->force_zss = true;
                break;
            case 'S':
                copts->force_zsd = true;
                break;
            case -1:
                if(optind == (argc - 1)) {
                    if(!strcasecmp(argv[optind], "start")) {
                        copts->starting = true;
                        return;
                    } else if(!strcasecmp(argv[optind], "checkconf")) {
                        copts->starting = false;
                        return;
                    }
                }
                // fallthrough
            default:
                usage(argv[0]);
                break;
        }
    }

    usage(argv[0]);
}

static void memlock(const bool started_as_root V_UNUSED) {
#ifdef RLIMIT_MEMLOCK
    struct rlimit rlim;
    if(getrlimit(RLIMIT_MEMLOCK, &rlim))
        log_fatal("getrlimit(RLIMIT_MEMLOCK) failed: %s", dmn_logf_errno());

    if(rlim.rlim_cur != RLIM_INFINITY) {
        if(!started_as_root) {
            // First, raise _cur to _max, which should never fail
            if(rlim.rlim_cur != rlim.rlim_max) {
                rlim.rlim_cur = rlim.rlim_max;
                if(setrlimit(RLIMIT_MEMLOCK, &rlim))
                    log_fatal("setrlimit(RLIMIT_MEMLOCK, cur = max) "
                        "failed: %s", dmn_logf_errno());
            }

            unsigned long long rc_printable = rlim.rlim_cur;

            if(rlim.rlim_cur < 1048576)
                log_fatal("Not started as root, lock_mem was set, "
                    "and the rlimit for locked memory is unreasonably "
                    "low (%llu bytes), failing", rc_printable);

            log_info("The rlimit for locked memory is %llu MB, and the "
                "daemon can't do anything about that since it wasn't "
                "started as root.  This may or may not be too small at "
                "runtime, leading to failure.  You have been warned.",
                (rc_printable >> 20));
        }
        else {
            // Luckily, root can do as they please with the ulimits, but
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
            // If the daemon gets compromised, even with privdrop,
            //  memlock is probably the least of your worries anyways.
            rlim.rlim_max = RLIM_INFINITY;
            if(setrlimit(RLIMIT_MEMLOCK, &rlim))
                log_fatal("setrlimit(RLIMIT_MEMLOCK, max = INF) "
                    "failed: %s", dmn_logf_errno());

            rlim.rlim_cur = RLIM_INFINITY;
            if(setrlimit(RLIMIT_MEMLOCK, &rlim))
                log_fatal("setrlimit(RLIMIT_MEMLOCK, cur = INF, "
                    "max = INF) failed: %s", dmn_logf_errno());
        }
    }
#endif
    if(mlockall(MCL_CURRENT | MCL_FUTURE))
        log_fatal("mlockall(MCL_CURRENT|MCL_FUTURE) failed: %s (you may need to disabled the lock_mem config option if your system or your ulimits do not allow it)",
            dmn_logf_errno());
}

// XXX these CFG_ macros abound all over the source base - find a better way to generalize?

#define CFG_OPT_BOOL(_store, _opt_set, _name) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_name, true); \
        if(_opt_setting) { \
            if(!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_bool(_opt_setting, &_store->_name)) \
                log_fatal("Config option %s: Value must be 'true' or 'false'", #_name); \
        } \
    } while(0)

#define CFG_OPT_INT(_store, _opt_set, _name, _min, _max) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_name, true); \
        if(_opt_setting) { \
            long _val; \
            if(!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_long(_opt_setting, &_val)) \
                log_fatal("Config option %s: Value must be an integer", #_name); \
            if(_val < _min || _val > _max) \
                log_fatal("Config option %s: Value out of range (%li, %li)", #_name, _min, _max); \
            _store->_name = (int) _val; \
        } \
    } while(0)

#define CFG_OPT_STR(_store, _opt_set, _name) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_name, true); \
        if(_opt_setting) { \
            if(!vscf_is_simple(_opt_setting)) \
                log_fatal("Config option %s: Wrong type (should be string)", #_name); \
            _store->_name = strdup(vscf_simple_get_data(_opt_setting)); \
        } \
    } while(0)

// Privileged config stuff (security, resource limits, etc,
//  that are handled within mcp.c before or during privdrop for
//  the runtime process).
typedef struct {
    const char* username;
    bool weaker_security;
    bool lock_mem;
    int priority; // -21 == "not set", legal range is -20 to +20
} priv_cfg_t;

static const priv_cfg_t priv_cfg_defaults = {
    .username = PACKAGE_NAME,
    .weaker_security = false,
    .lock_mem = false,
    .priority = -21,
};

static priv_cfg_t* priv_conf_load(const vscf_data_t* cfg_root) {
    priv_cfg_t* rv = xmalloc(sizeof(*rv));
    memcpy(rv, &priv_cfg_defaults, sizeof(*rv));

    if(!cfg_root)
        return rv;
    dmn_assert(vscf_is_hash(cfg_root));

    vscf_data_t* options = vscf_hash_get_data_byconstkey(cfg_root, "options", true);
    if(!options)
        return rv;
    if(!vscf_is_hash(options))
        dmn_log_fatal("Config key 'options': wrong type (must be hash)");

    CFG_OPT_STR(rv, options, username);
    CFG_OPT_INT(rv, options, priority, -20L, 20L);
    CFG_OPT_BOOL(rv, options, lock_mem);
    CFG_OPT_BOOL(rv, options, weaker_security);

    return rv;
}

// All of these states progress linearly and all states are visited unless
// there's an abnormal termination
typedef enum {
    // These three states happen during runtime's startup
    MCP_WAITING_RT_BIND_SOCKS,
    MCP_SENDING_RT_LISTEN,
    MCP_WAITING_RT_LISTEN,
    // The default idle state during normal runtime
    MCP_IDLE,
    // These three states happen during orderly shutdown
    MCP_SENDING_RT_SHUTDOWN,
    MCP_WAITING_RT_SHUTDOWN,
    MCP_WAITING_RT_CLOSE,
} mcp_state_t;

static struct {
    mcp_state_t        state;
    int                rtsock;
    int                killed_by;
    bool               fg;
    const socks_cfg_t* socks_cfg;
    ev_io*             w_rtsock_read;
    ev_io*             w_rtsock_write;
    ev_signal*         w_sigterm;
    ev_signal*         w_sigint;
    ev_signal*         w_sighup;
    struct ev_loop*    loop;
    gdnsd_css_t*       css;
} mcp = {
    .state = MCP_WAITING_RT_BIND_SOCKS,
    .rtsock = -1,
    .killed_by = 0,
    .fg = false,
    .socks_cfg = NULL,
    .w_rtsock_read = NULL,
    .w_rtsock_write = NULL,
    .w_sigterm = NULL,
    .w_sigint = NULL,
    .w_sighup = NULL,
    .loop = NULL,
    .css = NULL,
};

// killed_by is a signal, or zero for controlsock
static void mcp_shutdown(int killed_by) {
    // controlsock and signal watchers not installed until we reach MCP_IDLE,
    //  and protect themselves from calling here once shutdown commences...
    dmn_assert(mcp.state == MCP_IDLE);

    mcp.state = MCP_SENDING_RT_SHUTDOWN;
    ev_io_start(mcp.loop, mcp.w_rtsock_write);
    if(killed_by) {
        mcp.killed_by = killed_by;
        log_info("MCP: Beginning shutdown process down due to signal %i", killed_by);
    }
    else {
        log_info("MCP: Beginning shutdown process down due to control socket command");
    }
    dmn_sd_notify("STOPPING=1", false);
}

F_NONNULLX(1, 2)
static bool css_handler(uint8_t* buffer, uint32_t* len, void* data V_UNUSED) {
    dmn_assert(buffer); dmn_assert(len);

    // controlsock not installed until we reach MCP_IDLE
    dmn_assert(mcp.state >= MCP_IDLE);

    if(mcp.state > MCP_IDLE)
        return true; // abort on all new commands once we're shutting down...

    // handle stop command
    if(*len == 4 && !memcmp(buffer, "stop", 4)) {
        memcpy(buffer, "stopping", 8);
        *len = 8;
        mcp_shutdown(0);
        return false;
    }

    return true; // abort controlsock on invalid input
}

static void mcp_rtsock_read(struct ev_loop* loop, ev_io* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_READ);

    char msg;
    int readrv = read(w->fd, &msg, 1);
    if(readrv != 1) {
        dmn_assert(readrv < 1);
        if(readrv < 0) {
            if(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            dmn_log_fatal("MCP<-Runtime comms: exiting on socket error: %s", dmn_logf_errno());
        }
        else {
            if(mcp.state == MCP_WAITING_RT_CLOSE) {
                // runtime socket closed on exit after final shutdown
                // confirmation, as expected.  Now do a blocking reap of the
                // child before exiting ourselves...
                dmn_log_debug("MCP: blocking reap of runtime child at pid %li", (long)runtime_pid);
                int status = 0;
                pid_t wprv = waitpid(runtime_pid, &status, 0);
                if(wprv != runtime_pid)
                    dmn_log_fatal("MCP: waitpid on runtime child %li failed: %s", (long)runtime_pid, dmn_logf_errno());
                if(!WIFEXITED(status) || WEXITSTATUS(status))
                    dmn_log_fatal("MCP: runtime child %li exited abnormally with status %i", (long)runtime_pid, status);
                dmn_log_info("MCP: exiting cleanly after runtime shutdown completion");
                gdnsd_css_delete(mcp.css);
                if(mcp.killed_by) {
                    ev_signal_stop(loop, mcp.w_sigterm);
                    ev_signal_stop(loop, mcp.w_sigint);
                    if(mcp.fg)
                        ev_signal_stop(loop, mcp.w_sighup);
                    raise(mcp.killed_by);
                }
                exit(0);
            }
            else {
                dmn_log_fatal("MCP<-Runtime comms: socket closed unexpectedly!");
            }
        }
    }

    switch(mcp.state) {
        case MCP_WAITING_RT_BIND_SOCKS:
            if(msg != MSG_2MCP_BIND_SOCKS)
                dmn_log_fatal("MCP<-Runtime: unexpected input %c", msg);
            socks_lsocks_bind(mcp.socks_cfg);
            char* path = gdnsd_resolve_path_run("mcp.sock", NULL);
            mcp.css = gdnsd_css_new(path, css_handler, NULL, 100, 1024, 16, 300); // XXX tunables...
            free(path);
            mcp.state = MCP_SENDING_RT_LISTEN;
            ev_io_start(mcp.loop, mcp.w_rtsock_write);
            break;
        case MCP_WAITING_RT_LISTEN:
            if(msg != MSG_2MCP_LISTENING)
                dmn_log_fatal("MCP<-Runtime: unexpected input %c", msg);
            mcp.state = MCP_IDLE;
            ev_signal_start(mcp.loop, mcp.w_sigterm);
            ev_signal_start(mcp.loop, mcp.w_sigint);
            if(mcp.fg)
                ev_signal_start(mcp.loop, mcp.w_sighup);
            gdnsd_css_start(mcp.css, mcp.loop);
            dmn_finish();
            break;
        case MCP_WAITING_RT_SHUTDOWN:
            if(msg != MSG_2MCP_SHUTDOWN)
                dmn_log_fatal("MCP<-Runtime: unexpected input %c", msg);
            mcp.state = MCP_WAITING_RT_CLOSE;
            break;
        case MCP_IDLE:              // fall-through intentional
        case MCP_WAITING_RT_CLOSE:  // fall-through intentional
        case MCP_SENDING_RT_LISTEN: // fall-through intentional
        case MCP_SENDING_RT_SHUTDOWN:
            dmn_log_fatal("MCP<-Runtime: unexpected input %c", msg);
            break;
        default:
            dmn_assert(0);
    }
}

static void mcp_rtsock_write(struct ev_loop* loop, ev_io* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_WRITE);

    char msg;
    mcp_state_t next_state;

    switch(mcp.state) {
        case MCP_SENDING_RT_LISTEN:
            msg = MSG_2RT_OK_TO_LISTEN;
            next_state = MCP_WAITING_RT_LISTEN;
            break;
        case MCP_SENDING_RT_SHUTDOWN:
            msg = MSG_2RT_SHUTDOWN;
            next_state = MCP_WAITING_RT_SHUTDOWN;
            break;
        default:
            // In all other states, we don't have an active write watcher
            dmn_assert(0);
    }

    // send the "ok to listen" message
    const int writerv = write(w->fd, &msg, 1);
    if(writerv != 1) {
        dmn_assert(writerv < 0);
        if(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        log_fatal("MCP->Runtime comms error: %s", dmn_logf_errno());
    }
    dmn_log_debug("MCP: Runtime accepted message %c", msg);
    mcp.state = next_state;
    ev_io_stop(mcp.loop, mcp.w_rtsock_write);
}

static void mcp_sighandle(struct ev_loop* loop, ev_signal* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_SIGNAL);

    // signal watchers not installed until we reach MCP_IDLE
    dmn_assert(mcp.state >= MCP_IDLE);

    if(mcp.state > MCP_IDLE)
        return; // ignore redundant shutdown signals during shutdown sequence

    mcp_shutdown(w->signum);
}

DMN_F_NORETURN
static int mcp_loop(const int rtsock, const socks_cfg_t* socks_cfg) {
    mcp.rtsock = rtsock;
    mcp.socks_cfg = socks_cfg;

    // non-block for rtsock
    if(fcntl(mcp.rtsock, F_SETFL, (fcntl(mcp.rtsock, F_GETFL, 0)) | O_NONBLOCK) == -1)
        dmn_log_fatal("Failed to set O_NONBLOCK on runtime socket: %s", dmn_logf_errno());

    // Set up watchers
    mcp.w_rtsock_read = xmalloc(sizeof(ev_io));
    mcp.w_rtsock_write = xmalloc(sizeof(ev_io));
    mcp.w_sigterm = xmalloc(sizeof(ev_signal));
    mcp.w_sigint = xmalloc(sizeof(ev_signal));
    if(mcp.fg)
        mcp.w_sighup = xmalloc(sizeof(ev_signal));
    ev_io_init(mcp.w_rtsock_read, mcp_rtsock_read, mcp.rtsock, EV_READ);
    ev_io_init(mcp.w_rtsock_write, mcp_rtsock_write, mcp.rtsock, EV_WRITE);
    ev_signal_init(mcp.w_sigterm, mcp_sighandle, SIGTERM);
    ev_signal_init(mcp.w_sigint, mcp_sighandle, SIGINT);
    if(mcp.fg)
        ev_signal_init(mcp.w_sighup, mcp_sighandle, SIGHUP);

    // Create->Start the loop - does not return!
    // note ev_default_loop() would create a SIGCHLD handler internal to
    // libev, so we're using ev_loop_new() to avoid that so that our waitpid()
    // logic works out...
    mcp.loop = ev_loop_new(EVFLAG_AUTO);
    ev_io_start(mcp.loop, mcp.w_rtsock_read);
    ev_run(mcp.loop, 0);
    dmn_assert(0);

}

F_NONNULL F_NORETURN
static void syserr_for_ev(const char* msg) {
    dmn_assert(msg);
    log_fatal("%s: %s", msg, dmn_logf_errno());
}

int main(int argc, char** argv) {
    // Parse args - Exits on cmdline errors, does not use libdmn assert/log
    cmdline_opts_t copts = {
        .cfg_dir = NULL,
        .force_zss = false,
        .force_zsd = false,
        .debug = false,
        .foreground = false,
        .use_syslog = true,
        .starting = false,
    };
    parse_args(argc, argv, &copts);

    if(!copts.starting) {
        // checkconfig is implicitly -fx
        copts.foreground = true;
        copts.use_syslog = false;
    } else if(!copts.use_syslog && !copts.foreground) {
        // Do not allow disabling syslog when attempting to start
        //   without the foreground flag, as this would result in
        //   complete silence over all messaging channels
        usage(argv[0]);
    }

    // copy foreground flag to mcp global state (for SIGHUP)
    mcp.fg = copts.foreground;

    // dmn_init lets us start using dmn log funcs for config errors, etc
    dmn_init(copts.debug, copts.foreground, copts.use_syslog, PACKAGE_NAME);

    // Initialize libgdnsd and get parsed config
    vscf_data_t* cfg_root = gdnsd_initialize(copts.cfg_dir, copts.starting);

    // configure rundir for pidfile-related dmn code
    char* rundir = gdnsd_resolve_path_run(NULL, NULL);
    dmn_pm_config(rundir);
    free(rundir);

    // Do an early and easy check for a running daemon before trying complex
    // startup, to handle the common cases of starting when already running.
    // Note that true, close races will be resolved deeper in the dmn code
    // when acquiring the fcntl pidfile lock, it's just uglier and more
    // wasteful when not necessary.
    if(copts.starting) {
        const pid_t oldpid = dmn_status();
        if(oldpid) {
            log_err("start: already running at pid %li", (long)oldpid);
            exit(1);
        }
    }

    // Load socket configuration
    socks_cfg_t* socks_cfg = socks_conf_load(cfg_root);

    // In the checkconfig case, we do conf_load/ztree_init here locally here and avoid runtime()
    if(!copts.starting) {
        conf_load(cfg_root, socks_cfg, copts.force_zss, copts.force_zsd);
        ztree_init(true);
        exit(0);
    }

    // Set up libev error callback; all of our procs use libev one way or another...
    ev_set_syserr_cb(&syserr_for_ev);

    // Load privilege-related config stuff into priv_cfg
    priv_cfg_t* priv_cfg = priv_conf_load(cfg_root);

    // Initialize DNS listening sockets, but do not bind() them yet
    socks_lsocks_init(socks_cfg);

    // daemonization fork()->setsid()->fork() if !foreground
    // leaves foreground process running to later exit with
    //   correct status at correct time when dmn_finish() called.
    dmn_fork();

    // attempt to lock up the pidfile: fails fatally if already running
    // XXX note this will need special care on "reload"
    dmn_acquire_pidfile();

    // socketpair for MCP<->Runtime
    int sockets[2] = { -1, -1 };
    dmn_socketpair_cloexec(sockets);

    // This fork delineates the MCP process from the Runtime process
    // MCP is "the daemon" from the POV of the rest of the host machine,
    //   and it processes local interactions like signals, and it
    //   retains root if started as root.
    // Runtime is a child process of MCP that does the core work of
    //   being a DNS server.  It drops privs as appropriate, handles
    //   all network communications, and is managed by MCP.
    runtime_pid = fork();
    if(runtime_pid < 0)
        log_fatal("fork() failed: %s", dmn_logf_errno());

    // --- runtime child process
    if(!runtime_pid) {
        // Close MCP's side of the socketpair
        if(close(sockets[0]))
            dmn_log_fatal("close() of socketpair() fd in runtime failed: %s", dmn_logf_errno());
        const int mcp_sock = sockets[1];

        // within the runtime child process, but over here in mcp.c,
        //   we take care of things that require privileges, then drop
        //   privileges and hand off to runtime.c:runtime().

        // Did we start as root?  This determines how we handle memlock/setpriority
        const bool started_as_root = !geteuid();

        // If root, or if user explicitly set a priority...
        if(started_as_root || priv_cfg->priority != -21) {
            // If root and no explicit value, use -11
            if(started_as_root && priv_cfg->priority == -21)
                priv_cfg->priority = -11;
            if(setpriority(PRIO_PROCESS, (id_t)getpid(), priv_cfg->priority))
                log_warn("setpriority(%i) failed: %s", priv_cfg->priority, dmn_logf_errno());
        }

        // Handle mlockall()
        if(priv_cfg->lock_mem)
            memlock(started_as_root);

        // drop privs
        dmn_privdrop(priv_cfg->username, priv_cfg->weaker_security);

        // this switches over to the runtime.c code:
        runtime(cfg_root, socks_cfg, copts.force_zss, copts.force_zsd, mcp_sock);
        dmn_assert(0); // ^ does not return;
    }

    // -- MCP process running parallel to runtime child

    // Close Runtime's side of the socketpair
    if(close(sockets[1]))
        dmn_log_fatal("close() of socketpair() fd in mcp failed: %s", dmn_logf_errno());

    // MCP no longer needs the vscf config tree...
    vscf_destroy(cfg_root);

    // Set up and enter the MCP loop, which never returns...
    mcp_loop(sockets[0], socks_cfg);
    dmn_assert(0);
}
