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
#include <gdnsd/compiler.h>
#include <gdnsd/dmn.h>
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/vscf.h>
#include <gdnsd/paths.h>
#include <gdnsd/cs.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

F_NONNULL F_NORETURN
static void usage(const char* argv0) {
    fprintf(stderr,
        "gdnsdctl version " PACKAGE_VERSION "\n"
        "Usage: %s [-D] [-c %s] <action>\n"
        "  -D - Enable verbose debug output\n"
        "  -c - Configuration directory\n"
        "Actions:\n"
        "  stop - Stops the running daemon\n"
        "  reload-zones - Reload the running daemon's zone data\n"
        "  reload - Full reload (code, config, data) of the running daemon\n"
        "  status - Checks the running daemon's status\n"
        "  stats - Dumps JSON statistics from the running daemon\n"
        "\nFeatures: " BUILD_FEATURES
        "\nBuild Info: " BUILD_INFO
        "\nBug report URL: " PACKAGE_BUGREPORT
        "\nGeneral info URL: " PKG_URL
        "\n",
        argv0, gdnsd_get_default_config_dir()
    );
    exit(2);
}

// get control socket client handle
static gdnsd_csc_t* get_csc(void) {
    char* cs_path = gdnsd_resolve_path_run("cs", NULL);
    gdnsd_csc_t* csc = gdnsd_csc_new(cs_path);
    free(cs_path);
    return csc;
}

/**** Action functions ****/

F_NORETURN
static void action_stop(const int argc V_UNUSED, char** argv V_UNUSED) {
    dmn_assert(argc); dmn_assert(argv);

    gdnsd_csc_t* csc = get_csc();
    pid_t csc_pid = gdnsd_csc_getpid(csc);
    uint8_t buffer[8] = "stop";
    const uint32_t resp_len = gdnsd_csc_txn(csc, buffer, 4, 8);
    if(resp_len != 8 || memcmp(buffer, "stopping", 8))
        log_fatal("gdnsd did not respond correctly to 'stop' command");
    gdnsd_csc_closewait(csc);
    if(dmn_terminate_pid_and_wait(0, csc_pid))
        log_fatal("Stop failed, daemon still running, giving up!");
    exit(0);
}

F_NORETURN
static void action_reloadz(const int argc V_UNUSED, char** argv V_UNUSED) {
    dmn_assert(argc); dmn_assert(argv);
    dmn_log_fatal("XXX Not yet implemented");
}

F_NORETURN
static void action_reload(const int argc V_UNUSED, char** argv V_UNUSED) {
    dmn_assert(argc); dmn_assert(argv);
    dmn_log_fatal("XXX Not yet implemented");
}

F_NORETURN
static void action_status(const int argc V_UNUSED, char** argv V_UNUSED) {
    dmn_assert(argc); dmn_assert(argv);

    const pid_t oldpid = dmn_status();
    if(!oldpid) {
        log_info("status: not running");
        exit(3);
    }
    log_info("status: running at pid %li", (long)oldpid);

    // validate csock "getpid" vs fcntl result above
    gdnsd_csc_t* csc = get_csc();
    pid_t csc_pid = gdnsd_csc_getpid(csc);
    if(oldpid != csc_pid)
        log_fatal("MCP PID validation failed: pidfile has %li, socket says %li",
            (long)oldpid, (long)csc_pid);

    log_info("status: control sockets OK");
    exit(0);
}

F_NORETURN
static void action_stats(const int argc V_UNUSED, char** argv V_UNUSED) {
    dmn_assert(argc); dmn_assert(argv);

    gdnsd_csc_t* csc = get_csc();
    uint8_t* rt_buffer = xmalloc(65000);
    memcpy(rt_buffer, "stats", 5);
    const uint32_t rt_resp_len = gdnsd_csc_txn(csc, rt_buffer, 5, 65000);
    fwrite(rt_buffer, 1, rt_resp_len, stdout);
    exit(0);
}

/**** Commandline parsing and action selection ****/

typedef void (*afunc_t)(const int argc, char** argv);

static struct {
    const char* cmdstring;
    afunc_t func;
} actionmap[] = {
    { "stop",         action_stop    },
    { "reload-zones", action_reloadz },
    { "reload",       action_reload  },
    { "status",       action_status  },
    { "stats",        action_stats   },
};

F_NONNULL F_PURE F_RETNN
static afunc_t match_action(const char* argv0, const char* match) {
    dmn_assert(argv0); dmn_assert(match);

    unsigned i;
    for(i = 0; i < ARRAY_SIZE(actionmap); i++)
        if(!strcasecmp(actionmap[i].cmdstring, match))
            return actionmap[i].func;
    usage(argv0);
}

typedef struct {
    const char* cfg_dir;
    bool debug;
} cmdline_opts_t;

F_NONNULL F_RETNN
static afunc_t parse_args(const int argc, char** argv, cmdline_opts_t* copts) {
    dmn_assert(argc); dmn_assert(argv); dmn_assert(copts);

    int optchar;
    while((optchar = getopt(argc, argv, "c:D"))) {
        switch(optchar) {
            case 'c':
                copts->cfg_dir = optarg;
                break;
            case 'D':
                copts->debug = true;
                break;
            case -1:
                if(optind != (argc - 1))
                    usage(argv[0]);
                return match_action(argv[0], argv[optind]);
                break;
            default:
                usage(argv[0]);
                break;
        }
    }

    usage(argv[0]);
}

int main(int argc, char** argv) {
    // Parse args, getting the config path
    //   returning the action.  Exits on cmdline errors,
    //   does not use libdmn assert/log stuff.
    cmdline_opts_t copts = {
        .cfg_dir = NULL,
        .debug = false,
    };
    afunc_t action_func = parse_args(argc, argv, &copts);
    dmn_assert(action_func);

    // dmn_init lets us start using dmn log funcs for config errors, etc
    // note we force foreground+no-syslog in gdnsdctl, even though the flags
    // say otherwise, as those are to pass through to gdnsd
    dmn_init(copts.debug, true, false, PACKAGE_NAME);

    // Initialize libgdnsd and get parsed config
    vscf_data_t* cfg_root = gdnsd_initialize(copts.cfg_dir, false);
    vscf_destroy(cfg_root); // don't need it...

    // dmn_pm_config() lets us do daemon actions
    char* rundir = gdnsd_resolve_path_run(NULL, NULL);
    dmn_pm_config(rundir);
    free(rundir);

    // invoke requested action, none of which return
    action_func(argc, argv);
    dmn_assert(0);
}
