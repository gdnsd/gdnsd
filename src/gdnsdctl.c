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

#include "csc.h"

#include <gdnsd/compiler.h>
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/vscf.h>
#include <gdnsd/paths.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

#define MIN_TIMEO 5U
#define DEF_TIMEO 47U
#define MAX_TIMEO 300U

static unsigned opt_timeo = DEF_TIMEO;
static bool opt_debug = false;
static bool opt_syslog = false;
static const char* opt_cfg_dir = NULL;

F_NONNULL F_NORETURN
static void usage(const char* argv0) {
    fprintf(stderr,
            "gdnsdctl version " PACKAGE_VERSION "\n"
            "Usage: %s [-c %s] [-D] [-l] [-t %u] <action>\n"
            "  -c - Configuration directory (def %s)\n"
            "  -D - Enable verbose debug output\n"
            "  -l - Send logs to syslog rather than stderr\n"
            "  -t - Timeout in seconds (def %u, range %u - %u)\n"
            "Actions:\n"
            "  stop - Stops the running daemon\n"
            "  reload-zones - Reload the running daemon's zone data\n"
            "  replace - Ask daemon to spawn a takeover replacement of itself (updates code, config, zone data)\n"
            "  status - Checks the running daemon's status\n"
            "  stats - Dumps JSON statistics from the running daemon\n"
            "  states - Dumps JSON monitored states\n"
            "\nFeatures: " BUILD_FEATURES
            "\nBuild Info: " BUILD_INFO
            "\nBug report URL: " PACKAGE_BUGREPORT
            "\nGeneral info URL: " PACKAGE_URL
            "\n",
            argv0,
            gdnsd_get_default_config_dir(), DEF_TIMEO,
            gdnsd_get_default_config_dir(), DEF_TIMEO,
            MIN_TIMEO, MAX_TIMEO
           );
    exit(2);
}

/**** Action functions ****/

F_NONNULL
static int action_stop(csc_t* csc) {
    return csc_stop_server(csc)
        || csc_wait_stopping_server(csc);
}

F_NONNULL
static int action_reloadz(csc_t* csc) {
    csbuf_t req, resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_ZREL;
    if(csc_txn(csc, &req, &resp)) {
        log_err("Reload transaction failed!");
        return 1;
    }
    log_info("Zone data reloaded");
    return 0;
}

F_NONNULL
static int action_replace(csc_t* csc) {
    const pid_t s_pid = csc_get_server_pid(csc);
    const char* s_vers = csc_get_server_version(csc);
    log_info("Existing daemon: version %s running at pid %li", s_vers, (long)s_pid);

    csbuf_t req, resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_REPL;
    if(csc_txn(csc, &req, &resp)) {
        log_err("Replace command to old daemon failed");
        return 1;
    }

    if(csc_wait_stopping_server(csc)) {
        log_err("Replace command to old daemon succeeded, but old daemon never finished exiting...");
        return 1;
    }

    csc_t* csc2 = csc_new(opt_timeo);
    const pid_t s2_pid = csc_get_server_pid(csc2);
    const char* s2_vers = csc_get_server_version(csc2);
    log_info("Replacement daemon: version %s running at pid %li", s2_vers, (long)s2_pid);
    csc_delete(csc2);
    return 0;
}

F_NONNULL
static int action_status(csc_t* csc) {
    const pid_t s_pid = csc_get_server_pid(csc);
    const char* s_vers = csc_get_server_version(csc);
    log_info("version %s running at pid %li", s_vers, (long)s_pid);
    return 0;
}

F_NONNULL
static int action_stats(csc_t* csc) {
    char* resp_data;
    csbuf_t req, resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_STAT;
    if(csc_txn_getdata(csc, &req, &resp, &resp_data))
        return 1;
    fwrite(resp_data, 1, resp.d, stdout);
    free(resp_data);
    return 0;
}

F_NONNULL
static int action_states(csc_t* csc) {
    char* resp_data;
    csbuf_t req, resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_STATE;
    if(csc_txn_getdata(csc, &req, &resp, &resp_data))
        return 1;
    fwrite(resp_data, 1, resp.d, stdout);
    free(resp_data);
    return 0;
}

/**** Commandline parsing and action selection ****/

typedef int (*afunc_t)(csc_t* csc);

static struct {
    const char* cmdstring;
    afunc_t func;
} actionmap[] = {
    { "stop",         action_stop    },
    { "reload-zones", action_reloadz },
    { "replace",      action_replace },
    { "status",       action_status  },
    { "stats",        action_stats   },
    { "states",       action_states  },
};

F_NONNULL F_PURE F_RETNN
static afunc_t match_action(const char* argv0, const char* match) {
    unsigned i;
    for(i = 0; i < ARRAY_SIZE(actionmap); i++)
        if(!strcasecmp(actionmap[i].cmdstring, match))
            return actionmap[i].func;
    usage(argv0);
}

F_NONNULL F_RETNN
static afunc_t parse_args(const int argc, char** argv) {
    unsigned long timeo;
    int optchar;
    while((optchar = getopt(argc, argv, "c:Dlt:"))) {
        switch(optchar) {
            case 'c':
                opt_cfg_dir = optarg;
                break;
            case 'D':
                opt_debug = true;
                break;
            case 'l':
                opt_syslog = true;
                break;
            case 't':
                errno = 0;
                timeo = strtoul(optarg, NULL, 10);
                if(errno || timeo < MIN_TIMEO || timeo > MAX_TIMEO)
                    usage(argv[0]);
                opt_timeo = (unsigned)timeo;
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
    umask(022);
    afunc_t action_func = parse_args(argc, argv);
    gdnsd_assert(action_func);
    gdnsd_log_set_debug(opt_debug);
    gdnsd_log_set_syslog(opt_syslog);
    vscf_data_t* cfg_root = gdnsd_init_paths(opt_cfg_dir, false);
    vscf_destroy(cfg_root);
    csc_t* csc = csc_new(opt_timeo);
    int rv = action_func(csc);
    csc_delete(csc);
    return rv;
}
