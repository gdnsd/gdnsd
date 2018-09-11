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
#include "chal.h"

#include <gdnsd/compiler.h>
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/vscf.h>
#include <gdnsd/paths.h>
#include <gdnsd/dname.h>

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
static void usage(void)
{
    fprintf(stderr,
            "gdnsdctl version " PACKAGE_VERSION "\n"
            "Usage: gdnsdctl [-c %s] [-D] [-l] [-t %u] <action> [...]\n"
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
            "  acme-dns-01 - Create ACME DNS-01 payloads from additional arguments:\n"
            "                <name> <payload> <name> <payload> ... [max %u payloads]\n"
            "  acme-dns-01-flush - Flush (remove) all ACME DNS-01 payloads added above\n"
            "\nFeatures: " BUILD_FEATURES
            "\nBuild Info: " BUILD_INFO
            "\nBug report URL: " PACKAGE_BUGREPORT
            "\nGeneral info URL: " PACKAGE_URL
            "\n",
            gdnsd_get_default_config_dir(), DEF_TIMEO,
            gdnsd_get_default_config_dir(), DEF_TIMEO,
            MIN_TIMEO, MAX_TIMEO,
            CHAL_MAX_COUNT
           );
    exit(2);
}

/**** Action functions ****/

F_NONNULL
static int action_stop(csc_t* csc, int argc, char** argv V_UNUSED)
{
    if (argc)
        usage(); // No additional arguments

    return csc_stop_server(csc)
           || csc_wait_stopping_server(csc);
}

F_NONNULL
static int action_reloadz(csc_t* csc, int argc, char** argv V_UNUSED)
{
    if (argc)
        usage(); // No additional arguments

    csbuf_t req, resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_ZREL;
    if (csc_txn(csc, &req, &resp)) {
        log_err("Reload transaction failed!");
        return 1;
    }
    log_info("Zone data reloaded");
    return 0;
}

F_NONNULL
static int action_replace(csc_t* csc, int argc, char** argv V_UNUSED)
{
    if (argc)
        usage(); // No additional arguments

    const pid_t s_pid = csc_get_server_pid(csc);
    const char* s_vers = csc_get_server_version(csc);
    log_info("Existing daemon: version %s running at pid %li", s_vers, (long)s_pid);

    csbuf_t req, resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_REPL;
    if (csc_txn(csc, &req, &resp)) {
        log_err("Replace command to old daemon failed");
        return 1;
    }

    if (csc_wait_stopping_server(csc)) {
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
static int action_status(csc_t* csc, int argc, char** argv V_UNUSED)
{
    if (argc)
        usage(); // No additional arguments

    const pid_t s_pid = csc_get_server_pid(csc);
    const char* s_vers = csc_get_server_version(csc);
    log_info("version %s running at pid %li", s_vers, (long)s_pid);
    return 0;
}

F_NONNULL
static int action_stats(csc_t* csc, int argc, char** argv V_UNUSED)
{
    if (argc)
        usage(); // No additional arguments

    char* resp_data;
    csbuf_t req, resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_STAT;
    if (csc_txn_getdata(csc, &req, &resp, &resp_data))
        return 1;
    fwrite(resp_data, 1, resp.d, stdout);
    free(resp_data);
    return 0;
}

F_NONNULL
static int action_states(csc_t* csc, int argc, char** argv V_UNUSED)
{
    if (argc)
        usage(); // No additional arguments

    char* resp_data;
    csbuf_t req, resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_STATE;
    if (csc_txn_getdata(csc, &req, &resp, &resp_data))
        return 1;
    fwrite(resp_data, 1, resp.d, stdout);
    free(resp_data);
    return 0;
}

// base64url legal chars are [-_0-9A-Za-z]
static const unsigned b64u_legal[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

F_NONNULL
static int action_chal(csc_t* csc, int argc, char** argv)
{
    // Requires 2+ additional arguments, in pairs
    if (!argc || argc & 1 || argc > (int)(CHAL_MAX_COUNT * 2))
        usage();

    const unsigned chal_count = (unsigned)argc >> 1U;
    unsigned dlen = 0;
    uint8_t* buf = xmalloc(CHAL_MAX_DLEN);
    for (int i = 0; i < argc; i += 2) {
        gdnsd_assert(CHAL_MAX_DLEN - dlen >= (240U + 44U));
        const char* dname_input = argv[i];
        const char* chal_input = argv[i + 1];
        // If the user mistakenly puts the _acme-challenge. prefix on the
        // commandline, strip it:
        if (!strncmp(dname_input, "_acme-challenge.", 16U))
            dname_input += 16U;
        if (DNAME_INVALID == dname_from_string(&buf[dlen], dname_input, strlen(dname_input)))
            log_fatal("Could not parse domainname '%s'", dname_input);
        if (buf[dlen] > 239)
            log_fatal("Domainname '%s' is too long for ACME DNS-01 challenges", dname_input);
        dname_terminate(&buf[dlen]);
        dlen += (buf[dlen] + 1U);
        if (strlen(chal_input) != 43)
            log_fatal("Payload '%s' for '%s' is not 43 bytes long", chal_input, dname_input);
        for (unsigned j = 0; j < 43; j++)
            if (!b64u_legal[(unsigned)argv[i + 1][j]])
                log_fatal("Payload '%s' for '%s' illegal base64url bytes", chal_input, dname_input);
        memcpy(&buf[dlen], chal_input, 43);
        dlen += 43;
        buf[dlen++] = 0;
        gdnsd_assert(dlen <= CHAL_MAX_DLEN);
    }

    csbuf_t req, resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_CHAL;
    csbuf_set_v(&req, chal_count);
    req.d = dlen;
    return csc_txn_senddata(csc, &req, &resp, (char*)buf);
}

F_NONNULL
static int action_chalf(csc_t* csc, int argc, char** argv V_UNUSED)
{
    if (argc)
        usage(); // No additional arguments

    csbuf_t req, resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_CHALF;
    if (csc_txn(csc, &req, &resp)) {
        log_err("Failed to flush ACME DNS-01 challenges!");
        return 1;
    }
    log_info("ACME DNS-01 challenges flushed");
    return 0;
}


/**** Commandline parsing and action selection ****/

typedef int (*afunc_t)(csc_t* csc, int argc, char** argv);

static struct {
    const char* cmdstring;
    afunc_t func;
} actionmap[] = {
    { "stop",               action_stop    },
    { "reload-zones",       action_reloadz },
    { "replace",            action_replace },
    { "status",             action_status  },
    { "stats",              action_stats   },
    { "states",             action_states  },
    { "acme-dns-01",        action_chal    },
    { "acme-dns-01-flush",  action_chalf   },
};

F_NONNULL F_PURE F_RETNN
static afunc_t match_action(const char* match)
{
    unsigned i;
    for (i = 0; i < ARRAY_SIZE(actionmap); i++)
        if (!strcasecmp(actionmap[i].cmdstring, match))
            return actionmap[i].func;
    usage();
}

F_NONNULL F_RETNN
static afunc_t parse_args(const int argc, char** argv)
{
    unsigned long timeo;
    int optchar;
    while ((optchar = getopt(argc, argv, "c:Dlt:"))) {
        switch (optchar) {
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
            if (errno || timeo < MIN_TIMEO || timeo > MAX_TIMEO)
                usage();
            opt_timeo = (unsigned)timeo;
            break;
        case -1:
            if (optind >= argc)
                usage();
            return match_action(argv[optind++]);
            break;
        default:
            usage();
            break;
        }
    }

    usage();
}

int main(int argc, char** argv)
{
    umask(022);

    // We need POSIXLY_CORRECT to force GNU libc to do things the POSIX way in
    // getopt(), so that option processing stops after the action verb instead
    // of permuting the action verb out to the end.  Otherwise we run into
    // issues with acme-dns-01 challenge data which happens to start with the
    // legitimate base64url character '-'.
    setenv("POSIXLY_CORRECT", "1", 1);
    afunc_t action_func = parse_args(argc, argv);
    unsetenv("POSIXLY_CORRECT");

    gdnsd_assert(action_func);
    gdnsd_log_set_debug(opt_debug);
    gdnsd_log_set_syslog(opt_syslog);
    vscf_data_t* cfg_root = gdnsd_init_paths(opt_cfg_dir, false);
    vscf_destroy(cfg_root);
    csc_t* csc = csc_new(opt_timeo);
    int rv = action_func(csc, argc - optind, &argv[optind]);
    csc_delete(csc);
    return rv;
}
