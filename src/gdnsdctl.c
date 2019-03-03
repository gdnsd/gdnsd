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
static bool opt_oneshot = false;
static bool opt_ignore_dead = false;
static const char* opt_cfg_dir = NULL;

static volatile sig_atomic_t alarm_raised = 0;
static void sighand_alrm(int s V_UNUSED)
{
    alarm_raised = 1;
    // We only check the alarm_raised flag once per outer retry loop.  Several
    // separate calls are made which could/should fail all the way out
    // immediately with EINTR, but the alarm could also arrive between such
    // calls, or during some call that for some reason implicitly restarts in
    // spite of a lack of SA_RESTART, and at least some of the i/o calls will
    // block indefinitely if there is no alarm signal received.  Therefore, we
    // re-arm indefinitely at 1s intervals to plow through such cases.
    alarm(1U);
}

static void install_alarm(void)
{
    struct sigaction sa;
    sa.sa_handler = sighand_alrm;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGALRM, &sa, 0))
        log_fatal("Cannot install SIGALRM handler!");
    alarm(opt_timeo);
}

F_NONNULL F_NORETURN
static void usage(void)
{
    fprintf(stderr,
            "gdnsdctl version " PACKAGE_VERSION "\n"
            "Usage: gdnsdctl [-c %s] [-D] [-l] [-t %u] [-o] [-i] <action> [...]\n"
            "  -c - Configuration directory (def %s)\n"
            "  -D - Enable verbose debug output\n"
            "  -l - Send logs to syslog rather than stderr\n"
            "  -t - Timeout in seconds (def %u, range %u - %u)\n"
            "  -o - One-shot mode: do not retry soft failures (comms errors, replace-in-progress)\n"
            "  -i - Ignore lack of a running daemon for stop, reload-zones, replace,\n"
            "       and acme-dns-01-flush, reporting success instead of failure in those cases.\n"
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
static bool action_stop(csc_t* csc)
{
    csc_txn_rv_t crv = csc_stop_server(csc);
    if (crv == CSC_TXN_OK) {
        if (!csc_wait_stopping_server(csc)) {
            log_info("Stop command successful, daemon exited");
            return false;
        }
        log_fatal("Stop command accepted, but daemon failed to exit");
    } else if (!opt_oneshot && crv == CSC_TXN_FAIL_SOFT) {
        return true;
    }

    log_fatal("Stop command failed");
}

F_NONNULL
static bool action_reloadz(csc_t* csc)
{
    csbuf_t req;
    csbuf_t resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_ZREL;
    csc_txn_rv_t crv = csc_txn(csc, &req, &resp);
    if (opt_oneshot && crv == CSC_TXN_FAIL_SOFT)
        crv = CSC_TXN_FAIL_HARD;
    if (crv == CSC_TXN_FAIL_HARD)
        log_fatal("Reload transaction failed");
    if (crv == CSC_TXN_FAIL_SOFT)
        return true;

    log_info("Zone data reloaded");
    return false;
}

F_NONNULL
static bool action_replace(csc_t* csc)
{
    const pid_t s_pid = csc_get_server_pid(csc);
    const char* s_vers = csc_get_server_version(csc);
    log_info("REPLACE[gdnsdctl]: Sending replace command to old daemon version %s running at PID %li", s_vers, (long)s_pid);

    csbuf_t req;
    csbuf_t resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_REPL;
    csc_txn_rv_t crv = csc_txn(csc, &req, &resp);
    if (opt_oneshot && crv == CSC_TXN_FAIL_SOFT)
        crv = CSC_TXN_FAIL_HARD;
    if (crv == CSC_TXN_FAIL_HARD)
        log_fatal("REPLACE[gdnsdctl]: Replace command to old daemon failed");
    if (crv == CSC_TXN_FAIL_SOFT)
        return true;

    if (csc_wait_stopping_server(csc))
        log_fatal("REPLACE[gdnsdctl]: Replace command to old daemon succeeded, but old daemon never finished exiting...");

    csc_t* csc2 = csc_new(0, "");
    if (!csc2)
        log_fatal("REPLACE[gdnsdctl]: Cannot establish connection to new daemon for verification");

    const pid_t s2_pid = csc_get_server_pid(csc2);
    const char* s2_vers = csc_get_server_version(csc2);
    log_info("REPLACE[gdnsdctl]: SUCCESS, new daemon version %s running at PID %li", s2_vers, (long)s2_pid);
    csc_delete(csc2);
    return false;
}

F_NONNULL
static bool action_status(csc_t* csc)
{
    const pid_t s_pid = csc_get_server_pid(csc);
    const char* s_vers = csc_get_server_version(csc);
    log_info("version %s running at PID %li", s_vers, (long)s_pid);
    return false;
}

F_NONNULL
static bool action_stats(csc_t* csc)
{
    char* resp_data;
    csbuf_t req;
    csbuf_t resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_STAT;
    csc_txn_rv_t crv = csc_txn_getdata(csc, &req, &resp, &resp_data);
    if (opt_oneshot && crv == CSC_TXN_FAIL_SOFT)
        crv = CSC_TXN_FAIL_HARD;
    if (crv == CSC_TXN_FAIL_HARD)
        log_fatal("Stats command failed");
    if (crv == CSC_TXN_FAIL_SOFT)
        return true;

    gdnsd_assert(crv == CSC_TXN_OK);

    if (resp_data) {
        gdnsd_assert(resp.d);
        fwrite(resp_data, 1, resp.d, stdout);
        free(resp_data);
    }

    return false;
}

F_NONNULL
static bool action_states(csc_t* csc)
{
    char* resp_data;
    csbuf_t req;
    csbuf_t resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_STATE;
    csc_txn_rv_t crv = csc_txn_getdata(csc, &req, &resp, &resp_data);
    if (opt_oneshot && crv == CSC_TXN_FAIL_SOFT)
        crv = CSC_TXN_FAIL_HARD;
    if (crv == CSC_TXN_FAIL_HARD)
        log_fatal("States command failed");
    if (crv == CSC_TXN_FAIL_SOFT)
        return true;


    gdnsd_assert(crv == CSC_TXN_OK);

    if (resp_data) {
        gdnsd_assert(resp.d);
        fwrite(resp_data, 1, resp.d, stdout);
        free(resp_data);
    }

    return false;
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
static bool action_chal(csc_t* csc, int argc, char** argv)
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
            log_fatal("Payload for '%s' is not 43 bytes long", dname_input);
        for (unsigned j = 0; j < 43; j++) {
            const uint8_t x = (uint8_t)chal_input[j];
            if (!b64u_legal[x])
                log_fatal("Payload for '%s' has illegal base64url bytes", dname_input);
        }
        memcpy(&buf[dlen], chal_input, 43);
        dlen += 43;
        buf[dlen++] = 0;
        gdnsd_assert(dlen <= CHAL_MAX_DLEN);
    }

    csbuf_t req;
    csbuf_t resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_CHAL;
    csbuf_set_v(&req, chal_count);
    req.d = dlen;
    csc_txn_rv_t crv = csc_txn_senddata(csc, &req, &resp, (char*)buf);
    if (opt_oneshot && crv == CSC_TXN_FAIL_SOFT)
        crv = CSC_TXN_FAIL_HARD;
    if (crv == CSC_TXN_FAIL_HARD)
        log_fatal("acme-dns-01 command failed");
    if (crv == CSC_TXN_FAIL_SOFT)
        return true;

    gdnsd_assert(crv == CSC_TXN_OK);
    log_info("ACME DNS-01 challenges accepted");
    return false;
}

F_NONNULL
static bool action_chalf(csc_t* csc)
{
    csbuf_t req;
    csbuf_t resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_CHALF;
    csc_txn_rv_t crv = csc_txn(csc, &req, &resp);
    if (opt_oneshot && crv == CSC_TXN_FAIL_SOFT)
        crv = CSC_TXN_FAIL_HARD;
    if (crv == CSC_TXN_FAIL_HARD)
        log_fatal("Failed to flush ACME DNS-01 challenges");
    if (crv == CSC_TXN_FAIL_SOFT)
        return true;

    log_info("ACME DNS-01 challenges flushed");
    return false;
}

static bool do_action(csc_t* csc, const char* action, int argc, char** argv)
{
    if (!strcasecmp(action, "acme-dns-01"))
        return action_chal(csc, argc, argv);

    // Actions above use arguments
    if (argc)
        usage();
    // Actions below do not use arguments

    if (!strcasecmp(action, "stop"))
        return action_stop(csc);
    if (!strcasecmp(action, "reload-zones"))
        return action_reloadz(csc);
    if (!strcasecmp(action, "replace"))
        return action_replace(csc);
    if (!strcasecmp(action, "status"))
        return action_status(csc);
    if (!strcasecmp(action, "stats"))
        return action_stats(csc);
    if (!strcasecmp(action, "states"))
        return action_states(csc);
    if (!strcasecmp(action, "acme-dns-01-flush"))
        return action_chalf(csc);

    usage();
}

// These commands, when used with "-i", return success if no connection can be
// established.  For "stop" and "acme-dns-01-flush" this mode of operation is
// obvious (and arguably could've been default, but whatever), but for
// "reload-zones" and "replace" the use-case for "-i" is a little more subtle:
// you would use it with a scripted integration that does not want to interfere
// with other tools managing the daemon's liveness, but does want to ensure
// that if the daemon is alive, it reflects recently applies changes to
// zonefiles and/or config.  If it's down, then those state updates will
// obviously be available the next time something else starts it, so it's not
// untruthful to say they've been applied in some sense.
F_NONNULL
static bool can_ignore_dead(const char* action)
{
    return !strcasecmp(action, "stop")
           || !strcasecmp(action, "reload-zones")
           || !strcasecmp(action, "replace")
           || !strcasecmp(action, "acme-dns-01-flush");
}

F_NONNULL F_RETNN
static const char* parse_args(const int argc, char** argv)
{
    unsigned long timeo;
    int optchar;
    while ((optchar = getopt(argc, argv, "c:Dloit:"))) {
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
        case 'o':
            opt_oneshot = true;
            break;
        case 'i':
            opt_ignore_dead = true;
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
            return argv[optind++];
        default:
            usage();
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
    const char* action = parse_args(argc, argv);
    unsetenv("POSIXLY_CORRECT");

    gdnsd_assert(action);
    gdnsd_log_set_debug(opt_debug);
    gdnsd_log_set_syslog(opt_syslog, "gdnsdctl");
    vscf_data_t* cfg_root = gdnsd_init_paths(opt_cfg_dir, false);
    vscf_destroy(cfg_root);

    install_alarm();
    while (1) {
        csc_t* csc = csc_new(0, "");
        if (!csc) {
            if (opt_ignore_dead && can_ignore_dead(action)) {
                log_info("No running daemon, succeeding");
                return 0;
            }
            return 1; // csc_new already logged the reason
        }

        const bool retry = do_action(csc, action, argc - optind, &argv[optind]);
        csc_delete(csc);

        if (!retry)
            return 0;

        if (opt_oneshot || alarm_raised) {
            if (alarm_raised)
                log_err("Operation timed out");
            return 1;
        }

        log_warn("Soft failure (comms error or blocked by an in-progress replace operation), retrying in ~1s...");
        const struct timespec asecond = { 1, 0 };
        if (nanosleep(&asecond, NULL) && errno != EINTR)
            log_fatal("nanosleep() failed: %s", logf_errno());
    }
}
