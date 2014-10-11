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

#define GDNSD_PLUGIN_NAME extmon

#include "config.h"
#include "extmon_comms.h"
#include <gdnsd/plugin.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/socket.h>
#include <netdb.h>

// hopefully everyone defines this
#ifndef NSIG
#  define NSIG 100
#endif

typedef struct {
    char* name;
    char** args;
    unsigned num_args;
    unsigned timeout;
    unsigned interval;
    bool direct;
} svc_t;

typedef struct {
    const char* desc;
    const svc_t* svc;
    ev_timer* local_timeout;
    const char* thing;
    unsigned idx;
    bool seen_once;
} mon_t;

static unsigned num_svcs = 0;
static svc_t* svcs = NULL;

static unsigned num_mons = 0;
static mon_t* mons = NULL;

static const char* helper_path = NULL;
static pid_t helper_pid = 0;
static int helper_write_fd = -1;
static int helper_read_fd = -1;

static ev_io* helper_read_watcher = NULL;

// whether we're in the init phase or runtime phase,
//   and how many distinct mon_t have been updated
//   so far during init phase.
static bool init_phase = true;
static unsigned init_phase_count = 0;

// if we experience total helper failure at any point
static bool helper_is_dead_flag = false;

// behavior on helper failure
static bool die_on_helper_failure = false;

static const char fail_msg[] = "plugin_extmon: Cannot continue monitoring, child process gdnsd_extmon_helper failed!";
static void helper_is_dead(struct ev_loop* loop, const bool graceful) {
    dmn_assert(loop);

    if(graceful) {
        log_info("plugin_extmon: helper process %li exiting gracefully", (long)helper_pid);
    }
    else {
        if(die_on_helper_failure)
            log_fatal(fail_msg);
        log_err(fail_msg);
    }

    close(helper_read_fd);
    ev_io_stop(loop, helper_read_watcher);
    for(unsigned i = 0; i < num_mons; i++)
        ev_timer_stop(loop, mons[i].local_timeout);
    helper_is_dead_flag = true;
}

// common code to bump the local_timeout timer for (interval+timeout)*2,
//   starting it if not already running.
static void bump_local_timeout(struct ev_loop* loop, mon_t* mon) {
    mon->local_timeout->repeat = ((mon->svc->timeout + mon->svc->interval) << 1);
    ev_timer_again(loop, mon->local_timeout);
}

static void helper_read_cb(struct ev_loop* loop, ev_io* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_READ);
    dmn_assert(w->fd == helper_read_fd);

    while(1) { // loop on all immediately-available results
        uint32_t data;
        int rv = read(helper_read_fd, &data, 4);
        if(rv != 4) {
            if(rv < 0) {
                if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                    return;
                else
                    log_err("plugin_extmon: pipe read() failed: %s", dmn_logf_strerror(errno));
            }
            else if(rv != 0) {
                log_err("plugin_extmon: BUG: short pipe read for mon results");
            }
            else {
                log_err("plugin_extmon: helper pipe closed, no more results");
            }
            helper_is_dead(loop, false);
            return;
        }

        if(emc_decode_is_exit(data)) {
            helper_is_dead(loop, true);
            return;
        }

        const unsigned idx = emc_decode_mon_idx(data);
        const bool failed = emc_decode_mon_failed(data);
        if(idx >= num_mons)
            log_fatal("plugin_extmon: BUG: got helper result for out of range index %u", idx);
        mon_t* this_mon = &mons[idx];
        if(this_mon->svc->direct) {
            gdnsd_sttl_t new_sttl = GDNSD_STTL_TTL_MAX;
            if(failed)
                 new_sttl |= GDNSD_STTL_DOWN;
            gdnsd_mon_sttl_updater(this_mon->idx, new_sttl);
        }
        else {
            gdnsd_mon_state_updater(this_mon->idx, !failed); // wants true for success
        }

        if(init_phase) {
            ev_timer_stop(loop, this_mon->local_timeout);
            if(!this_mon->seen_once) {
                this_mon->seen_once = true;
                if(++init_phase_count == num_mons) {
                    ev_io_stop(loop, w);
                    return;
                }
            }
        }
        else {
            bump_local_timeout(loop, this_mon);
        }
    }
}

// This fires if it's been way too long since helper
//   updated us about a given monitored resource
static void local_timeout_cb(struct ev_loop* loop, ev_timer* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w);
    dmn_assert(revents == EV_TIMER);

    mon_t* this_mon = w->data;
    dmn_assert(this_mon->local_timeout == w);

    log_info("plugin_extmon: '%s': helper is very late for a status update, locally applying a negative update...", this_mon->desc);
    gdnsd_mon_state_updater(this_mon->idx, false);
    if(!init_phase) {
        bump_local_timeout(loop, this_mon);
    }
    else {
        ev_timer_stop(loop, w);
        dmn_assert(!this_mon->seen_once);
        this_mon->seen_once = true;
        if(++init_phase_count == num_mons)
            ev_io_stop(loop, helper_read_watcher);
    }
}

static char* num_to_str(const int i) {
    char* out = xmalloc(64);
    snprintf(out, 64, "%i", i);
    return out;
}

static char* thing_xlate(const char* instr, const char* thing, const unsigned thing_len) {
    char outbuf[1024]; // way more than enough, I'd hope...
    char* out_cur = outbuf;
    while(*instr) {
        if(!strncmp(instr, "%%ITEM%%", 8)) {
            memcpy(out_cur, thing, thing_len);
            out_cur += thing_len;
            instr += 8;
        }
        else {
            *out_cur++ = *instr++;
        }
    }
    *out_cur = '\0';
    return strdup(outbuf);
}

static void send_cmd(const unsigned idx, const mon_t* mon) {
    char** this_args = xmalloc(mon->svc->num_args * sizeof(char*));

    const unsigned thing_len = strlen(mon->thing);

    for(unsigned i = 0; i < mon->svc->num_args; i++)
        this_args[i] = thing_xlate(mon->svc->args[i], mon->thing, thing_len);

    extmon_cmd_t this_cmd = {
        .idx = idx,
        .timeout = mon->svc->timeout,
        .interval = mon->svc->interval,
        .num_args = mon->svc->num_args,
        .args = (const char**)this_args,
        .desc = mon->desc,
    };

    if(emc_write_command(helper_write_fd, &this_cmd)
        || emc_read_exact(helper_read_fd, "CMD_ACK"))
        log_fatal("plugin_extmon: failed to write command for '%s' to helper!", mon->desc);

    for(unsigned i = 0; i < mon->svc->num_args; i++)
        free(this_args[i]);
    free(this_args);
}

static void spawn_helper(void) {
    int writepipe[2];
    int readpipe[2];
    if(pipe(writepipe))
        log_fatal("plugin_extmon: pipe() failed: %s", dmn_logf_strerror(errno));
    if(pipe(readpipe))
        log_fatal("plugin_extmon: pipe() failed: %s", dmn_logf_strerror(errno));

    // Before forking, block all signals and save the old mask
    //   to avoid a race condition where local sighandlers execute
    //   in the child between fork and exec().
    sigset_t all_sigs;
    sigfillset(&all_sigs);
    sigset_t saved_mask;
    sigemptyset(&saved_mask);
    if(pthread_sigmask(SIG_SETMASK, &all_sigs, &saved_mask))
        log_fatal("pthread_sigmask() failed");

    helper_pid = fork();
    if(helper_pid == -1)
        log_fatal("plugin_extmon: fork() failed: %s", dmn_logf_strerror(errno));

    if(!helper_pid) { // child
        // reset all signal handlers to default before unblocking
        struct sigaction defaultme;
        sigemptyset(&defaultme.sa_mask);
        defaultme.sa_handler = SIG_DFL;
        defaultme.sa_flags = 0;

        // we really don't care about error retvals here
        for(unsigned i = 0; i < NSIG; i++)
            (void)sigaction(i, &defaultme, NULL);

        // unblock all
        sigset_t no_sigs;
        sigemptyset(&no_sigs);
        if(pthread_sigmask(SIG_SETMASK, &no_sigs, NULL))
            log_fatal("pthread_sigmask() failed");

        close(writepipe[1]);
        close(readpipe[0]);
        const char* child_read_fdstr = num_to_str(writepipe[0]);
        const char* child_write_fdstr = num_to_str(readpipe[1]);
        execl(helper_path, helper_path, dmn_get_debug() ? "Y" : "N", dmn_get_syslog_alive() ? "S" : "X",
            child_read_fdstr, child_write_fdstr, (const char*)NULL);
        log_fatal("plugin_extmon: execl(%s) failed: %s", helper_path, dmn_logf_strerror(errno));
    }

    // restore previous signal mask from before fork in parent
    if(pthread_sigmask(SIG_SETMASK, &saved_mask, NULL))
        log_fatal("pthread_sigmask() failed");

    // parent;
    dmn_assert(helper_pid);
    gdnsd_register_child_pid(helper_pid);

    close(writepipe[0]);
    close(readpipe[1]);
    helper_write_fd = writepipe[1];
    helper_read_fd = readpipe[0];

    if(emc_write_string(helper_write_fd, "HELO", 4))
        log_fatal("plugin_extmon: failed to write HELO to helper process, helper died immediately?");
    if(emc_read_exact(helper_read_fd, "HELO_ACK"))
        log_fatal("plugin_extmon: failed to read HELO_ACK from helper process, helper died immediately?");

    char cmds_buf[7];
    memcpy(cmds_buf, "CMDS:", 5);
    cmds_buf[5] = num_mons >> 8;
    cmds_buf[6] = num_mons & 0xFF;
    if(emc_write_string(helper_write_fd, cmds_buf, 7))
        log_fatal("plugin_extmon: failed to write command count to helper process");
    if(emc_read_exact(helper_read_fd, "CMDS_ACK"))
        log_fatal("plugin_extmon: failed to read CMDS_ACK from helper process");

    for(unsigned i = 0; i < num_mons; i++)
         send_cmd(i, &mons[i]);

    if(emc_write_string(helper_write_fd, "END_CMDS", 8))
        log_fatal("plugin_extmon: failed to write END_CMDS to helper process");
    if(emc_read_exact(helper_read_fd, "END_CMDS_ACK"))
        log_fatal("plugin_extmon: failed to read END_CMDS_ACK from helper process");

    // done sending stuff, close writepipe and go nonblock on read side for eventloop
    close(helper_write_fd);
    if(unlikely(fcntl(helper_read_fd, F_SETFL, (fcntl(helper_read_fd, F_GETFL, 0)) | O_NONBLOCK) == -1))
        log_fatal("plugin_extmon: Failed to set O_NONBLOCK on pipe: %s", dmn_logf_errno());
}

static bool bad_opt(const char* key, unsigned klen V_UNUSED, vscf_data_t* d V_UNUSED, void* data V_UNUSED) {
    log_fatal("plugin_extmon: bad global option '%s'", key);
}

void plugin_extmon_load_config(vscf_data_t* config, const unsigned num_threads V_UNUSED) {
    if(config) {
        vscf_data_t* helper_path_cfg = vscf_hash_get_data_byconstkey(config, "helper_path", true);
        if(helper_path_cfg) {
            if(!vscf_is_simple(helper_path_cfg))
                log_fatal("plugin_extmon: config option 'helper_path' must be a simple string");
            helper_path = gdnsd_resolve_path_libexec(vscf_simple_get_data(helper_path_cfg), NULL);
        }
        vscf_data_t* fail_cfg = vscf_hash_get_data_byconstkey(config, "helper_failure_action", true);
        if(fail_cfg) {
            if(!vscf_is_simple(fail_cfg))
                log_fatal("plugin_extmon: config option 'helper_failure_action' must be a simple string");
            const char* fail_str = vscf_simple_get_data(fail_cfg);
            if(!strcmp(fail_str, "stasis"))
                die_on_helper_failure = false;
            else if(!strcmp(fail_str, "kill_daemon"))
                die_on_helper_failure = true;
            else
                log_fatal("plugin_extmon: config option 'helper_failure_action' must be one of 'stasis' or 'kill_daemon' (you provided '%s')", fail_str);
        }
        vscf_hash_iterate(config, true, bad_opt, NULL);
    }

    // need to at least resolve this to a default, even in the absence of config
    if(!helper_path)
        helper_path = gdnsd_resolve_path_libexec("gdnsd_extmon_helper", NULL);
}

void plugin_extmon_add_svctype(const char* name, vscf_data_t* svc_cfg, const unsigned interval, const unsigned timeout) {
    dmn_assert(name); dmn_assert(svc_cfg);

    svcs = xrealloc(svcs, (num_svcs + 1) * sizeof(svc_t));
    svc_t* this_svc = &svcs[num_svcs++];
    this_svc->name = strdup(name);
    this_svc->timeout = timeout;
    this_svc->interval = interval;

    vscf_data_t* args_cfg = vscf_hash_get_data_byconstkey(svc_cfg, "cmd", true);
    if(!args_cfg)
        log_fatal("plugin_extmon: service_type '%s': option 'cmd' must be defined!", name);
    this_svc->num_args = vscf_array_get_len(args_cfg);
    if(this_svc->num_args < 1)
        log_fatal("plugin_extmon: service_type '%s': option 'cmd' cannot be an empty array", name);
    this_svc->args = xmalloc(this_svc->num_args * sizeof(const char*));
    for(unsigned i = 0; i < this_svc->num_args; i++) {
        vscf_data_t* arg_cfg = vscf_array_get_data(args_cfg, i);
        if(!vscf_is_simple(arg_cfg))
            log_fatal("plugin_extmon: service_type '%s': option 'cmd': all elements must be simple strings", name);
        this_svc->args[i] = strdup(vscf_simple_get_data(arg_cfg));
    }

    this_svc->direct = false;
    vscf_data_t* direct_cfg = vscf_hash_get_data_byconstkey(svc_cfg, "direct", true);
    if(direct_cfg && !vscf_simple_get_as_bool(direct_cfg, &this_svc->direct))
        log_fatal("plugin_extmon: service type '%s': option 'direct' must have the value 'true' or 'false'", name);
}

static void add_mon_any(const char* desc, const char* svc_name, const char* thing, const unsigned idx) {
    dmn_assert(desc); dmn_assert(svc_name); dmn_assert(thing);

    mons = xrealloc(mons, (num_mons + 1) * sizeof(mon_t));
    mon_t* this_mon = &mons[num_mons++];
    this_mon->desc = strdup(desc);
    this_mon->idx = idx;

    this_mon->svc = NULL;
    for(unsigned i = 0; i < num_svcs; i++) {
        if(!strcmp(svcs[i].name, svc_name)) {
            this_mon->svc = &svcs[i];
            break;
        }
    }
    dmn_assert(this_mon->svc);

    this_mon->thing = strdup(thing);
    this_mon->local_timeout = NULL;
    this_mon->seen_once = false;
}

void plugin_extmon_add_mon_addr(const char* desc, const char* svc_name, const char* cname, const dmn_anysin_t* addr V_UNUSED, const unsigned idx) {
    dmn_assert(desc); dmn_assert(svc_name); dmn_assert(cname); dmn_assert(addr);
    add_mon_any(desc, svc_name, cname, idx);
}

void plugin_extmon_add_mon_cname(const char* desc, const char* svc_name, const char* cname, const unsigned idx) {
    dmn_assert(desc); dmn_assert(svc_name); dmn_assert(cname);
    add_mon_any(desc, svc_name, cname, idx);
}

void plugin_extmon_init_monitors(struct ev_loop* mon_loop) {
    dmn_assert(helper_path);
    if(num_mons) {
        spawn_helper();
        helper_read_watcher = xmalloc(sizeof(ev_io));
        ev_io_init(helper_read_watcher, helper_read_cb, helper_read_fd, EV_READ);
        ev_set_priority(helper_read_watcher, 2);
        ev_io_start(mon_loop, helper_read_watcher);
        for(unsigned i = 0; i < num_mons; i++) {
            mon_t* this_mon = &mons[i];
            this_mon->local_timeout = xmalloc(sizeof(ev_timer));
            ev_timer_init(this_mon->local_timeout, local_timeout_cb, 0., 0.);
            this_mon->local_timeout->data = this_mon;
            ev_set_priority(this_mon->local_timeout, 0);
            bump_local_timeout(mon_loop, this_mon);
        }
    }
}

void plugin_extmon_start_monitors(struct ev_loop* mon_loop) {
    if(num_mons && !helper_is_dead_flag) {
        init_phase = false;
        ev_io_start(mon_loop, helper_read_watcher);
        for(unsigned i = 0; i < num_mons; i++)
            bump_local_timeout(mon_loop, &mons[i]);
    }
}
