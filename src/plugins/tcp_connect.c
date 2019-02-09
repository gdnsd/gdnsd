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

// This was basically copied from tcp_connect.c and stripped down
//   to just check connect() success or failure without doing
//   any actual socket i/o.

#include <config.h>

#include <gdnsd/compiler.h>
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/vscf.h>
#include "mon.h"
#include "plugapi.h"
#include "plugins.h"

#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>

typedef struct {
    const char* name;
    unsigned port;
    unsigned timeout;
    unsigned interval;
} tcp_svc_t;

typedef enum {
    TCP_STATE_WAITING = 0,
    TCP_STATE_CONNECTING
} tcp_state_t;

typedef struct {
    const char* desc;
    tcp_svc_t* tcp_svc;
    ev_io connect_watcher;
    ev_timer timeout_watcher;
    ev_timer interval_watcher;
    gdnsd_anysin_t addr;
    unsigned idx;
    tcp_state_t tcp_state;
    int sock;
} tcp_events_t;

static unsigned num_tcp_svcs = 0;
static unsigned num_mons = 0;
static tcp_svc_t* service_types = NULL;
static tcp_events_t** mons = NULL;

F_NONNULL
static void mon_interval_cb(struct ev_loop* loop, struct ev_timer* t, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_TIMER);

    tcp_events_t* md = t->data;

    gdnsd_assert(md);

    if (md->tcp_state != TCP_STATE_WAITING) {
        log_warn("plugin_tcp_connect: A monitoring request attempt seems to have "
                 "lasted longer than the monitoring interval. "
                 "Skipping this round of monitoring - are you "
                 "starved for CPU time?");
        return;
    }

    ev_io* c_watcher = &md->connect_watcher;
    ev_timer* t_watcher = &md->timeout_watcher;

    gdnsd_assert(md->sock == -1);
    gdnsd_assert(!ev_is_active(c_watcher));
    gdnsd_assert(!ev_is_active(t_watcher) && !ev_is_pending(t_watcher));

    log_debug("plugin_tcp_connect: Starting state poll of %s", md->desc);

    const bool isv6 = md->addr.sa.sa_family == AF_INET6;

    const int sock = socket(isv6 ? PF_INET6 : PF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
    if (sock == -1) {
        log_err("plugin_tcp_connect: Failed to create monitoring socket: %s", logf_errno());
        return;
    }

    bool success = false;
    if (likely(connect(sock, &md->addr.sa, md->addr.len) == -1)) {
        switch (errno) {
        case EINPROGRESS:
            // this is the normal case, where nonblock connect
            //   wants us to wait for writability...
            md->sock = sock;
            md->tcp_state = TCP_STATE_CONNECTING;
            ev_io_set(c_watcher, sock, EV_WRITE);
            ev_io_start(loop, c_watcher);
            ev_timer_set(t_watcher, md->tcp_svc->timeout, 0);
            ev_timer_start(loop, t_watcher);
            return; // don't do socket/status finishing actions below...
        case EPIPE:
        case ECONNREFUSED:
        case ETIMEDOUT:
        case EHOSTUNREACH:
        case EHOSTDOWN:
        case ENETUNREACH:
            // fast remote failures, e.g. when remote is local, I hope
            log_debug("plugin_tcp_connect: State poll of %s failed very quickly", md->desc);
            break;
        default:
            log_err("plugin_tcp_connect: Failed to connect() monitoring socket to remote server, possible local problem: %s", logf_errno());
        }
    } else {
        success = true;
    }

    close(sock);
    gdnsd_mon_state_updater(md->idx, success);
}

F_NONNULL
static void mon_connect_cb(struct ev_loop* loop, struct ev_io* w, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_WRITE);

    tcp_events_t* md = w->data;
    ev_timer* t_watcher = &md->timeout_watcher;

    gdnsd_assert(md);
    gdnsd_assert(md->tcp_state == TCP_STATE_CONNECTING);
    gdnsd_assert(ev_is_active(w));
    gdnsd_assert(ev_is_active(t_watcher) || ev_is_pending(t_watcher));
    gdnsd_assert(md->sock > -1);

    // nonblocking connect() just finished, need to check status
    bool success = false;
    int sock = md->sock;
    int so_error = 0;
    socklen_t so_error_len = sizeof(so_error);
    (void)getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len);
    if (unlikely(so_error)) {
        switch (so_error) {
        case EPIPE:
        case ECONNREFUSED:
        case ETIMEDOUT:
        case EHOSTUNREACH:
        case EHOSTDOWN:
        case ENETUNREACH:
            log_debug("plugin_tcp_connect: State poll of %s failed quickly: %s", md->desc, logf_strerror(so_error));
            break;
        default:
            log_err("plugin_tcp_connect: Failed to connect() monitoring socket to remote server, possible local problem: %s", logf_strerror(so_error));
        }
    } else {
        success = true;
    }

    shutdown(sock, SHUT_RDWR);
    close(sock);
    md->sock = -1;
    ev_io_stop(loop, w);
    ev_timer_stop(loop, t_watcher);
    md->tcp_state = TCP_STATE_WAITING;
    gdnsd_mon_state_updater(md->idx, success);
}

F_NONNULL
static void mon_timeout_cb(struct ev_loop* loop, struct ev_timer* t, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_TIMER);

    tcp_events_t* md = t->data;
    ev_io* c_watcher = &md->connect_watcher;

    gdnsd_assert(md);
    gdnsd_assert(md->sock > -1);
    gdnsd_assert(md->tcp_state == TCP_STATE_CONNECTING);
    gdnsd_assert(ev_is_active(c_watcher));

    log_debug("plugin_tcp_connect: State poll of %s timed out", md->desc);
    ev_io_stop(loop, c_watcher);
    shutdown(md->sock, SHUT_RDWR);
    close(md->sock);
    md->sock = -1;
    md->tcp_state = TCP_STATE_WAITING;
    gdnsd_mon_state_updater(md->idx, false);
}

#define SVC_OPT_UINT(_hash, _typnam, _loc, _min, _max) \
    do { \
        vscf_data_t* _data = vscf_hash_get_data_byconstkey(_hash, #_loc, true); \
        if (_data) { \
            unsigned long _val; \
            if (!vscf_is_simple(_data) \
            || !vscf_simple_get_as_ulong(_data, &_val)) \
                log_fatal("plugin_tcp_connect: Service type '%s': option '%s': Value must be a positive integer", _typnam, #_loc); \
            if (_val < _min || _val > _max) \
                log_fatal("plugin_tcp_connect: Service type '%s': option '%s': Value out of range (%lu, %lu)", _typnam, #_loc, _min, _max); \
            _loc = (unsigned) _val; \
        } \
    } while (0)

static void plugin_tcp_connect_add_svctype(const char* name, vscf_data_t* svc_cfg, const unsigned interval, const unsigned timeout)
{
    service_types = xrealloc_n(service_types, num_tcp_svcs + 1, sizeof(*service_types));
    tcp_svc_t* this_svc = &service_types[num_tcp_svcs++];

    this_svc->name = xstrdup(name);
    unsigned port = 0U;

    SVC_OPT_UINT(svc_cfg, name, port, 1LU, 65534LU);
    if (!port)
        log_fatal("plugin_tcp_connect: service type '%s' must have a 'port' parameter", name);

    this_svc->port = port;
    this_svc->timeout = timeout;
    this_svc->interval = interval;
}

static void plugin_tcp_connect_add_mon_addr(const char* desc, const char* svc_name, const char* cname V_UNUSED, const gdnsd_anysin_t* addr, const unsigned idx)
{
    tcp_events_t* this_mon = xcalloc(sizeof(*this_mon));
    this_mon->desc = xstrdup(desc);
    this_mon->idx = idx;

    for (unsigned i = 0; i < num_tcp_svcs; i++) {
        if (!strcmp(service_types[i].name, svc_name)) {
            this_mon->tcp_svc = &service_types[i];
            break;
        }
    }

    gdnsd_assert(this_mon->tcp_svc);

    memcpy(&this_mon->addr, addr, sizeof(this_mon->addr));
    if (this_mon->addr.sa.sa_family == AF_INET) {
        this_mon->addr.sin4.sin_port = htons(this_mon->tcp_svc->port);
    } else {
        gdnsd_assert(this_mon->addr.sa.sa_family == AF_INET6);
        this_mon->addr.sin6.sin6_port = htons(this_mon->tcp_svc->port);
    }

    this_mon->tcp_state = TCP_STATE_WAITING;
    this_mon->sock = -1;

    ev_io* c_watcher = &this_mon->connect_watcher;
    ev_io_init(c_watcher, mon_connect_cb, -1, 0);
    c_watcher->data = this_mon;

    ev_timer* t_watcher = &this_mon->timeout_watcher;
    ev_timer_init(t_watcher, mon_timeout_cb, 0, 0);
    t_watcher->data = this_mon;

    ev_timer* i_watcher = &this_mon->interval_watcher;
    ev_timer_init(i_watcher, mon_interval_cb, 0, 0);
    i_watcher->data = this_mon;

    mons = xrealloc_n(mons, num_mons + 1, sizeof(*mons));
    mons[num_mons++] = this_mon;
}

static void plugin_tcp_connect_init_monitors(struct ev_loop* mon_loop)
{
    for (unsigned i = 0; i < num_mons; i++) {
        ev_timer* ival_watcher = &mons[i]->interval_watcher;
        gdnsd_assert(mons[i]->sock == -1);
        ev_timer_set(ival_watcher, 0, 0);
        ev_timer_start(mon_loop, ival_watcher);
    }
}

static void plugin_tcp_connect_start_monitors(struct ev_loop* mon_loop)
{
    for (unsigned i = 0; i < num_mons; i++) {
        tcp_events_t* mon = mons[i];
        gdnsd_assert(mon->sock == -1);
        const unsigned ival = mon->tcp_svc->interval;
        const double stagger = (((double)i) / ((double)num_mons)) * ((double)ival);
        ev_timer* ival_watcher = &mon->interval_watcher;
        ev_timer_set(ival_watcher, stagger, ival);
        ev_timer_start(mon_loop, ival_watcher);
    }
}

plugin_t plugin_tcp_connect_funcs = {
    .name = "tcp_connect",
    .config_loaded = false,
    .used = false,
    .load_config = NULL,
    .map_res = NULL,
    .pre_run = NULL,
    .iothread_init = NULL,
    .iothread_cleanup = NULL,
    .resolve = NULL,
    .add_svctype = plugin_tcp_connect_add_svctype,
    .add_mon_addr = plugin_tcp_connect_add_mon_addr,
    .add_mon_cname = NULL,
    .init_monitors = plugin_tcp_connect_init_monitors,
    .start_monitors = plugin_tcp_connect_start_monitors,
};
