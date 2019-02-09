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

#include <ev.h>

typedef struct {
    const char* name;
    unsigned* ok_codes;
    char* req_data;
    unsigned req_data_len;
    unsigned num_ok_codes;
    unsigned port;
    unsigned timeout;
    unsigned interval;
} http_svc_t;

typedef enum {
    HTTP_STATE_WAITING = 0,   // waiting for interval to expire before next send
    HTTP_STATE_WRITING,   // trying to send the request
    HTTP_STATE_READING  // trying to receive the response
} http_state_t;

typedef struct {
    const char* desc;
    http_svc_t* http_svc;
    ev_io read_watcher;
    ev_io write_watcher;
    ev_timer timeout_watcher;
    ev_timer interval_watcher;
    unsigned idx;
    gdnsd_anysin_t addr;
    char res_buf[14];
    int sock;
    http_state_t hstate;
    unsigned done;
    bool already_connected;
} http_events_t;

static unsigned num_http_svcs = 0;
static unsigned num_mons = 0;
static http_svc_t* service_types = NULL;
static http_events_t** mons = NULL;

F_NONNULL
static void mon_quick_fail(http_events_t* md)
{
    log_debug("plugin_http_status: State poll of %s failed very quickly", md->desc);
    md->hstate = HTTP_STATE_WAITING;
    gdnsd_mon_state_updater(md->idx, false);
}

F_NONNULL
static void mon_interval_cb(struct ev_loop* loop, struct ev_timer* t, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_TIMER);

    http_events_t* md = t->data;

    gdnsd_assert(md);

    if (md->hstate != HTTP_STATE_WAITING) {
        log_warn("plugin_http_status: A monitoring request attempt seems to have "
                 "lasted longer than the monitoring interval. "
                 "Skipping this round of monitoring - are you "
                 "starved for CPU time?");
        return;
    }

    ev_io* w_watcher = &md->write_watcher;
    ev_timer* t_watcher = &md->timeout_watcher;

    gdnsd_assert(md->sock == -1);
    gdnsd_assert(!ev_is_active(w_watcher));
    gdnsd_assert(!ev_is_active(t_watcher) && !ev_is_pending(t_watcher));

    log_debug("plugin_http_status: Starting state poll of %s", md->desc);

    const bool isv6 = md->addr.sa.sa_family == AF_INET6;

    const int sock = socket(isv6 ? PF_INET6 : PF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
    if (sock < 0) {
        log_err("plugin_http_status: Failed to create monitoring socket: %s", logf_errno());
        mon_quick_fail(md);
        return;
    }

    md->already_connected = true;
    if (likely(connect(sock, &md->addr.sa, md->addr.len) == -1)) {
        if (likely(errno == EINPROGRESS)) {
            md->already_connected = false;
        } else {
            switch (errno) {
            case EPIPE:
            case ECONNREFUSED:
            case ETIMEDOUT:
            case EHOSTUNREACH:
            case EHOSTDOWN:
            case ENETUNREACH:
                break;
            default:
                log_err("plugin_http_status: Failed to connect() monitoring socket to remote server, possible local problem: %s", logf_errno());
            }

            close(sock);
            mon_quick_fail(md);
            return;
        }
    }

    md->sock = sock;
    md->hstate = HTTP_STATE_WRITING;
    md->done = 0;
    ev_io_set(w_watcher, sock, EV_WRITE);
    ev_io_start(loop, w_watcher);
    ev_timer_set(t_watcher, md->http_svc->timeout, 0);
    ev_timer_start(loop, t_watcher);
}

F_NONNULL
static void mon_write_cb(struct ev_loop* loop, struct ev_io* io, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_WRITE);

    http_events_t* md = io->data;

    ev_io* r_watcher = &md->read_watcher;
    ev_io* w_watcher = &md->write_watcher;
    ev_timer* t_watcher = &md->timeout_watcher;

    gdnsd_assert(md);
    gdnsd_assert(md->hstate == HTTP_STATE_WRITING);
    gdnsd_assert(!ev_is_active(r_watcher));
    gdnsd_assert(ev_is_active(w_watcher));
    gdnsd_assert(ev_is_active(t_watcher) || ev_is_pending(t_watcher));
    gdnsd_assert(md->sock > -1);

    int sock = md->sock;
    if (likely(!md->already_connected)) {
        // nonblocking connect() just finished, need to check status
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
                break;
            default:
                log_err("plugin_http_status: Failed to connect() monitoring socket to remote server, possible local problem: %s", logf_strerror(so_error));
            }

            log_debug("plugin_http_status: State poll of %s failed quickly: %s", md->desc, logf_strerror(so_error));
            close(sock);
            md->sock = -1;
            ev_io_stop(loop, w_watcher);
            ev_timer_stop(loop, t_watcher);
            md->hstate = HTTP_STATE_WAITING;
            gdnsd_mon_state_updater(md->idx, false);
            return;
        }
        md->already_connected = true;
    }

    gdnsd_assert(md->done < md->http_svc->req_data_len);
    const unsigned to_send = md->http_svc->req_data_len - md->done;
    gdnsd_assert(to_send > 0);

    const ssize_t send_rv = send(sock, md->http_svc->req_data + md->done, to_send, 0);
    if (unlikely(send_rv < 0)) {
        switch (errno) {
        case EAGAIN:
#if EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
        case EINTR:
            return;
        case ENOTCONN:
        case ECONNRESET:
        case ETIMEDOUT:
        case EHOSTUNREACH:
        case ENETUNREACH:
        case EPIPE:
            break;
        default:
            log_err("plugin_http_status: send() to monitoring socket failed, possible local problem: %s", logf_errno());
        }
        shutdown(sock, SHUT_RDWR);
        close(sock);
        md->sock = -1;
        ev_io_stop(loop, w_watcher);
        ev_timer_stop(loop, t_watcher);
        md->hstate = HTTP_STATE_WAITING;
        gdnsd_mon_state_updater(md->idx, false);
        return;
    }

    const size_t sent = (size_t)send_rv;
    gdnsd_assert(sent <= to_send);

    if (unlikely(sent != to_send)) {
        md->done += sent;
        return;
    }

    md->done = 0;
    md->hstate = HTTP_STATE_READING;
    ev_io_stop(loop, w_watcher);
    ev_io_set(r_watcher, sock, EV_READ);
    ev_io_start(loop, r_watcher);
}

F_NONNULL
static void mon_read_cb(struct ev_loop* loop, struct ev_io* io, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_READ);

    http_events_t* md = io->data;

    ev_io* r_watcher = &md->read_watcher;
    ev_timer* t_watcher = &md->timeout_watcher;

    gdnsd_assert(md);
    gdnsd_assert(md->hstate == HTTP_STATE_READING);
    gdnsd_assert(ev_is_active(r_watcher));
    gdnsd_assert(md->sock > -1);

    bool final_status = false;
    const unsigned to_recv = 13U - md->done;
    const ssize_t recv_rv = recv(md->sock, md->res_buf + md->done, to_recv, 0);
    if (unlikely(recv_rv < 0)) {
        switch (errno) {
        case EAGAIN:
#if EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
        case EINTR:
            return;
        case ETIMEDOUT:
        case ENOTCONN:
        case ECONNRESET:
        case EPIPE:
            break;
        default:
            log_err("plugin_http_status: read() from monitoring socket failed, possible local problem: %s", logf_errno());
        }
    } else {
        const size_t recvd = (size_t)recv_rv;
        if (recvd < to_recv) {
            md->done += recvd;
            return;
        }
        md->res_buf[13] = '\0';
        char code_str[4] = { 0 };
        if (1 == sscanf(md->res_buf, "HTTP/1.%*1[01]%*1[ ]%3c%*1[ ]", code_str)) {
            unsigned lcode = (unsigned)strtoul(code_str, NULL, 10);
            for (unsigned i = 0; i < md->http_svc->num_ok_codes; i++) {
                if (lcode == md->http_svc->ok_codes[i]) {
                    final_status = true;
                    break;
                }
            }
        }
    }

    // I don't believe we actually need to read the rest of the response before
    //   shutdown/close in order to avoid bad TCP behavior, but I could be wrong.

    log_debug("plugin_http_status: State poll of %s %s", md->desc, final_status ? "succeeded" : "failed");
    shutdown(md->sock, SHUT_RDWR);
    close(md->sock);
    md->sock = -1;
    ev_io_stop(loop, r_watcher);
    ev_timer_stop(loop, t_watcher);
    md->hstate = HTTP_STATE_WAITING;
    gdnsd_mon_state_updater(md->idx, final_status);
}

F_NONNULL
static void mon_timeout_cb(struct ev_loop* loop, struct ev_timer* t, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_TIMER);

    http_events_t* md = t->data;

    ev_io* r_watcher = &md->read_watcher;
    ev_io* w_watcher = &md->write_watcher;

    gdnsd_assert(md);
    gdnsd_assert(md->sock != -1);
    gdnsd_assert(
        (md->hstate == HTTP_STATE_READING && ev_is_active(r_watcher))
        || (md->hstate == HTTP_STATE_WRITING && ev_is_active(w_watcher))
    );

    log_debug("plugin_http_status: State poll of %s timed out", md->desc);
    if (md->hstate == HTTP_STATE_READING)
        ev_io_stop(loop, r_watcher);
    else if (md->hstate == HTTP_STATE_WRITING)
        ev_io_stop(loop, w_watcher);
    shutdown(md->sock, SHUT_RDWR);
    close(md->sock);
    md->sock = -1;
    md->hstate = HTTP_STATE_WAITING;
    gdnsd_mon_state_updater(md->idx, false);
}

#define SVC_OPT_STR(_hash, _typnam, _loc) \
    do { \
        vscf_data_t* _data = vscf_hash_get_data_byconstkey(_hash, #_loc, true); \
        if (_data) { \
            if (!vscf_is_simple(_data)) \
                log_fatal("plugin_http_status: Service type '%s': option %s: Wrong type (should be string)", _typnam, #_loc); \
            _loc = vscf_simple_get_data(_data); \
        } \
    } while (0)

#define SVC_OPT_UINT(_hash, _typnam, _loc, _min, _max) \
    do { \
        vscf_data_t* _data = vscf_hash_get_data_byconstkey(_hash, #_loc, true); \
        if (_data) { \
            unsigned long _val; \
            if (!vscf_is_simple(_data) \
            || !vscf_simple_get_as_ulong(_data, &_val)) \
                log_fatal("plugin_http_status: Service type '%s': option '%s': Value must be a positive integer", _typnam, #_loc); \
            if (_val < _min || _val > _max) \
                log_fatal("plugin_http_status: Service type '%s': option '%s': Value out of range (%lu, %lu)", _typnam, #_loc, _min, _max); \
            _loc = (unsigned) _val; \
        } \
    } while (0)

// _LEN sizes below are without trailing NUL, and without
//   and printf templates (%s) either.

static const char REQ_TMPL[] = "GET %s HTTP/1.0\r\nUser-Agent: gdnsd-monitor\r\n\r\n";
static const char REQ_TMPL_VHOST[] = "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: gdnsd-monitor\r\n\r\n";
#define REQ_TMPL_LEN (sizeof(REQ_TMPL) - 2U - 1U)
#define REQ_TMPL_VHOST_LEN (sizeof(REQ_TMPL_VHOST) - 2U - 2U - 1U)

F_NONNULLX(1, 2)
static void make_req_data(http_svc_t* s, const char* url_path, const char* vhost)
{
    const unsigned url_len = strlen(url_path);
    if (vhost) {
        s->req_data_len = REQ_TMPL_VHOST_LEN + url_len + strlen(vhost);
        s->req_data = xmalloc(s->req_data_len + 1);
        snprintf(s->req_data, s->req_data_len + 1, REQ_TMPL_VHOST, url_path, vhost);
    } else {
        s->req_data_len = REQ_TMPL_LEN + url_len;
        s->req_data = xmalloc(s->req_data_len + 1);
        snprintf(s->req_data, s->req_data_len + 1, REQ_TMPL, url_path);
    }
}

static void plugin_http_status_add_svctype(const char* name, vscf_data_t* svc_cfg, const unsigned interval, const unsigned timeout)
{
    // defaults
    const char* url_path = "/";
    const char* vhost = NULL;
    unsigned port = 80;

    service_types = xrealloc_n(service_types, num_http_svcs + 1, sizeof(*service_types));
    http_svc_t* this_svc = &service_types[num_http_svcs++];

    this_svc->name = xstrdup(name);
    this_svc->num_ok_codes = 0;
    this_svc->ok_codes = NULL;
    bool ok_codes_set = false;

    SVC_OPT_STR(svc_cfg, name, url_path);
    SVC_OPT_STR(svc_cfg, name, vhost);
    SVC_OPT_UINT(svc_cfg, name, port, 1LU, 65534LU);
    vscf_data_t* ok_codes_cfg = vscf_hash_get_data_byconstkey(svc_cfg, "ok_codes", true);
    if (ok_codes_cfg) {
        ok_codes_set = true;
        this_svc->num_ok_codes = vscf_array_get_len(ok_codes_cfg);
        if (!this_svc->num_ok_codes)
            log_fatal("plugin_http_status: service type '%s': ok_codes array cannot be empty", this_svc->name);
        this_svc->ok_codes = xmalloc_n(this_svc->num_ok_codes, sizeof(*this_svc->ok_codes));
        for (unsigned i = 0; i < this_svc->num_ok_codes; i++) {
            vscf_data_t* code_cfg = vscf_array_get_data(ok_codes_cfg, i);
            unsigned long tmpcode;
            if (!vscf_simple_get_as_ulong(code_cfg, &tmpcode))
                log_fatal("plugin_http_status: service type '%s': illegal ok_codes value '%s', must be numeric http status code (100-999)", this_svc->name, vscf_simple_get_data(code_cfg));
            if (tmpcode < 100LU || tmpcode > 999LU)
                log_fatal("plugin_http_status: service type '%s': illegal ok_codes value '%lu', must be numeric http status code (100-999)", this_svc->name, tmpcode);
            this_svc->ok_codes[i] = (unsigned)tmpcode;
        }
    }

    // default the ok_codes array to [ 200 ]
    if (!ok_codes_set) {
        this_svc->num_ok_codes = 1;
        this_svc->ok_codes = xmalloc(sizeof(*this_svc->ok_codes));
        this_svc->ok_codes[0] = 200LU;
    }

    make_req_data(this_svc, url_path, vhost);
    this_svc->port = port;
    this_svc->timeout = timeout;
    this_svc->interval = interval;
}

static void plugin_http_status_add_mon_addr(const char* desc, const char* svc_name, const char* cname V_UNUSED, const gdnsd_anysin_t* addr, const unsigned idx)
{
    http_events_t* this_mon = xcalloc(sizeof(*this_mon));
    this_mon->desc = xstrdup(desc);
    this_mon->idx = idx;

    for (unsigned i = 0; i < num_http_svcs; i++) {
        if (!strcmp(service_types[i].name, svc_name)) {
            this_mon->http_svc = &service_types[i];
            break;
        }
    }

    gdnsd_assert(this_mon->http_svc);

    memcpy(&this_mon->addr, addr, sizeof(this_mon->addr));
    if (this_mon->addr.sa.sa_family == AF_INET) {
        this_mon->addr.sin4.sin_port = htons(this_mon->http_svc->port);
    } else {
        gdnsd_assert(this_mon->addr.sa.sa_family == AF_INET6);
        this_mon->addr.sin6.sin6_port = htons(this_mon->http_svc->port);
    }

    this_mon->hstate = HTTP_STATE_WAITING;
    this_mon->sock = -1;

    ev_io* r_watcher = &this_mon->read_watcher;
    ev_io_init(r_watcher, mon_read_cb, -1, 0);
    r_watcher->data = this_mon;

    ev_io* w_watcher = &this_mon->write_watcher;
    ev_io_init(w_watcher, mon_write_cb, -1, 0);
    w_watcher->data = this_mon;

    ev_timer* t_watcher = &this_mon->timeout_watcher;
    ev_timer_init(t_watcher, mon_timeout_cb, 0, 0);
    t_watcher->data = this_mon;

    ev_timer* i_watcher = &this_mon->interval_watcher;
    ev_timer_init(i_watcher, mon_interval_cb, 0, 0);
    i_watcher->data = this_mon;

    mons = xrealloc_n(mons, num_mons + 1, sizeof(*mons));
    mons[num_mons++] = this_mon;
}

static void plugin_http_status_init_monitors(struct ev_loop* mon_loop)
{
    for (unsigned i = 0; i < num_mons; i++) {
        ev_timer* ival_watcher = &mons[i]->interval_watcher;
        gdnsd_assert(mons[i]->sock == -1);
        ev_timer_set(ival_watcher, 0, 0);
        ev_timer_start(mon_loop, ival_watcher);
    }
}

static void plugin_http_status_start_monitors(struct ev_loop* mon_loop)
{
    for (unsigned i = 0; i < num_mons; i++) {
        http_events_t* mon = mons[i];
        gdnsd_assert(mon->sock == -1);
        const unsigned ival = mon->http_svc->interval;
        const double stagger = (((double)i) / ((double)num_mons)) * ((double)ival);
        ev_timer* ival_watcher = &mon->interval_watcher;
        ev_timer_set(ival_watcher, stagger, ival);
        ev_timer_start(mon_loop, ival_watcher);
    }
}

plugin_t plugin_http_status_funcs = {
    .name = "http_status",
    .config_loaded = false,
    .used = false,
    .load_config = NULL,
    .map_res = NULL,
    .pre_run = NULL,
    .iothread_init = NULL,
    .iothread_cleanup = NULL,
    .resolve = NULL,
    .add_svctype = plugin_http_status_add_svctype,
    .add_mon_addr = plugin_http_status_add_mon_addr,
    .add_mon_cname = NULL,
    .init_monitors = plugin_http_status_init_monitors,
    .start_monitors = plugin_http_status_start_monitors,
};
