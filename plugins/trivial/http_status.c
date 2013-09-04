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

#define GDNSD_PLUGIN_NAME http_status

#include "config.h"
#include <gdnsd/plugin.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>

typedef struct {
    const char* name;
    unsigned long* ok_codes;
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
    http_svc_t* http_svc;
    ev_io* read_watcher;
    ev_io* write_watcher;
    ev_timer* timeout_watcher;
    ev_timer* interval_watcher;
    mon_smgr_t* smgr;
    anysin_t addr;
    char res_buf[14];
    int sock;
    http_state_t hstate;
    unsigned done;
    bool already_connected;
} http_events_t;

static unsigned num_http_svcs = 0;
static unsigned int num_mons = 0;
static http_svc_t* service_types = NULL;
static http_events_t** mons = NULL;

F_NONNULL
static void mon_interval_cb(struct ev_loop* loop, struct ev_timer* t, const int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(t);
    dmn_assert(revents == EV_TIMER);

    http_events_t* md = (http_events_t*)t->data;

    dmn_assert(md);

    if(unlikely(md->hstate != HTTP_STATE_WAITING)) {
        log_warn("plugin_http_status: A monitoring request attempt seems to have "
            "lasted longer than the monitoring interval. "
            "Skipping this round of monitoring - are you "
            "starved for CPU time?");
        return;
    }

    dmn_assert(md->sock == -1);
    dmn_assert(!ev_is_active(md->read_watcher));
    dmn_assert(!ev_is_active(md->write_watcher));
    dmn_assert(!ev_is_active(md->timeout_watcher));

    log_debug("plugin_http_status: Starting state poll of %s", md->smgr->desc);

    do {
        const bool isv6 = md->addr.sa.sa_family == AF_INET6;

        const int sock = socket(isv6 ? PF_INET6 : PF_INET, SOCK_STREAM, gdnsd_getproto_tcp());
        if(unlikely(sock < 0)) {
            log_err("plugin_http_status: Failed to create monitoring socket: %s", logf_errno());
            break;
        }

        if(unlikely(fcntl(sock, F_SETFL, (fcntl(sock, F_GETFL, 0)) | O_NONBLOCK) == -1)) {
            log_err("plugin_http_status: Failed to set O_NONBLOCK on monitoring socket: %s", logf_errno());
            close(sock);
            break;
        }

        md->already_connected = true;
        if(likely(connect(sock, &md->addr.sa, md->addr.len) == -1)) {
            if(likely(errno == EINPROGRESS)) { md->already_connected = false; }
            else {
                switch(errno) {
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
                break;
            }
        }

        md->sock = sock;
        md->hstate = HTTP_STATE_WRITING;
        md->done = 0;
        ev_io_set(md->write_watcher, sock, EV_WRITE);
        ev_io_start(loop, md->write_watcher);
        ev_timer_set(md->timeout_watcher, md->http_svc->timeout, 0);
        ev_timer_start(loop, md->timeout_watcher);
        return;
    } while(0);

    // This is only reachable via "break"'s above, which indicate an immediate failure
    log_debug("plugin_http_status: State poll of %s failed very quickly", md->smgr->desc);
    md->hstate = HTTP_STATE_WAITING;
    gdnsd_mon_state_updater(md->smgr, false);
}

F_NONNULL
static void mon_write_cb(struct ev_loop* loop, struct ev_io* io, const int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(io);
    dmn_assert(revents == EV_WRITE);

    http_events_t* md = (http_events_t*)io->data;

    dmn_assert(md);
    dmn_assert(md->hstate == HTTP_STATE_WRITING);
    dmn_assert(!ev_is_active(md->read_watcher));
    dmn_assert(ev_is_active(md->write_watcher));
    dmn_assert(ev_is_active(md->timeout_watcher));
    dmn_assert(md->sock > -1);

    int sock = md->sock;
    if(likely(!md->already_connected)) {
        // nonblocking connect() just finished, need to check status
        int so_error = 0;
        unsigned int so_error_len = sizeof(so_error);
        (void)getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len);
        if(unlikely(so_error)) {
            switch(so_error) {
                case EPIPE:
                case ECONNREFUSED:
                case ETIMEDOUT:
                case EHOSTUNREACH:
                case EHOSTDOWN:
                case ENETUNREACH:
                    break;
                default:
                    log_err("plugin_http_status: Failed to connect() monitoring socket to remote server, possible local problem: %s", logf_errnum(so_error));
            }

            log_debug("plugin_http_status: State poll of %s failed quickly: %s", md->smgr->desc, logf_errnum(so_error));
            close(sock); md->sock = -1;
            ev_io_stop(loop, md->write_watcher);
            ev_timer_stop(loop, md->timeout_watcher);
            md->hstate = HTTP_STATE_WAITING;
            gdnsd_mon_state_updater(md->smgr, false);
            return;
        }
        md->already_connected = true;
    }

    const unsigned to_send = md->http_svc->req_data_len - md->done;
    const int sent = send(sock, md->http_svc->req_data + md->done, md->http_svc->req_data_len, 0);
    if(unlikely(sent == -1)) {
        switch(errno) {
            case EAGAIN:
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
                log_err("plugin_http_status: write() to monitoring socket failed, possible local problem: %s", logf_errno());
        }
        shutdown(sock, SHUT_RDWR);
        close(sock);
        md->sock = -1;
        ev_io_stop(loop, md->write_watcher);
        ev_timer_stop(loop, md->timeout_watcher);
        md->hstate = HTTP_STATE_WAITING;
        gdnsd_mon_state_updater(md->smgr, false);
    }
    if(unlikely(sent != (signed)to_send)) {
        md->done += sent;
        return;
    }

    md->done = 0;
    md->hstate = HTTP_STATE_READING;
    ev_io_stop(loop, md->write_watcher);
    ev_io_set(md->read_watcher, sock, EV_READ);
    ev_io_start(loop, md->read_watcher);
}

F_NONNULL
static void mon_read_cb(struct ev_loop* loop, struct ev_io* io, const int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(io);
    dmn_assert(revents == EV_READ);

    http_events_t* md = (http_events_t*)io->data;

    dmn_assert(md);
    dmn_assert(md->hstate == HTTP_STATE_READING);
    dmn_assert(ev_is_active(md->read_watcher));
    dmn_assert(!ev_is_active(md->write_watcher));
    dmn_assert(md->sock > -1);

    bool final_status = false;
    const int to_recv = 13 - md->done;
    const int recvd = recv(md->sock, md->res_buf + md->done, to_recv, 0);
    if(unlikely(recvd == -1)) {
        switch(errno) {
            case EAGAIN:
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
    }
    else if(recvd < to_recv) {
        md->done += recvd;
        return;
    }
    else {
        md->res_buf[13] = '\0';
        char code_str[4] = { 0 };
        if(1 == sscanf(md->res_buf, "HTTP/1.%*1[01]%*1[ ]%3c%*1[ ]", code_str)) {
            unsigned long lcode = strtoul(code_str, NULL, 10);
            for(unsigned i = 0; i < md->http_svc->num_ok_codes; i++) {
                if(lcode == md->http_svc->ok_codes[i]) {
                    final_status = true;
                    break;
                }
            }
        }
    }

    // I don't believe we actually need to read the rest of the response before
    //   shutdown/close in order to avoid bad TCP behavior, but I could be wrong.

    log_debug("plugin_http_status: State poll of %s %s", md->smgr->desc, final_status ? "succeeded" : "failed");
    shutdown(md->sock, SHUT_RDWR);
    close(md->sock);
    md->sock = -1;
    ev_io_stop(loop, md->read_watcher);
    ev_timer_stop(loop, md->timeout_watcher);
    md->hstate = HTTP_STATE_WAITING;
    gdnsd_mon_state_updater(md->smgr, final_status);
}

F_NONNULL
static void mon_timeout_cb(struct ev_loop* loop, struct ev_timer* t, const int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(t);
    dmn_assert(revents == EV_TIMER);

    http_events_t* md = (http_events_t*)t->data;

    dmn_assert(md);
    dmn_assert(md->sock != -1);
    dmn_assert(
        (md->hstate == HTTP_STATE_READING && ev_is_active(md->read_watcher))
     || (md->hstate == HTTP_STATE_WRITING && ev_is_active(md->write_watcher))
    );

    log_debug("plugin_http_status: State poll of %s timed out", md->smgr->desc);
    if(md->hstate == HTTP_STATE_READING) ev_io_stop(loop, md->read_watcher);
    else if(md->hstate == HTTP_STATE_WRITING) ev_io_stop(loop, md->write_watcher);
    shutdown(md->sock, SHUT_RDWR);
    close(md->sock);
    md->sock = -1;
    md->hstate = HTTP_STATE_WAITING;
    gdnsd_mon_state_updater(md->smgr, false);
}

#define SVC_OPT_UINT(_hash, _typnam, _loc, _min, _max) \
    do { \
        const vscf_data_t* _data = vscf_hash_get_data_byconstkey(_hash, #_loc, true); \
        if(_data) { \
            unsigned long _val; \
            if(!vscf_is_simple(_data) \
            || !vscf_simple_get_as_ulong(_data, &_val)) \
                log_fatal("plugin_http_status: Service type '%s': option '%s': Value must be a positive integer", _typnam, #_loc); \
            if(_val < _min || _val > _max) \
                log_fatal("plugin_http_status: Service type '%s': option '%s': Value out of range (%lu, %lu)", _typnam, #_loc, _min, _max); \
            _loc = (unsigned) _val; \
        } \
    } while(0)

#define SVC_OPT_STR(_hash, _typnam, _loc) \
    do { \
        const vscf_data_t* _data = vscf_hash_get_data_byconstkey(_hash, #_loc, true); \
        if(_data) { \
            if(!vscf_is_simple(_data)) \
                log_fatal("plugin_http_status: Service type '%s': option %s: Wrong type (should be string)", _typnam, #_loc); \
            _loc = vscf_simple_get_data(_data); \
        } \
    } while(0)

F_NONNULLX(1, 2)
static void make_req_data(http_svc_t* s, const char* url_path, const char* vhost) {
    dmn_assert(s); dmn_assert(url_path);
    const unsigned url_len = strlen(url_path);
    if(vhost) {
        s->req_data_len = 25 + url_len + strlen(vhost);
        s->req_data = malloc(s->req_data_len + 1);
        snprintf(s->req_data, s->req_data_len + 1, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", url_path, vhost);
    }
    else {
        s->req_data_len = 17 + url_len;
        s->req_data = malloc(s->req_data_len + 1);
        snprintf(s->req_data, s->req_data_len + 1, "GET %s HTTP/1.0\r\n\r\n", url_path);
    }
}

void plugin_http_status_add_svctype(const char* name, const vscf_data_t* svc_cfg, const unsigned interval, const unsigned timeout) {
    dmn_assert(name);

    // defaults
    const char* url_path = "/";
    const char* vhost = NULL;
    unsigned port = 80;

    service_types = realloc(service_types, (num_http_svcs + 1) * sizeof(http_svc_t));
    http_svc_t* this_svc = &service_types[num_http_svcs++];

    this_svc->name = strdup(name);
    this_svc->num_ok_codes = 0;
    this_svc->ok_codes = NULL;
    bool ok_codes_set = false;

    if(svc_cfg) {
        SVC_OPT_STR(svc_cfg, name, url_path);
        SVC_OPT_STR(svc_cfg, name, vhost);
        SVC_OPT_UINT(svc_cfg, name, port, 1LU, 65534LU);
        const vscf_data_t* ok_codes_cfg = vscf_hash_get_data_byconstkey(svc_cfg, "ok_codes", true);
        if(ok_codes_cfg) {
            ok_codes_set = true;
            this_svc->num_ok_codes = vscf_array_get_len(ok_codes_cfg);
            this_svc->ok_codes = malloc(sizeof(unsigned long) * this_svc->num_ok_codes);
            for(unsigned i = 0; i < this_svc->num_ok_codes; i++) {
                const vscf_data_t* code_cfg = vscf_array_get_data(ok_codes_cfg, i);
                if(!vscf_simple_get_as_ulong(code_cfg, &this_svc->ok_codes[i]))
                    log_fatal("plugin_http_status: service type '%s': illegal ok_codes value '%s', must be numeric http status code (100-999)", this_svc->name, vscf_simple_get_data(code_cfg));
                if(this_svc->ok_codes[i] < 100LU || this_svc->ok_codes[i] > 999LU)
                    log_fatal("plugin_http_status: service type '%s': illegal ok_codes value '%lu', must be numeric http status code (100-999)", this_svc->name, this_svc->ok_codes[i]);
            }
        }
    }

    // no config at all, but not the empty array...
    if(!ok_codes_set) {
        this_svc->num_ok_codes = 1;
        this_svc->ok_codes = malloc(sizeof(unsigned long));
        this_svc->ok_codes[0] = 200LU;
    }

    make_req_data(this_svc, url_path, vhost);
    this_svc->port = port;
    this_svc->timeout = timeout;
    this_svc->interval = interval;
}

void plugin_http_status_add_monitor(const char* svc_name, mon_smgr_t* smgr) {
    dmn_assert(svc_name); dmn_assert(smgr);

    http_events_t* this_mon = calloc(1, sizeof(http_events_t));

    for(unsigned i = 0; i < num_http_svcs; i++) {
        if(!strcmp(service_types[i].name, svc_name)) {
            this_mon->http_svc = &service_types[i];
            break;
        }
    }

    dmn_assert(this_mon->http_svc);

    memcpy(&this_mon->addr, &smgr->addr, sizeof(anysin_t));
    if(this_mon->addr.sa.sa_family == AF_INET) {
        this_mon->addr.sin.sin_port = htons(this_mon->http_svc->port);
    }
    else {
        dmn_assert(this_mon->addr.sa.sa_family == AF_INET6);
        this_mon->addr.sin6.sin6_port = htons(this_mon->http_svc->port);
    }

    this_mon->smgr = smgr;
    this_mon->hstate = HTTP_STATE_WAITING;
    this_mon->sock = -1;

    this_mon->read_watcher = malloc(sizeof(ev_io));
    ev_io_init(this_mon->read_watcher, &mon_read_cb, -1, 0);
    this_mon->read_watcher->data = this_mon;

    this_mon->write_watcher = malloc(sizeof(ev_io));
    ev_io_init(this_mon->write_watcher, &mon_write_cb, -1, 0);
    this_mon->write_watcher->data = this_mon;

    this_mon->timeout_watcher = malloc(sizeof(ev_timer));
    ev_timer_init(this_mon->timeout_watcher, &mon_timeout_cb, 0, 0);
    this_mon->timeout_watcher->data = this_mon;

    this_mon->interval_watcher = malloc(sizeof(ev_timer));
    ev_timer_init(this_mon->interval_watcher, &mon_interval_cb, 0, 0);
    this_mon->interval_watcher->data = this_mon;

    mons = realloc(mons, sizeof(http_events_t*) * (num_mons + 1));
    mons[num_mons++] = this_mon;
}

void plugin_http_status_init_monitors(struct ev_loop* mon_loop) {
    dmn_assert(mon_loop);

    for(unsigned int i = 0; i < num_mons; i++) {
        ev_timer* ival_watcher = mons[i]->interval_watcher;
        dmn_assert(mons[i]->sock == -1);
        ev_timer_set(ival_watcher, 0, 0);
        ev_timer_start(mon_loop, ival_watcher);
    }
}

void plugin_http_status_start_monitors(struct ev_loop* mon_loop) {
    dmn_assert(mon_loop);

    for(unsigned int i = 0; i < num_mons; i++) {
        http_events_t* mon = mons[i];
        dmn_assert(mon->sock == -1);
        const unsigned ival = mon->http_svc->interval;
        const double stagger = (((double)i) / ((double)num_mons)) * ((double)ival);
        ev_timer* ival_watcher = mon->interval_watcher;
        ev_timer_set(ival_watcher, stagger, ival);
        ev_timer_start(mon_loop, ival_watcher);
    }
}
