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
#include "css.h"
#include "cs.h"
#include "main.h"
#include "statio.h"
#include "main.h"

#include <gdnsd/compiler.h>
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/paths.h>
#include <gdnsd/net.h>
#include <gdnsd-prot/mon.h>

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/file.h>

static const char base_sock[] = "control.sock";
static const char base_lock[] = "control.lock";

static const unsigned max_clients = 100U;

static const mode_t CSOCK_PERMS = (S_IRUSR|S_IWUSR); // 0600

typedef enum {
    READING_REQ,
    WAITING_SERVER,
    WRITING_RESP,
    WRITING_RESP_DATA
} css_cstate_t;

struct css_conn_s_;
typedef struct css_conn_s_ css_conn_t;

struct css_conn_s_ {
    css_conn_t* next; // linked-list for cleanup
    css_conn_t* prev;
    css_t* css;
    csbuf_t rbuf;
    csbuf_t wbuf;
    char* resp_data;
    ev_io* w_read;
    ev_io* w_write;
    int fd;
    size_t resp_size;
    size_t resp_size_done;
    css_cstate_t state;
};

typedef struct {
    css_conn_t** q;
    size_t len;
} conn_queue_t;

static void conn_queue_add(conn_queue_t* queue, css_conn_t* c) {
    queue->q = xrealloc(queue->q, ((queue->len + 1) * sizeof(*queue->q)));
    queue->q[queue->len++] = c;
}

static void conn_queue_clear(conn_queue_t* queue) {
    queue->len = 0;
    if(queue->q) {
        free(queue->q);
        queue->q = NULL;
    }
}

struct css_s_ {
    int fd;
    int lock_fd;
    unsigned num_clients;
    uint32_t status_v;
    uint32_t status_d;
    ev_io* w_accept;
    struct ev_loop* loop;
    char* path;
    css_conn_t* clients;
    conn_queue_t* reload_zones_queued;
    conn_queue_t* reload_zones_active;
};

static void swap_reload_zones_queues(css_t* css) {
    conn_queue_t* x = css->reload_zones_queued;
    css->reload_zones_queued = css->reload_zones_active;
    css->reload_zones_active = x;
}

F_NONNULL
static void css_conn_cleanup(css_conn_t* c) {
    css_t* css = c->css;
    gdnsd_assert(css);

    // stop/free io-related things
    if(c->resp_data)
        free(c->resp_data);
    ev_io_stop(css->loop, c->w_read);
    ev_io_stop(css->loop, c->w_write);
    free(c->w_read);
    free(c->w_write);
    if(c->fd >= 0)
        close(c->fd);

    // remove from linked list
    if(c == css->clients)
        css->clients = c->next;
    if(c->prev)
        c->prev->next = c->next;
    if(c->next)
        c->next->prev = c->prev;
    free(c);

    // if we were at the maximum, start accepting connections again
    if(css->num_clients-- == max_clients)
        ev_io_start(css->loop, css->w_accept);
}

F_NONNULL
static bool respond_blocking_ack(css_conn_t* c) {
    gdnsd_assert(c->css);
    gdnsd_assert(c->state == WAITING_SERVER);
    c->wbuf.key = RESP_ACK;
    csbuf_set_v(&c->wbuf, 0);
    c->wbuf.d = 0;
    c->state = WRITING_RESP;
    ssize_t pktlen = send(c->fd, c->wbuf.raw, 8, 0);
    if(pktlen != 8) {
        log_err("blocking control socket write of 8 bytes failed with retval %zi, closing: %s", pktlen, logf_errno());
        css_conn_cleanup(c);
        return true;
    }
    return false;
}

F_NONNULL
static void css_conn_write_data(css_conn_t* c) {
    gdnsd_assert(c->state == WRITING_RESP_DATA);
    gdnsd_assert(c->resp_data);
    gdnsd_assert(c->resp_size);
    size_t wanted = c->resp_size - c->resp_size_done;
    gdnsd_assert(wanted > 0);
    ssize_t pktlen = send(c->fd, &c->resp_data[c->resp_size_done], wanted, MSG_DONTWAIT);
    if(pktlen < 0) {
        if(ERRNO_WOULDBLOCK)
            return;
        log_err("control socket write of %zu bytes failed with retval %zi, closing: %s", wanted, pktlen, logf_errno());
        css_conn_cleanup(c);
        return;
    }

    c->resp_size_done += (size_t)pktlen;
    if(c->resp_size_done == c->resp_size) {
        free(c->resp_data);
        c->resp_data = NULL;
        c->resp_size = 0;
        c->resp_size_done = 0;
        ev_io_stop(c->css->loop, c->w_write);
        ev_io_start(c->css->loop, c->w_read);
        c->state = READING_REQ;
    }
}

F_NONNULL
static void css_conn_write(struct ev_loop* loop, ev_io* w, int revents V_UNUSED) {
    gdnsd_assert(revents == EV_WRITE);
    css_conn_t* c = w->data;
    css_t* css = c->css;
    gdnsd_assert(c); gdnsd_assert(css);
    gdnsd_assert(c->state == WRITING_RESP || c->state == WRITING_RESP_DATA);

    if(c->state == WRITING_RESP) {
        ssize_t pktlen = send(c->fd, c->wbuf.raw, 8, MSG_DONTWAIT);
        if(pktlen != 8) {
            if(pktlen < 0 && ERRNO_WOULDBLOCK)
                return;
            log_err("control socket write of 8 bytes failed with retval %zi, closing: %s", pktlen, logf_errno());
            css_conn_cleanup(c);
            return;
        }
        if(c->resp_data) {
            c->state = WRITING_RESP_DATA;
        } else {
            ev_io_stop(loop, c->w_write);
            ev_io_start(loop, c->w_read);
            c->state = READING_REQ;
            return;
        }
    }

    css_conn_write_data(c);
}

// If "resp_data" is set, it's a buffer of extended response data to send after
// the initial 8-byte response (and then free once sent), and "d" contains the
// length of the data.
F_NONNULLX(1)
static void respond(css_conn_t* c, const char key, const uint32_t v, const uint32_t d, char* resp_data) {
    gdnsd_assert(c->css);
    gdnsd_assert(c->state == WAITING_SERVER);
    gdnsd_assert(v <= 0xFFFFFF);
    c->wbuf.key = key;
    csbuf_set_v(&c->wbuf, v);
    c->wbuf.d = d;
    if(resp_data) {
        c->resp_data = resp_data;
        c->resp_size = d;
        c->resp_size_done = 0;
    }
    c->state = WRITING_RESP;
    ev_io_start(c->css->loop, c->w_write);
}

F_NONNULL
static void css_conn_read(struct ev_loop* loop, ev_io* w, int revents V_UNUSED) {
    gdnsd_assert(revents == EV_READ);
    css_conn_t* c = w->data;
    css_t* css = c->css;
    gdnsd_assert(c); gdnsd_assert(css);
    gdnsd_assert(c->state == READING_REQ);

    const ssize_t pktlen = recv(c->fd, c->rbuf.raw, 8, MSG_DONTWAIT);
    if(pktlen != 8) {
        if(pktlen < 0 && ERRNO_WOULDBLOCK)
            return;
        if(pktlen == 0)
            log_devdebug("control socket client disconnected cleanly during read");
        else
            log_err("control socket read of 8 bytes failed with retval %zi, closing: %s", pktlen, logf_errno());
        css_conn_cleanup(c);
        return;
    }

    ev_io_stop(loop, c->w_read);
    c->state = WAITING_SERVER;

    double nowish;
    size_t stats_size;
    size_t states_size;
    char* stats_msg;
    char* states_msg;

    switch(c->rbuf.key) {
        case REQ_INFO:
            respond(c, RESP_ACK, css->status_v, css->status_d, NULL);
            break;
        case REQ_STOP:
            log_info("Received stop request over control socket");
            ev_break(loop, EVBREAK_ALL);
            // Setting fd = -1 prevents further writes and prevents closing
            // during css_delete(), so that socket close can be used to witness
            // the daemon exiting just before the PID vanishes...
            if(!respond_blocking_ack(c))
                c->fd = -1;
            break;
        case REQ_STAT:
            nowish = ev_now(loop);
            stats_size = 0;
            stats_msg = statio_get_json((time_t)nowish, &stats_size);
            gdnsd_assert(stats_size <= UINT32_MAX);
            respond(c, RESP_ACK, 0, (uint32_t)stats_size, stats_msg);
            break;
        case REQ_STATE:
            states_size = 0;
            states_msg = gdnsd_mon_states_get_json(&states_size);
            gdnsd_assert(states_size <= UINT32_MAX);
            respond(c, RESP_ACK, 0, (uint32_t)states_size, states_msg);
            break;
        case REQ_ZREL:
            // always enqueue new clients to the "queued" queue.  no need to
            // check for duplicate clients, because clients are serial
            conn_queue_add(css->reload_zones_queued, c);
            // If there is no "active" queue, then there is no other zones
            // reload in progress, so swap the queues and start a reload
            if(!css->reload_zones_active->len) {
                swap_reload_zones_queues(css);
                spawn_async_zones_reloader_thread();
            }
            break;
        default:
            log_err("Invalid request from control socket, closing");
            css_conn_cleanup(c);
    }
}

F_NONNULL
static void css_accept(struct ev_loop* loop V_UNUSED, ev_io* w, int revents V_UNUSED) {
    gdnsd_assert(revents == EV_READ);
    css_t* css = w->data;
    gdnsd_assert(css);

    const int fd = accept4(w->fd, NULL, NULL, SOCK_NONBLOCK);

    if(unlikely(fd < 0)) {
        switch(errno) {
            case EAGAIN:
#if EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
            case EINTR:
                break;
            default:
                log_err("control socket early connection failure: %s", logf_errno());
                break;
        }
        return;
    }

    // if we now have max_clients connected, stop accepting new ones
    if(++css->num_clients == max_clients)
        ev_io_stop(css->loop, css->w_accept);

    // set up the per-connection state and start reading requests...
    css_conn_t* c = xcalloc(1, sizeof(*c));
    c->css = css;
    c->fd = fd;
    c->w_read = xmalloc(sizeof(*c->w_read));
    c->w_write = xmalloc(sizeof(*c->w_write));
    ev_io_init(c->w_read, css_conn_read, fd, EV_READ);
    ev_io_init(c->w_write, css_conn_write, fd, EV_WRITE);
    c->w_read->data = c;
    c->w_write->data = c;

    // set up buffer/watcher state to read input length
    c->state = READING_REQ;
    ev_io_start(css->loop, c->w_read);

    // insert into front of linked list
    if(css->clients) {
        c->next = css->clients;
        css->clients->prev = c;
    }
    css->clients = c;
}

/*********************
 * Public interfaces *
 *********************/

css_t* css_new(void) {
    char* lock_path = gdnsd_resolve_path_run(base_lock, NULL);

    const int lock_fd = open(lock_path, O_RDONLY | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if(lock_fd < 0)
        log_fatal("cannot open control sock lock at %s: %s", lock_path, logf_errno());

    if(flock(lock_fd, LOCK_EX | LOCK_NB)) {
        if(errno != EWOULDBLOCK)
            log_fatal("cannot lock control sock lock at %s: %s", lock_path, logf_errno());
        close(lock_fd);
        free(lock_path);
        return NULL;
    }

    free(lock_path);

    css_t* css = xcalloc(1, sizeof(*css));
    css->lock_fd = lock_fd;
    css->reload_zones_queued = xcalloc(1, sizeof(*css->reload_zones_queued));
    css->reload_zones_active = xcalloc(1, sizeof(*css->reload_zones_active));
    css->status_d = (uint32_t)getpid();
    uint8_t x, y, z;
    if(3 != sscanf(PACKAGE_VERSION, "%hhu.%hhu.%hhu", &x, &y, &z))
        log_fatal("BUG: Cannot parse our own package version");
    css->status_v = csbuf_make_v(x, y, z);

    css->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(css->fd < 0)
        log_fatal("socket(AF_UNIX, SOCK_STREAM, 0) failed: %s", logf_errno());

    css->w_accept = xmalloc(sizeof(*css->w_accept));
    ev_io_init(css->w_accept, css_accept, css->fd, EV_READ);
    css->w_accept->data = css;

    char* sock_path = gdnsd_resolve_path_run(base_sock, NULL);
    struct sockaddr_un addr;
    sun_set_path(&addr, sock_path);
    if(unlink(sock_path) && errno != ENOENT)
        log_fatal("unlink(%s) failed: %s", sock_path, logf_errno());
    if(bind(css->fd, (struct sockaddr*)&addr, sizeof(addr)))
        log_fatal("bind() of unix domain socket %s failed: %s", sock_path, logf_errno());

    if(chmod(sock_path, CSOCK_PERMS))
        log_fatal("Failed to chmod(%s, 0%o): %s", sock_path, CSOCK_PERMS, logf_errno());
    if(listen(css->fd, 100))
        log_fatal("Failed to listen() on control socket %s: %s", sock_path, logf_errno());

    free(sock_path);
    return css;
}

void css_start(css_t* css, struct ev_loop* loop) {
    css->loop = loop;
    ev_io_start(css->loop, css->w_accept);
}

bool css_notify_zone_reloaders(css_t* css, const bool failed) {
    // Notify log and all waiting control sock clients of success/fail
    for(size_t i = 0; i < css->reload_zones_active->len; i++)
        respond(css->reload_zones_active->q[i],
                failed ? RESP_NAK : RESP_ACK, 0, 0, NULL);

    // clear out the queue of clients waiting for reload status
    conn_queue_clear(css->reload_zones_active);

    // Swap queues, and spawn another new update thread if more waiting clients
    // piled up during the previous reload
    swap_reload_zones_queues(css);

    // If the new active queue already had waiters,
    // return true to start another reload
    return !!css->reload_zones_active->len;
}

void css_delete(css_t* css) {
    // clean out active connections...
    css_conn_t* c = css->clients;
    while(c) {
        css_conn_t* next = c->next;
        css_conn_cleanup(c);
        c = next;
    };
    gdnsd_assert(!css->num_clients);

    // free up the reload queues
    conn_queue_clear(css->reload_zones_queued);
    free(css->reload_zones_queued);
    conn_queue_clear(css->reload_zones_active);
    free(css->reload_zones_active);

    ev_io_stop(css->loop, css->w_accept);
    free(css->w_accept);
    close(css->fd);
    close(css->lock_fd); // Closing the lock fd implicitly clears the lock
    free(css);
}
