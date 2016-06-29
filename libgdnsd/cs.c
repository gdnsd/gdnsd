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
#include <gdnsd/cs.h>

#include <gdnsd/compiler.h>
#include <gdnsd/alloc.h>
#include <gdnsd/dmn.h>
#include <gdnsd/log.h>

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

static const mode_t CSOCK_PERMS = (S_IRUSR|S_IWUSR); // 0600

typedef enum {
    READING_SIZE = 0,
    READING_DATA,
    WAITING_RESPONSE,
    WRITING_SIZE,
    WRITING_DATA,
} css_cstate_t;

struct css_conn_s_;
typedef struct css_conn_s_ css_conn_t;

struct css_conn_s_ {
    css_conn_t* next; // linked-list for cleanup
    css_conn_t* prev;
    gdnsd_css_t* css;
    uint8_t* buffer;
    ev_io* w_read;
    ev_io* w_write;
    ev_timer* w_timeout;
    uint64_t clid;
    int fd;
    union {
        uint32_t u32;
        uint8_t u8[4];
    } szbuf;
    uint32_t size;
    uint32_t size_done;
    css_cstate_t state;
};

struct gdnsd_css_s_ {
    int fd;
    uint32_t max_buffer_in;
    uint32_t max_buffer_out;
    unsigned max_clients;
    unsigned timeout;
    unsigned num_clients;
    uint64_t next_clid;
    gdnsd_css_rcb_t rcb;
    void* data;
    ev_io* w_accept;
    struct ev_loop* loop;
    char* path;
    css_conn_t* first_client;
};

struct gdnsd_csc_s_ {
    int fd;
    char* path;
};

F_NONNULL
static void css_conn_cleanup(css_conn_t* c) {
    gdnsd_css_t* css = c->css;
    dmn_assert(css);

    // stop/free io-related things
    ev_io_stop(css->loop, c->w_read);
    ev_io_stop(css->loop, c->w_write);
    ev_timer_stop(css->loop, c->w_timeout);
    free(c->w_read);
    free(c->w_write);
    free(c->w_timeout);
    free(c->buffer);
    close(c->fd);

    // remove from linked list
    if(c == css->first_client)
        css->first_client = c->next;
    if(c->prev)
        c->prev->next = c->next;
    if(c->next)
        c->next->prev = c->prev;
    free(c);

    // if we were at the maximum, start accepting connections again
    if(css->num_clients-- == css->max_clients)
        ev_io_start(css->loop, css->w_accept);
}

F_NONNULL
static void css_conn_timeout(struct ev_loop* loop V_UNUSED, ev_timer* w, const int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_TIMER);
    css_conn_t* c = w->data;
    dmn_assert(c);
    if(c->state != READING_SIZE)
        dmn_log_warn("control socket connection timed out mid-transaction");
    css_conn_cleanup(c);
}

F_NONNULL
static void css_conn_write(struct ev_loop* loop, ev_io* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_WRITE);
    css_conn_t* c = w->data;
    gdnsd_css_t* css = c->css;
    dmn_assert(c); dmn_assert(css);

    dmn_assert(c->state == WRITING_SIZE || c->state == WRITING_DATA);
    const uint8_t* source = c->state == WRITING_SIZE ? c->szbuf.u8 : c->buffer;
    const size_t wanted = c->size - c->size_done;
    source += c->size_done;

    const ssize_t send_rv = send(w->fd, source, wanted, 0);

    if(unlikely(send_rv < 0)) {
        if(errno != EAGAIN && errno != EWOULDBLOCK) {
            dmn_log_debug("control socket write of %zu bytes failed: %s", wanted, dmn_logf_errno());
            css_conn_cleanup(c);
        }
        return;
    }

    // we sent something...
    c->size_done += (size_t)send_rv;
    if(c->size_done < c->size)
        return;

    if(c->state == WRITING_SIZE) {
        c->state = WRITING_DATA;
        c->size = c->szbuf.u32;
        c->size_done = 0;
        return;
    }

    ev_timer_again(loop, c->w_timeout);
    ev_io_stop(loop, c->w_write);
    ev_io_start(loop, c->w_read);
    c->state = READING_SIZE;
    c->size = 4;
    c->size_done = 0;
    return;
}

F_NONNULL
static void css_conn_read(struct ev_loop* loop, ev_io* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_READ);
    css_conn_t* c = w->data;
    gdnsd_css_t* css = c->css;
    dmn_assert(c); dmn_assert(css);

    dmn_assert(c->state == READING_SIZE || c->state == READING_DATA);
    uint8_t* buffer = c->state == READING_SIZE
        ? c->szbuf.u8 : c->buffer;

    uint8_t* destination = &buffer[c->size_done];
    const size_t wanted = c->size - c->size_done;
    const ssize_t pktlen = recv(w->fd, destination, wanted, 0);
    if(pktlen < 1) {
        if(unlikely(pktlen == -1 || c->size_done)) {
            if(pktlen == -1) {
                if(errno == EAGAIN || errno == EWOULDBLOCK) {
                    return;
                }
                dmn_log_warn("control socket read failed: %s", dmn_logf_errno());
            }
            else if(c->size_done) {
                dmn_log_warn("control socket client closed mid-transmit");
            }
        }
        css_conn_cleanup(c);
        return;
    }

    c->size_done += pktlen;

    // need to wait for more input data...
    if(c->size_done < c->size)
        return;

    if(c->state == READING_SIZE) {
        c->state = READING_DATA;
        c->size = c->szbuf.u32;
        c->size_done = 0;
        if(c->size > css->max_buffer_in) {
            dmn_log_warn("oversized client control socket message of length %" PRIu32, c->size);
            css_conn_cleanup(c);
        }
        else if(!c->size) {
            dmn_log_warn("client control socket message of length zero is illegal");
            css_conn_cleanup(c);
        }
        return;
    }

    // we have a full request to process from here...
    c->state = WAITING_RESPONSE;
    ev_io_stop(loop, c->w_read);

    // built-in ping->pong no-op transaction
    if(c->size == 4 && !memcmp(c->buffer, "ping", 4)) {
        c->buffer[1] = 'o';
        c->state = WRITING_SIZE;
        c->szbuf.u32 = 4;
        c->size = 4;
        c->size_done = 0;
        ev_io_start(loop, c->w_write);
    }
    // built-in getpid transaction
    else if(c->size == 6 && !memcmp(c->buffer, "getpid", 6)) {
        pid_t my_pid = getpid();
        int snp_rv = snprintf((char*)c->buffer, 22, "%li", (long)my_pid);
        dmn_assert(snp_rv > 0);
        c->state = WRITING_SIZE;
        c->szbuf.u32 = (uint32_t)snp_rv;
        c->size = 4;
        c->size_done = 0;
        ev_io_start(loop, c->w_write);
    }
    // callback for real transactions
    else if(css->rcb(css, c->clid, c->buffer, c->size, css->data)) {
        css_conn_cleanup(c);
    }
}

F_NONNULL
static void css_accept(struct ev_loop* loop, ev_io* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_READ);
    gdnsd_css_t* css = w->data;
    dmn_assert(css);

    const int fd = accept(w->fd, NULL, NULL);

    if(unlikely(fd < 0)) {
        switch(errno) {
            case EAGAIN:
#if EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
            case EINTR:
                break;
            default:
                dmn_log_err("control socket early connection failure: %s", dmn_logf_errno());
                break;
        }
        return;
    }

    if(fcntl(css->fd, F_SETFD, FD_CLOEXEC))
        dmn_log_fatal("fcntl(FD_CLOEXEC) on control socket fd failed: %s", dmn_logf_errno());

    if(fcntl(fd, F_SETFL, (fcntl(fd, F_GETFL, 0)) | O_NONBLOCK) == -1)
        dmn_log_fatal("Failed to set O_NONBLOCK on control socket connection: %s", dmn_logf_errno());

    // if we now have max_clients connected, stop accepting new ones
    if(++css->num_clients == css->max_clients)
        ev_io_stop(css->loop, css->w_accept);

    // calculate max + set SO_(SND|RCV)BUF
    const uint32_t maxbuf = css->max_buffer_out > css->max_buffer_in
        ? css->max_buffer_out
        : css->max_buffer_in;

    if(maxbuf > 4096U) {
        int opt_size = (int)maxbuf;
        if(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt_size, sizeof(opt_size)))
            dmn_log_warn("Failed to set SO_SNDBUF to %i for controlsock fd: %s",
                         opt_size, dmn_logf_errno());
        if(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt_size, sizeof(opt_size)))
            dmn_log_warn("Failed to set SO_RCVBUF to %i for controlsock fd: %s",
                         opt_size, dmn_logf_errno());
    }

    // set up the per-connection state and start reading requests...
    css_conn_t* c = xmalloc(sizeof(css_conn_t));
    c->css = css;
    c->fd = fd;
    c->clid = css->next_clid++;
    c->buffer = xmalloc(maxbuf);
    c->w_read = xmalloc(sizeof(ev_io));
    c->w_write = xmalloc(sizeof(ev_io));
    c->w_timeout = xmalloc(sizeof(ev_timer));
    ev_io_init(c->w_read, css_conn_read, fd, EV_READ);
    ev_io_init(c->w_write, css_conn_write, fd, EV_WRITE);
    ev_timer_init(c->w_timeout, css_conn_timeout, 0, css->timeout);
    c->w_read->data = c;
    c->w_write->data = c;

    // set up buffer/watcher state to read input length
    c->state = READING_SIZE;
    c->size = 4;
    c->size_done = 0;
    ev_io_start(css->loop, c->w_read);
    ev_timer_again(css->loop, c->w_timeout);

    // insert into front of linked list
    c->next = css->first_client;
    c->prev = NULL;
    if(css->first_client)
        css->first_client->prev = c;
    css->first_client = c;
}

F_NONNULL
static void sun_set_path(struct sockaddr_un* a, const char* path) {
    dmn_assert(a); dmn_assert(path);

    memset(a, 0, sizeof(*a));
    a->sun_family = AF_UNIX;
    const unsigned plen = strlen(path) + 1;
    if(plen > sizeof(a->sun_path))
        dmn_log_fatal("Implementation bug/limit: desired control socket path %s exceeds sun_path length of %zu", path, sizeof(a->sun_path));
    memcpy(a->sun_path, path, plen);
}

static int lsock_create_and_bind(const char* path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(fd < 0)
        dmn_log_fatal("socket(AF_UNIX, SOCK_STREAM, 0) failed: %s", dmn_logf_errno());
    if(fcntl(fd, F_SETFD, FD_CLOEXEC))
        dmn_log_fatal("fcntl(FD_CLOEXEC) on control socket fd failed: %s", dmn_logf_errno());

    struct sockaddr_un addr;
    sun_set_path(&addr, path);
    if(unlink(path) && errno != ENOENT)
        dmn_log_fatal("unlink(%s) failed: %s", path, dmn_logf_errno());
    if(bind(fd, (struct sockaddr*)&addr, sizeof(addr)))
        dmn_log_fatal("bind() of unix domain socket %s failed: %s", path, dmn_logf_errno());

    return fd;
}

/*********************
 * Public interfaces *
 *********************/

gdnsd_css_t* gdnsd_css_new(const char* path, gdnsd_css_rcb_t rcb, void* data, uint32_t max_buffer_in, uint32_t max_buffer_out, unsigned max_clients, unsigned timeout) {
    dmn_assert(path); dmn_assert(rcb);

    // floor buffer maxes for reasonable built-ins
    if(max_buffer_out < 64)
        max_buffer_out = 64;
    if(max_buffer_in < 8)
        max_buffer_in = 8;

    // floor max_clients to 1 and timeout to 3 for sanity
    if(max_clients < 1)
        max_clients = 1;
    if(timeout < 3)
        timeout = 3;

    gdnsd_css_t* css = xmalloc(sizeof(gdnsd_css_t));
    css->loop = NULL;
    css->path = strdup(path);
    css->max_buffer_in = max_buffer_in;
    css->max_buffer_out = max_buffer_out;
    css->max_clients = max_clients;
    css->timeout = timeout;
    css->num_clients = 0;
    css->first_client = NULL;
    css->next_clid = 1;

    css->fd = lsock_create_and_bind(css->path);

    css->rcb = rcb;
    css->data = data;
    css->w_accept = xmalloc(sizeof(ev_io));
    ev_io_init(css->w_accept, css_accept, css->fd, EV_READ);
    css->w_accept->data = css;

    // XXX There's a potential race here, maybe, on some platforms, that could
    // allow unauthorized access to the control socket from unrelated local
    // users.  But it may not be much of an issue in practice...?
    if(chmod(css->path, CSOCK_PERMS))
        dmn_log_fatal("Failed to chmod(%s, 0%o): %s", css->path, CSOCK_PERMS, dmn_logf_errno());
    if(listen(css->fd, 100))
        dmn_log_fatal("Failed to listen() on control socket %s: %s", css->path, dmn_logf_errno());
    if(fcntl(css->fd, F_SETFL, (fcntl(css->fd, F_GETFL, 0)) | O_NONBLOCK) == -1)
        dmn_log_fatal("Failed to set O_NONBLOCK on control socket %s: %s", css->path, dmn_logf_errno());

    return css;
}

void gdnsd_css_start(gdnsd_css_t* css, struct ev_loop* loop) {
    dmn_assert(css);
    dmn_assert(loop);
    css->loop = loop;
    ev_io_start(css->loop, css->w_accept);
}

void gdnsd_css_recreate(gdnsd_css_t* css) {
    dmn_assert(css);
    dmn_assert(css->loop);
    ev_io_stop(css->loop, css->w_accept);
    close(css->fd);
    css->fd = lsock_create_and_bind(css->path);
    ev_io_set(css->w_accept, css->fd, EV_READ);
    if(css->num_clients < css->max_clients)
        ev_io_start(css->loop, css->w_accept);
}

void gdnsd_css_respond(gdnsd_css_t* css, uint64_t clid, const void* buffer, uint32_t len) {
    dmn_assert(css); dmn_assert(buffer);

    // find this client (we assume the list isn't so huge that linear search is an issue)
    css_conn_t* c = NULL;
    css_conn_t* searchme = css->first_client;
    while(!c && searchme) {
        if(searchme->clid == clid)
            c = searchme;
        else
            searchme = searchme->next;
    }

    if(!c)
        dmn_log_fatal("BUG: css_respond called with invalid clid %" PRIu64, clid);

    if(c->state != WAITING_RESPONSE)
        dmn_log_fatal("BUG: css_respond called for clid %" PRIu64 ", which was not waiting on a response", clid);

    if(len > css->max_buffer_out)
        dmn_log_fatal("BUG: css_respond called with len %" PRIu32 " vs max_buffer_out %" PRIu32, len, css->max_buffer_out);

    if(!len)
        dmn_log_err("BUG: css_respond called with zero response length for clid %" PRIu64, clid);

    if(buffer != c->buffer)
        memcpy(c->buffer, buffer, len);
    c->state = WRITING_SIZE;
    c->szbuf.u32 = len;
    c->size = 4;
    c->size_done = 0;
    ev_io_start(css->loop, c->w_write);
}

void gdnsd_css_delete(gdnsd_css_t* css) {
    dmn_assert(css);

    // clean out active connections...
    css_conn_t* c = css->first_client;
    while(c) {
        css_conn_t* next = c->next;
        css_conn_cleanup(c);
        c = next;
    };
    dmn_assert(!css->num_clients);

    // stop the watcher for new connections and close the listen fd
    ev_io_stop(css->loop, css->w_accept);
    free(css->w_accept);
    close(css->fd);

    // free remaining data
    free(css->path);
    free(css);
}

gdnsd_csc_t* gdnsd_csc_new(const char* path) {
    dmn_assert(path);

    gdnsd_csc_t* csc = xmalloc(sizeof(gdnsd_csc_t));
    csc->path = strdup(path);
    csc->fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(csc->fd < 0)
        dmn_log_fatal("socket(AF_UNIX, SOCK_STREAM, 0) failed: %s", dmn_logf_errno());

    struct sockaddr_un addr;
    sun_set_path(&addr, csc->path);

    if(connect(csc->fd, (struct sockaddr*)&addr, sizeof(addr)))
        dmn_log_fatal("connect() to unix domain socket %s failed: %s", csc->path, dmn_logf_errno());

    return csc;
}

uint32_t gdnsd_csc_txn(gdnsd_csc_t* csc, void* buffer, uint32_t req_len, uint32_t max_resp_len) {
    dmn_assert(csc); dmn_assert(buffer);

    if(!req_len)
        dmn_log_fatal("control socket client: invalid req_len of zero");
    if(!max_resp_len)
        dmn_log_fatal("control socket client: invalid max_resp_len of zero");

    union {
        uint8_t u8[4];
        uint32_t u32;
    } szbuf;

    szbuf.u32 = req_len;
    ssize_t send_rv = send(csc->fd, szbuf.u8, 4, 0);
    if(send_rv != 4)
        dmn_log_fatal("4-byte send() failed with retval %zi: %s", send_rv, dmn_logf_errno());
    send_rv = send(csc->fd, buffer, req_len, 0);
    if(send_rv != req_len)
        dmn_log_fatal("%" PRIu32 "-byte send() failed with retval %zi: %s", req_len, send_rv, dmn_logf_errno());

    ssize_t recv_rv = recv(csc->fd, szbuf.u8, 4, 0);
    if(recv_rv != 4)
        dmn_log_fatal("4-byte recv() failed with retval %zi: %s", recv_rv, dmn_logf_errno());
    if(szbuf.u32 > max_resp_len)
        dmn_log_fatal("server tried to send excessive size %" PRIu32, szbuf.u32);
    recv_rv = recv(csc->fd, buffer, szbuf.u32, 0);
    if(recv_rv != szbuf.u32)
        dmn_log_fatal("%" PRIu32 "-byte recv() failed with retval %zi: %s", szbuf.u32, recv_rv, dmn_logf_errno());

    return szbuf.u32;
}

void gdnsd_csc_closewait(gdnsd_csc_t* csc) {
    dmn_assert(csc);
    char x;
    const ssize_t recv_rv = recv(csc->fd, &x, 1, 0);
    if(recv_rv)
        dmn_log_fatal("while waiting for server close, control socket retval was %zi: %s", recv_rv, dmn_logf_errno());
}

bool gdnsd_csc_ping(gdnsd_csc_t* csc) {
    uint8_t buffer[4] = "ping";
    const uint32_t resp_len = gdnsd_csc_txn(csc, buffer, 4, 4);
    return ((resp_len != 4) || memcmp(buffer, "pong", 4));
}

pid_t gdnsd_csc_getpid(gdnsd_csc_t* csc) {
    uint8_t buffer[22] = "getpid";
    const uint32_t resp_len = gdnsd_csc_txn(csc, buffer, 6, 21);
    buffer[resp_len] = '\0';
    const long pid = atol((char*)buffer);
    return (pid_t)pid;
}

void gdnsd_csc_delete(gdnsd_csc_t* csc) {
    close(csc->fd);
    free(csc->path);
    free(csc);
}
