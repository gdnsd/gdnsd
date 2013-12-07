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

#include "dnsio_tcp.h"

#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "conf.h"
#include "dnswire.h"
#include "dnspacket.h"
#include "dnsio.h"
#include "gdnsd/log.h"
#include "gdnsd/net.h"
#include "gdnsd/prcu-priv.h"

typedef enum {
    READING_INITIAL = 0,
    READING_MORE,
    WRITING,
} tcpdns_state_t;

// per-thread state
typedef struct {
    dnspacket_context_t* pctx;
    unsigned timeout;
    unsigned max_clients;
    ev_io* accept_watcher;
    unsigned int num_conn_watchers;
} tcpdns_thread_t;

// per-connection state
typedef struct {
    tcpdns_thread_t* thread_ctx;
    anysin_t* asin;
    uint8_t* buffer;
    ev_io* read_watcher;
    ev_io* write_watcher;
    ev_timer* timeout_watcher;
    unsigned size;
    unsigned size_done;
    tcpdns_state_t state;
} tcpdns_conn_t;

F_NONNULL
static void cleanup_conn_watchers(struct ev_loop* loop, tcpdns_conn_t* tdata) {
    dmn_assert(loop); dmn_assert(tdata);

    shutdown(tdata->read_watcher->fd, SHUT_RDWR);
    close(tdata->read_watcher->fd);
    ev_timer_stop(loop, tdata->timeout_watcher);
    ev_io_stop(loop, tdata->read_watcher);
    if(tdata->write_watcher) ev_io_stop(loop, tdata->write_watcher);
    free(tdata->buffer);
    free(tdata->timeout_watcher);
    free(tdata->read_watcher);
    if(tdata->write_watcher) free(tdata->write_watcher);
    free(tdata->asin);

    if((tdata->thread_ctx->num_conn_watchers-- == tdata->thread_ctx->max_clients))
        ev_io_start(loop, tdata->thread_ctx->accept_watcher);

    free(tdata);
}

F_NONNULL
static void tcp_timeout_handler(struct ev_loop* loop V_UNUSED, ev_timer* t, const int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(t);
    dmn_assert(revents == EV_TIMER);

    tcpdns_conn_t* tdata = (tcpdns_conn_t*)t->data;
    log_debug("TCP DNS Connection timed out while %s %s",
        tdata->state == WRITING ? "writing to" : "reading from", logf_anysin(tdata->asin));

    if(tdata->state == WRITING)
        stats_own_inc(&tdata->thread_ctx->pctx->stats->tcp.sendfail);
    else
        stats_own_inc(&tdata->thread_ctx->pctx->stats->tcp.recvfail);

    cleanup_conn_watchers(loop, tdata);
}

F_NONNULL
static void tcp_write_handler(struct ev_loop* loop, ev_io* io, const int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(io);
    dmn_assert(revents == EV_WRITE);

    tcpdns_conn_t* tdata = (tcpdns_conn_t*)io->data;
    const size_t wanted = tdata->size - tdata->size_done;
    const uint8_t* source = tdata->buffer + tdata->size_done;

    const ssize_t written = send(io->fd, source, wanted, 0);
    if(unlikely(written == -1)) {
        if(errno != EAGAIN) {
            log_debug("TCP DNS send() failed, dropping response to %s: %s", logf_anysin(tdata->asin), logf_errno());
            stats_own_inc(&tdata->thread_ctx->pctx->stats->tcp.sendfail);
            cleanup_conn_watchers(loop, tdata);
            return;
        }
    }
    else { // we sent something...
        tdata->size_done += written;
        if(likely(tdata->size_done == tdata->size)) {
            ev_timer_again(loop, tdata->timeout_watcher);
            tdata->state = READING_INITIAL;
            if(tdata->write_watcher) ev_io_stop(loop, tdata->write_watcher);
            ev_io_start(loop, tdata->read_watcher);
            tdata->size_done = 0;
            tdata->size = 0;
            return;
        }
    }

    // Setup/Start write watcher if necc
    if(!tdata->write_watcher) {
        ev_io* write_watcher = malloc(sizeof(ev_io));
        tdata->write_watcher = write_watcher;
        write_watcher->data = tdata;
        ev_io_init(write_watcher, tcp_write_handler, io->fd, EV_WRITE);
        ev_set_priority(write_watcher, 1);
    }
    ev_io_start(loop, tdata->write_watcher);
}

F_NONNULL
static void tcp_read_handler(struct ev_loop* loop, ev_io* io, const int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(io);
    dmn_assert(revents == EV_READ);
    tcpdns_conn_t* tdata = (tcpdns_conn_t*)io->data;

    dmn_assert(tdata);
    dmn_assert(tdata->state == READING_INITIAL || tdata->state == READING_MORE);

    uint8_t* destination = &tdata->buffer[tdata->size_done];
    const size_t wanted =
        (tdata->state == READING_INITIAL ? DNS_RECV_SIZE : tdata->size)
        - tdata->size_done;

    const ssize_t pktlen = recv(io->fd, destination, wanted, 0);
    if(pktlen < 1) {
        if(unlikely(pktlen == -1 || tdata->size_done)) {
            if(pktlen == -1) {
                if(errno == EAGAIN) {
#                   ifdef TCP_DEFER_ACCEPT
                        ev_io_start(loop, tdata->read_watcher);
#                   endif
                    return;
                }
                log_debug("TCP DNS recv() from %s: %s", logf_anysin(tdata->asin), logf_errno());
            }
            else if(tdata->size_done) {
                log_debug("TCP DNS recv() from %s: Unexpected EOF", logf_anysin(tdata->asin));
            }
            stats_own_inc(&tdata->thread_ctx->pctx->stats->tcp.recvfail);
        }
        cleanup_conn_watchers(loop, tdata);
        return;
    }

    tdata->size_done += pktlen;

    if(likely(tdata->state == READING_INITIAL)) {
        if(likely(tdata->size_done > 1)) {
            tdata->size = (tdata->buffer[0] << 8) + tdata->buffer[1] + 2;
            if(unlikely(tdata->size > DNS_RECV_SIZE)) {
                log_debug("Oversized TCP DNS query of length %u from %s", tdata->size, logf_anysin(tdata->asin));
                stats_own_inc(&tdata->thread_ctx->pctx->stats->tcp.recvfail);
                cleanup_conn_watchers(loop, tdata);
                return;
            }
            tdata->state = READING_MORE;
        }
    }

    if(unlikely(tdata->size_done < tdata->size)) {
#       ifdef TCP_DEFER_ACCEPT
            ev_io_start(loop, tdata->read_watcher);
#       endif
        return;
    }

    //  Process the query and start the writer
    tdata->size = process_dns_query(tdata->thread_ctx->pctx, tdata->asin, &tdata->buffer[2], tdata->size - 2);
    if(!tdata->size) {
        cleanup_conn_watchers(loop, tdata);
        return;
    }

    ev_io_stop(loop, tdata->read_watcher);
    gdnsd_put_una16(htons(tdata->size), tdata->buffer);
    tdata->size += 2;
    tdata->size_done = 0;
    tdata->state = WRITING;

    // Most likely the response fits in the socket buffers
    //  as well as the window size, and therefore a complete
    //  write can proceed immediately, so try it without
    //  going through the loop.  tcp_write_handler() will
    //  start its own watcher if necc.  We can use the
    //  read_watcher (aka io here) as the ev_io for this invocation,
    //  since all the code cares about is ->data and ->fd.
    tcp_write_handler(loop, io, EV_WRITE);
}

F_NONNULL
static void accept_handler(struct ev_loop* loop, ev_io* io, const int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(io);
    dmn_assert(revents == EV_READ);

    tcpdns_thread_t* thread_ctx = (tcpdns_thread_t*)io->data;

    anysin_t* asin = malloc(sizeof(anysin_t));
    asin->len = ANYSIN_MAXLEN;

    const int sock = accept(io->fd, &asin->sa, &asin->len);

    if(unlikely(sock < 0)) {
        free(asin);
        switch(errno) {
            case EAGAIN:
            case EINTR:
                break;
#ifdef ENONET
            case ENONET:
#endif
            case ENETDOWN:
            case EPROTO:
            case EHOSTDOWN:
            case EHOSTUNREACH:
            case ENETUNREACH:
                log_debug("TCP DNS: early tcp socket death: %s", logf_errno());
                break;
            default:
                log_err("TCP DNS: accept() failed: %s", logf_errno());
        }
        return;
    }

    log_debug("Received TCP DNS connection from %s", logf_anysin(asin));

    if(unlikely(fcntl(sock, F_SETFL, (fcntl(sock, F_GETFL, 0)) | O_NONBLOCK) == -1)) {
        free(asin);
        close(sock);
        log_err("Failed to set O_NONBLOCK on inbound TCP DNS socket: %s", logf_errno());
        return;
    }

    if((++thread_ctx->num_conn_watchers == thread_ctx->max_clients))
        ev_io_stop(loop, thread_ctx->accept_watcher);

    tcpdns_conn_t* tdata = calloc(1, sizeof(tcpdns_conn_t));
    tdata->buffer = malloc(gconfig.max_response + 2);
    tdata->thread_ctx = thread_ctx;
    tdata->state = READING_INITIAL;
    tdata->asin = asin;

    ev_io* read_watcher = malloc(sizeof(ev_io));
    tdata->read_watcher = read_watcher;
    read_watcher->data = tdata;
    ev_io_init(read_watcher, tcp_read_handler, sock, EV_READ);
    ev_set_priority(read_watcher, 0);

    ev_timer* timeout_watcher = malloc(sizeof(ev_timer));
    timeout_watcher->data = tdata;
    tdata->timeout_watcher = timeout_watcher;
    ev_timer_init(timeout_watcher, tcp_timeout_handler, 0, thread_ctx->timeout);
    ev_set_priority(timeout_watcher, -1);
    ev_timer_again(loop, timeout_watcher);

#ifdef TCP_DEFER_ACCEPT
    // Since we use DEFER_ACCEPT, the request is likely already
    //  queued and available at this point, so start read()-ing
    //  without going through the event loop
    tcp_read_handler(loop, tdata->read_watcher, EV_READ);
#else
    ev_io_start(loop, read_watcher);
#endif
}

#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif

#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

int tcp_listen_pre_setup(const anysin_t* asin, const int timeout V_UNUSED, const bool reuseport V_UNUSED) {

    dmn_assert(asin);

    const bool isv6 = asin->sa.sa_family == AF_INET6 ? true : false;
    dmn_assert(isv6 || asin->sa.sa_family == AF_INET);

    const int sock = socket(isv6 ? PF_INET6 : PF_INET, SOCK_STREAM, gdnsd_getproto_tcp());
    if(sock < 0) log_fatal("Failed to create IPv%c TCP socket: %s", isv6 ? '6' : '4', logf_errno());

    if(fcntl(sock, F_SETFL, (fcntl(sock, F_GETFL, 0)) | O_NONBLOCK) == -1)
        log_fatal("Failed to set O_NONBLOCK on TCP socket: %s", logf_errno());

    const int opt_one = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt_one, sizeof opt_one) == -1)
        log_fatal("Failed to set SO_REUSEADDR on TCP socket: %s", logf_errno());

#ifdef SO_REUSEPORT
    if(reuseport)
        if(setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt_one, sizeof opt_one) == -1)
            log_fatal("Failed to set SO_REUSEPORT on TCP socket: %s", logf_errno());
#endif

#ifdef TCP_DEFER_ACCEPT
    const int opt_timeout = timeout;
    if(setsockopt(sock, SOL_TCP, TCP_DEFER_ACCEPT, &opt_timeout, sizeof opt_timeout) == -1)
        log_fatal("Failed to set TCP_DEFER_ACCEPT on TCP socket: %s", logf_errno());
#endif

    if(isv6)
        if(setsockopt(sock, SOL_IPV6, IPV6_V6ONLY, &opt_one, sizeof(opt_one)) == -1)
            log_fatal("Failed to set IPV6_V6ONLY on TCP socket: %s", logf_errno());

    return sock;
}

bool tcp_dns_listen_setup(dns_thread_t* t) {
    dmn_assert(t);

    const dns_addr_t* addrconf = t->ac;
    dmn_assert(addrconf);

    const anysin_t* asin = &addrconf->addr;

    t->sock = tcp_listen_pre_setup(&addrconf->addr, addrconf->tcp_timeout, t->ac->tcp_threads > 1);
    const bool need_caps = dnsio_bind(t);
    if(listen(t->sock, addrconf->tcp_clients_per_thread) == -1)
        log_fatal("Failed to listen(s, %i) on TCP socket %s: %s", addrconf->tcp_clients_per_thread, logf_anysin(asin), logf_errno());
    return need_caps;
}

static void thread_clean(void* arg_unused V_UNUSED) {
    gdnsd_prcu_rdr_thread_end();
}

static void ztstate_offline(struct ev_loop* loop V_UNUSED, ev_prepare* w V_UNUSED, int revents V_UNUSED) {
    gdnsd_prcu_rdr_offline();
}

static void ztstate_online(struct ev_loop* loop V_UNUSED, ev_check* w V_UNUSED, int revents V_UNUSED) {
    gdnsd_prcu_rdr_online();
}

void* dnsio_tcp_start(void* thread_asvoid) {
    dmn_assert(thread_asvoid);

    const dns_thread_t* t = (const dns_thread_t*)thread_asvoid;
    const dns_addr_t* addrconf = t->ac;

    tcpdns_thread_t* thread_ctx = malloc(sizeof(tcpdns_thread_t));
    thread_ctx->pctx = dnspacket_context_new(t->threadnum, false);

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    thread_ctx->num_conn_watchers = 0;
    thread_ctx->timeout = addrconf->tcp_timeout;
    thread_ctx->max_clients = addrconf->tcp_clients_per_thread;

    if(t->need_late_bind) {
        const anysin_t* asin = &addrconf->addr;
        while(bind(t->sock, &asin->sa, asin->len)) {
            if(errno != EADDRNOTAVAIL) {
                log_err("Failed late bind() of TCP socket to %s: %s.  This listener thread is now shutting down.  Late bind attempts for this socket will no longer be attempted!", logf_anysin(asin), logf_errno());
                pthread_exit(NULL);
            }
            sleep(addrconf->late_bind_secs);
        }

        if(listen(t->sock, addrconf->tcp_clients_per_thread) == -1)
            log_fatal("Failed to listen(s, %i) on late-bound TCP socket %s: %s", addrconf->tcp_clients_per_thread, logf_anysin(asin), logf_errno());

        log_info("Late bind() of TCP socket to %s succeeded, serving requests now", logf_anysin(asin));
    }
    else if(t->autoscan_bind_failed) {
        // already logged this condition back when bind() failed, but it's simpler
        //  to spawn the thread and do the dnspacket_context_new() here properly and
        //  then exit the iothread.  The rest of the code will see this as a thread that
        //  simply never gets requests.
        pthread_exit(NULL);
    }

    struct ev_io* accept_watcher = thread_ctx->accept_watcher = malloc(sizeof(struct ev_io));
    ev_io_init(accept_watcher, accept_handler, t->sock, EV_READ);
    ev_set_priority(accept_watcher, -2);
    accept_watcher->data = thread_ctx;

    struct ev_loop* loop = ev_loop_new(EVFLAG_AUTO);
    if(!loop) log_fatal("ev_loop_new() failed");
    ev_set_timeout_collect_interval(loop, 0.1);

    ev_io_start(loop, accept_watcher);

    gdnsd_prcu_rdr_thread_start();
    pthread_cleanup_push(thread_clean, NULL);

    struct ev_prepare* prep_watcher = malloc(sizeof(struct ev_prepare));
    struct ev_check* check_watcher = malloc(sizeof(struct ev_check));
    ev_prepare_init(prep_watcher, ztstate_offline);
    ev_check_init(check_watcher, ztstate_online);
    ev_set_priority(check_watcher, EV_MAXPRI);
    ev_prepare_start(loop, prep_watcher);
    ev_check_start(loop, check_watcher);
    ev_run(loop, 0);

    pthread_cleanup_pop(1);

    return NULL;
}

