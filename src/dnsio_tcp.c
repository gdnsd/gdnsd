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
#include "dnsio_tcp.h"

#include "conf.h"
#include "dnswire.h"
#include "dnspacket.h"
#include "socks.h"

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/misc.h>
#include <gdnsd/net.h>

#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <ev.h>
#include <urcu-qsbr.h>

typedef enum {
    ST_IDLE = 0,
    ST_READING,
    ST_WRITING,
} tcpdns_state_t;

struct tcpdns_conn;
typedef struct tcpdns_conn tcpdns_conn_t;

// per-thread state
typedef struct {
    dnspacket_stats_t* stats;
    void* dnsp_ctx;
    struct ev_loop* loop;
    ev_io accept_watcher;
    ev_prepare prep_watcher;
    ev_async stop_watcher;
    ev_timer timeout_watcher;
    tcpdns_conn_t* idleq_head; // doubly-linked-list, most-idle at head
    tcpdns_conn_t* idleq_tail; // last element, least-idle
    double tmo_scaler; // timeout changes by this much per connection under tmo_thresh75
    unsigned tmo_thresh75; // 75% threshold connection count for timeout calc
    unsigned edns0_keepalive; // current timeout, minus 2s, in integer units of 100ms
    unsigned max_timeout;
    unsigned max_clients;
    unsigned num_conns; // count of all conns, also len of idleq list
    bool rcu_is_online;
    bool shutting_down;
} tcpdns_thread_t;

// per-connection state
struct tcpdns_conn {
    tcpdns_conn_t* next; // doubly-linked-list
    tcpdns_conn_t* prev; // doubly-linked-list
    tcpdns_thread_t* ctx;
    ev_io read_watcher;
    ev_io write_watcher;
    ev_tstamp idle_start;
    gdnsd_anysin_t asin;
    unsigned size;
    unsigned size_done;
    tcpdns_state_t state;
    uint8_t buffer[0];
};

static pthread_mutex_t registry_lock = PTHREAD_MUTEX_INITIALIZER;
static tcpdns_thread_t** registry = NULL;
static size_t registry_size = 0;
static size_t registry_init = 0;

void dnsio_tcp_init(unsigned num_threads)
{
    registry_size = (size_t)num_threads;
    registry = xcalloc_n(registry_size, sizeof(*registry));
}

void dnsio_tcp_request_threads_stop(void)
{
    gdnsd_assert(registry_size == registry_init);
    for (unsigned i = 0; i < registry_init; i++) {
        tcpdns_thread_t* ctx = registry[i];
        ev_async* stop_watcher = &ctx->stop_watcher;
        ev_async_send(ctx->loop, stop_watcher);
    }
}

static void register_thread(tcpdns_thread_t* ctx)
{
    pthread_mutex_lock(&registry_lock);
    gdnsd_assert(registry_init < registry_size);
    registry[registry_init++] = ctx;
    pthread_mutex_unlock(&registry_lock);
}

// Used by raw idleq-managing functions to just close the conn itself and stop
// watchers, but not free the conn structure or remove it from the idleq
F_NONNULL
static void conn_close(tcpdns_conn_t* conn, bool clean)
{
    struct ev_loop* loop = conn->ctx->loop;
    ev_io* read_watcher = &conn->read_watcher;
    if (clean)
        shutdown(read_watcher->fd, SHUT_RDWR);
    close(read_watcher->fd);
    ev_io_stop(loop, read_watcher);
    ev_io* write_watcher = &conn->write_watcher;
    ev_io_stop(loop, write_watcher);
}

// idleq_process_timeouts:
// * Forces the closure of idleq_head (most-idle) if max_clients connections
//   have been reached.
// * Closes off the first N connections (starting at idleq_head) which are
//   past the current idle timeout, dynamically adjusting the idle timeout
//   cutoff after each close reduces the count of open connections
// * Updates the idle timeout based on the remaining connection count
// * Resets the actual timer event based on the new timeout and the new list
//   head (or stops it, if list became empty).
// This needs to be called in all of these various cases:
// * A new connection is added to the idleq
// * A connection is removed from the idleq
// * The head of the idleq changes (prev head bumped to tail for activity)
// * The timeout timer managed by this function fires
F_NONNULL
static void idleq_process_timeouts(tcpdns_thread_t* ctx)
{
    gdnsd_assert(ctx->num_conns <= ctx->max_clients);

    // If we arrived here just after adding a new connection which raised us to
    // the maximum, force the expiry of the next entry on the list by faking
    // its idle_start to zero.
    if (ctx->num_conns == ctx->max_clients)
        ctx->idleq_head->idle_start = 0.;

    // Calculate an updated timeout value (if shutting down, fixed 2s)
    double cur_timeout = 2.0;
    if (!ctx->shutting_down)
        cur_timeout += ((ctx->num_conns >= ctx->tmo_thresh75 ? 0 : (ctx->tmo_thresh75 - ctx->num_conns)) * ctx->tmo_scaler);

    // efficiency/fudge factor, expire up to 10ms past the actual clock cutoff
    double cutoff = ev_now(ctx->loop) + 0.01 - cur_timeout;

    tcpdns_conn_t* conn = ctx->idleq_head;
    while (conn && conn->idle_start <= cutoff) {
        tcpdns_conn_t* next_conn = conn->next;
        ctx->num_conns--;
        // adjust cutoff and cur_timeout as we close conns, if not shutting down
        if (ctx->num_conns < ctx->tmo_thresh75 && !ctx->shutting_down) {
            cutoff -= ctx->tmo_scaler;
            cur_timeout += ctx->tmo_scaler;
        }
        // we're looking for the force-to-zero above, vs realistic timestamp, the "< 1.0" is to avoid float-equality problems.
        if (conn->idle_start < 1.0) {
            log_debug("TCP DNS conn to %s closed by server: killed due to connection load", logf_anysin(&conn->asin));
            stats_own_inc(&conn->ctx->stats->tcp.close_s_kill);
        } else {
            log_debug("TCP DNS conn to %s closed by server: timeout", logf_anysin(&conn->asin));
            stats_own_inc(&conn->ctx->stats->tcp.close_s_ok);
        }
        conn_close(conn, true);
        free(conn);
        conn = next_conn;
    }

    if (conn) {
        conn->prev = NULL;
        ctx->idleq_head = conn;
    } else {
        gdnsd_assert(!ctx->num_conns);
        ctx->idleq_head = ctx->idleq_tail = NULL;
    }

    // Adjust timer event as approrpriate
    ev_timer* tmo = &ctx->timeout_watcher;
    if (ctx->idleq_head) {
        ev_tstamp next_interval = cur_timeout - (ev_now(ctx->loop) - ctx->idleq_head->idle_start);
        if (next_interval < 0.01)
            next_interval = 0.01;
        tmo->repeat = next_interval;
        ev_timer_again(ctx->loop, tmo);
    } else {
        gdnsd_assert(!ctx->num_conns);
        ev_timer_stop(ctx->loop, tmo);
    }

    // Update edns0 keepalive view of current timeout
    gdnsd_assert(cur_timeout >= 2.0);
    ctx->edns0_keepalive = (unsigned)((cur_timeout - 2.0) * 10.0);
}

// Append a new connection at the tail of the idle list and set its idle_start
F_NONNULL
static void idleq_append_tail(tcpdns_conn_t* conn)
{
    tcpdns_thread_t* ctx = conn->ctx;
    gdnsd_assert(ctx);

    // This element is not part of the linked list yet
    gdnsd_assert(ctx->idleq_head != conn);
    gdnsd_assert(ctx->idleq_tail != conn);
    gdnsd_assert(!conn->next);
    gdnsd_assert(!conn->prev);

    if (!ctx->idleq_head) {
        // Empty idle queue, we must set head+tail
        gdnsd_assert(!ctx->idleq_tail);
        ctx->idleq_head = ctx->idleq_tail = conn;
    } else {
        gdnsd_assert(ctx->idleq_tail);
        gdnsd_assert(!ctx->idleq_tail->next);
        ctx->idleq_tail->next = conn;
        conn->prev = ctx->idleq_tail;
        ctx->idleq_tail = conn;
    }

    conn->idle_start = ev_now(ctx->loop);
    ctx->num_conns++;
    idleq_process_timeouts(ctx);
}

// Remove a connection from the list
F_NONNULL
static void idleq_remove(tcpdns_conn_t* conn, bool skip_timer_updates)
{
    tcpdns_thread_t* ctx = conn->ctx;
    gdnsd_assert(ctx);

    gdnsd_assert(ctx->num_conns);

    if (conn->next) {
        gdnsd_assert(conn != ctx->idleq_tail);
        conn->next->prev = conn->prev;
    } else {
        gdnsd_assert(conn == ctx->idleq_tail);
        ctx->idleq_tail = conn->prev;
    }

    if (conn->prev) {
        gdnsd_assert(conn != ctx->idleq_head);
        conn->prev->next = conn->next;
    } else {
        gdnsd_assert(conn == ctx->idleq_head);
        ctx->idleq_head = conn->next;
    }

    // wipe the stale references from the removed object
    conn->prev = conn->next = NULL;

    ctx->num_conns--;
    if (!skip_timer_updates)
        idleq_process_timeouts(ctx);
}

// Update idle_start for a connection, move to tail of list, adjust next
// timeout if applicable
F_NONNULL
static void idleq_refresh(tcpdns_conn_t* conn)
{
    tcpdns_thread_t* ctx = conn->ctx;
    gdnsd_assert(ctx);

    bool needs_timeouts = false;

    conn->idle_start = ev_now(ctx->loop);
    if (conn == ctx->idleq_head) {
        if (conn->next) {
            gdnsd_assert(conn != ctx->idleq_tail);
            ctx->idleq_head = conn->next;
        }
        needs_timeouts = true;
    }

    if (conn->next) {
        conn->next->prev = conn->prev;
        if (conn->prev)
            conn->prev->next = conn->next;
        conn->next = NULL;
        conn->prev = ctx->idleq_tail;
        ctx->idleq_tail->next = conn;
        ctx->idleq_tail = conn;
    }

    if (needs_timeouts)
        idleq_process_timeouts(ctx);
}

F_NONNULL
static void tcp_timeout_handler(struct ev_loop* loop V_UNUSED, ev_timer* t, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_TIMER);
    tcpdns_thread_t* ctx = t->data;
    gdnsd_assert(ctx);
    idleq_process_timeouts(ctx);
}

// Used by per-connection callbacks to close+destroy a singular conn
F_NONNULL
static void conn_close_and_destroy(tcpdns_conn_t* conn, bool clean, bool skip_timer_update)
{
    conn_close(conn, clean);
    idleq_remove(conn, skip_timer_update);
    free(conn);
}

F_NONNULL
static void stop_handler(struct ev_loop* loop, ev_async* w, int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_ASYNC);
    tcpdns_thread_t* ctx = w->data;
    gdnsd_assert(ctx);

    // Stop the accept() and stop-watchers
    ev_async* stop_watcher = &ctx->stop_watcher;
    ev_async_stop(loop, stop_watcher);
    ev_io* accept_watcher = &ctx->accept_watcher;
    ev_io_stop(loop, accept_watcher);

    // This flag informs the read handler that connections should be terminated
    // immediately on reaching the ST_IDLE state, for any that are still
    // outstanding in other states.  It also tells idleq_process_timeouts()
    // above to alter its behavior for the shutdown phase.
    ctx->shutting_down = true;

    // Walk the idle conns list and immediately destroy any in ST_IDLE,
    // telling the destructor not to process idleq timer updates yet (primarily
    // because it would potentially mutate this list while we're walking it,
    // but also for efficiency since we're going to call
    // idleq_process_timeouts() after the loop anyways).
    tcpdns_conn_t* conn = ctx->idleq_head;
    while (conn) {
        tcpdns_conn_t* next_conn = conn->next;
        if (conn->state == ST_IDLE) {
            log_debug("TCP DNS conn to %s closed by server (shutting down): while idle", logf_anysin(&conn->asin));
            stats_own_inc(&conn->ctx->stats->tcp.close_s_ok);
            conn_close_and_destroy(conn, true, true);
        }
        conn = next_conn;
    }

    // Now run the idle timeout updates
    idleq_process_timeouts(ctx);
}

F_NONNULL
static void tcp_write_handler(struct ev_loop* loop, ev_io* w, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_WRITE);

    tcpdns_conn_t* conn = w->data;
    ev_io* read_watcher = &conn->read_watcher;

    const size_t wanted = conn->size - conn->size_done;
    const uint8_t* source = conn->buffer + conn->size_done;

    const ssize_t send_rv = send(w->fd, source, wanted, 0);
    if (unlikely(send_rv < 0)) {
        if (!ERRNO_WOULDBLOCK) {
            log_debug("TCP DNS conn to %s closed by server: failed while writing: %s", logf_anysin(&conn->asin), logf_errno());
            stats_own_inc(&conn->ctx->stats->tcp.sendfail);
            stats_own_inc(&conn->ctx->stats->tcp.close_s_err);
            conn_close_and_destroy(conn, false, false);
            return;
        }
    } else { // we sent something...
        conn->size_done += (size_t)send_rv;
        if (likely(conn->size_done == conn->size)) {
            conn->state = ST_IDLE;
            if (conn->ctx->shutting_down) {
                log_debug("TCP DNS conn to %s closed by server (shutting down): while idle", logf_anysin(&conn->asin));
                stats_own_inc(&conn->ctx->stats->tcp.close_s_ok);
                conn_close_and_destroy(conn, true, false);
            } else {
                ev_io_stop(loop, w);
                ev_io_start(loop, read_watcher);
                conn->size_done = 0;
                conn->size = 0;
                idleq_refresh(conn);
            }
            return;
        }
    }

    // Start write watcher if necc
    ev_io* write_watcher = &conn->write_watcher;
    ev_io_start(loop, write_watcher);
}

F_NONNULL
static void tcp_read_handler(struct ev_loop* loop, ev_io* w, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_READ);
    tcpdns_conn_t* conn = w->data;

    gdnsd_assert(conn);
    gdnsd_assert(conn->state == ST_IDLE || conn->state == ST_READING);

    uint8_t* destination = &conn->buffer[conn->size_done];
    const size_t wanted =
        (conn->state == ST_IDLE ? (DNS_RECV_SIZE + 2) : conn->size)
        - conn->size_done;

    const ssize_t pktlen = recv(w->fd, destination, wanted, 0);
    if (pktlen < 1) {
        if (!pktlen) { // EOF
            if (conn->size_done) {
                log_debug("TCP DNS conn to %s closed by client while reading: unexpected EOF", logf_anysin(&conn->asin));
                stats_own_inc(&conn->ctx->stats->tcp.recvfail);
                stats_own_inc(&conn->ctx->stats->tcp.close_s_err);
                conn_close_and_destroy(conn, false, false);
            } else {
                log_debug("TCP DNS conn to %s closed by client while idle (ideal close)", logf_anysin(&conn->asin));
                stats_own_inc(&conn->ctx->stats->tcp.close_c);
                conn_close_and_destroy(conn, true, false);
            }
        } else if (!ERRNO_WOULDBLOCK) {
            log_debug("TCP DNS conn to %s closed by server while reading: error: %s", logf_anysin(&conn->asin), logf_errno());
            stats_own_inc(&conn->ctx->stats->tcp.recvfail);
            stats_own_inc(&conn->ctx->stats->tcp.close_s_err);
            conn_close_and_destroy(conn, false, false);
        }
        return;
    }

    conn->size_done += pktlen;

    if (likely(conn->state == ST_IDLE)) {
        if (likely(conn->size_done > 1)) {
            conn->size = ((unsigned)conn->buffer[0] << 8U) + (unsigned)conn->buffer[1] + 2U;
            if (unlikely(conn->size > DNS_RECV_SIZE)) {
                log_debug("TCP DNS conn to %s closed by server while reading: oversized query of length %u", logf_anysin(&conn->asin), conn->size);
                stats_own_inc(&conn->ctx->stats->tcp.recvfail);
                stats_own_inc(&conn->ctx->stats->tcp.close_s_err);
                conn_close_and_destroy(conn, false, false);
                return;
            }
            conn->state = ST_READING;
        }
    }

    if (unlikely(conn->size_done < conn->size))
        return;

    //  Process the query and start the writer
    if (!conn->ctx->rcu_is_online) {
        conn->ctx->rcu_is_online = true;
        rcu_thread_online();
    }
    conn->size = process_dns_query(conn->ctx->dnsp_ctx, conn->ctx->stats, &conn->asin, &conn->buffer[2], conn->size - 2, conn->ctx->edns0_keepalive);
    if (!conn->size) {
        log_debug("TCP DNS conn to %s closed by server: dropped invalid query", logf_anysin(&conn->asin));
        stats_own_inc(&conn->ctx->stats->tcp.close_s_err);
        conn_close_and_destroy(conn, false, false);
        return;
    }

    ev_io_stop(loop, w);
    conn->buffer[0] = (uint8_t)(conn->size >> 8U);
    conn->buffer[1] = (uint8_t)(conn->size & 0xFF);
    conn->size += 2;
    conn->size_done = 0;
    conn->state = ST_WRITING;

    // Most likely the response fits in the socket buffers
    //  as well as the window size, and therefore a complete
    //  write can proceed immediately, so try it without
    //  going through the loop.  tcp_write_handler() will
    //  start its own watcher if necc.
    ev_io* write_watcher = &conn->write_watcher;
    tcp_write_handler(loop, write_watcher, EV_WRITE);
}

F_NONNULL
static void accept_handler(struct ev_loop* loop, ev_io* w, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_READ);

    gdnsd_anysin_t asin;
    memset(&asin, 0, sizeof(asin));
    asin.len = GDNSD_ANYSIN_MAXLEN;

    const int sock = accept4(w->fd, &asin.sa, &asin.len, SOCK_NONBLOCK | SOCK_CLOEXEC);

    if (unlikely(sock < 0)) {
        switch (errno) {
        case EAGAIN:
#if EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
        case EINTR:
            break;
#ifdef ENONET
        case ENONET:
#endif
        case ENETDOWN:
#ifdef EPROTO
        case EPROTO:
#endif
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

    log_debug("Received TCP DNS connection from %s", logf_anysin(&asin));

    tcpdns_thread_t* ctx = w->data;
    stats_own_inc(&ctx->stats->tcp.conns);

    // buffer[0] is last element of struct, sized to max_response + 2.
    tcpdns_conn_t* conn = xcalloc(sizeof(*conn) + (gcfg->max_response + 2));
    memcpy(&conn->asin, &asin, sizeof(asin));

    conn->state = ST_IDLE;
    conn->ctx = ctx;
    idleq_append_tail(conn); // Insert at end of idleness list, updating tail

    ev_io* read_watcher = &conn->read_watcher;
    ev_io_init(read_watcher, tcp_read_handler, sock, EV_READ);
    ev_set_priority(read_watcher, 0);
    read_watcher->data = conn;
    ev_io_start(loop, read_watcher);

    ev_io* write_watcher = &conn->write_watcher;
    ev_io_init(write_watcher, tcp_write_handler, sock, EV_WRITE);
    ev_set_priority(write_watcher, 1);
    write_watcher->data = conn;

    // Even if TCP_DEFER_ACCEPT and SO_ACCEPTFILTER are both unavailable,
    // there's a chance that under load the request data from a legitimate
    // client already arrived before we processed the accept(), so
    // optimistically try to read() immediately and avoid a chance at this
    // connection being killed for idleness before its first read:
    tcp_read_handler(loop, &conn->read_watcher, EV_READ);
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

void tcp_dns_listen_setup(dns_thread_t* t)
{
    const dns_addr_t* addrconf = t->ac;
    gdnsd_assert(addrconf);

    const gdnsd_anysin_t* asin = &addrconf->addr;
    gdnsd_assert(asin);

    const bool isv6 = asin->sa.sa_family == AF_INET6 ? true : false;
    gdnsd_assert(isv6 || asin->sa.sa_family == AF_INET);

    bool need_bind = false;
    if (t->sock == -1) { // not acquired via takeover
        t->sock = socket(isv6 ? PF_INET6 : PF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, gdnsd_getproto_tcp());
        if (t->sock < 0)
            log_fatal("Failed to create IPv%c TCP socket: %s", isv6 ? '6' : '4', logf_errno());
        need_bind = true;
    }

    const int opt_one = 1;
    if (setsockopt(t->sock, SOL_SOCKET, SO_REUSEADDR, &opt_one, sizeof(opt_one)) == -1)
        log_fatal("Failed to set SO_REUSEADDR on TCP socket: %s", logf_errno());

    if (setsockopt(t->sock, SOL_SOCKET, SO_REUSEPORT, &opt_one, sizeof(opt_one)) == -1)
        log_fatal("Failed to set SO_REUSEPORT on TCP socket: %s", logf_errno());

#ifdef TCP_DEFER_ACCEPT
    const int opt_timeout = (int)addrconf->tcp_max_timeout;
    if (setsockopt(t->sock, SOL_TCP, TCP_DEFER_ACCEPT, &opt_timeout, sizeof(opt_timeout)) == -1)
        log_fatal("Failed to set TCP_DEFER_ACCEPT on TCP socket: %s", logf_errno());
#endif

#ifdef TCP_FASTOPEN
    const int opt_tfo = (int)addrconf->tcp_fastopen;
    if (opt_tfo) {
        if (setsockopt(t->sock, SOL_TCP, TCP_FASTOPEN, &opt_tfo, sizeof(opt_tfo)) == -1)
            log_fatal("Failed to set TCP_FASTOPEN to %i on TCP socket: %s", opt_tfo, logf_errno());
    }
#endif

    if (isv6) {
        // Guard IPV6_V6ONLY with a getsockopt(), because Linux fails here if a
        // socket is already bound (in which case we also should've already set
        // this in the previous daemon instance), because it affects how binding
        // works...
        int opt_v6o = 0;
        socklen_t opt_v6o_len = sizeof(opt_v6o);
        if (getsockopt(t->sock, SOL_IPV6, IPV6_V6ONLY, &opt_v6o, &opt_v6o_len) == -1)
            log_fatal("Failed to get IPV6_V6ONLY on TCP socket: %s", logf_errno());
        if (!opt_v6o)
            if (setsockopt(t->sock, SOL_IPV6, IPV6_V6ONLY, &opt_one, sizeof(opt_one)) == -1)
                log_fatal("Failed to set IPV6_V6ONLY on TCP socket: %s", logf_errno());
    }

    if (need_bind)
        socks_bind_sock("TCP DNS", t->sock, asin);
}

static void set_rcu_offline(struct ev_loop* loop V_UNUSED, ev_prepare* w V_UNUSED, int revents V_UNUSED)
{
    tcpdns_thread_t* ctx = w->data;
    if (ctx->rcu_is_online) {
        ctx->rcu_is_online = false;
        rcu_thread_offline();
    }
}

void* dnsio_tcp_start(void* thread_asvoid)
{
    gdnsd_thread_setname("gdnsd-io-tcp");

    const dns_thread_t* t = thread_asvoid;
    gdnsd_assert(!t->is_udp);

    const dns_addr_t* addrconf = t->ac;

    tcpdns_thread_t* ctx = xcalloc(sizeof(*ctx));
    register_thread(ctx);

    if (listen(t->sock, (int)addrconf->tcp_clients_per_thread) == -1)
        log_fatal("Failed to listen(s, %u) on TCP socket %s: %s", addrconf->tcp_clients_per_thread, logf_anysin(&addrconf->addr), logf_errno());

#ifdef SO_ACCEPTFILTER
    struct accept_filter_arg afa;
    memset(&afa, 0, sizeof(afa));
    strcpy(afa.af_name, "dnsready");
    if (setsockopt(t->sock, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa)))
        log_err("Failed to install 'dnsready' SO_ACCEPTFILTER on TCP socket %s: %s", logf_anysin(&addrconf->addr), logf_errno());
#endif

    ctx->dnsp_ctx = dnspacket_ctx_init(&ctx->stats, false);

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    ctx->max_timeout = addrconf->tcp_max_timeout;
    ctx->max_clients = addrconf->tcp_clients_per_thread;

    // cached pre-calculations based on the above two configured values:
    ctx->tmo_thresh75 = ctx->max_clients - (ctx->max_clients >> 2U);
    ctx->tmo_scaler = ((double)ctx->max_timeout - 2.0) / (double)ctx->tmo_thresh75;

    ev_io* accept_watcher = &ctx->accept_watcher;
    ev_io_init(accept_watcher, accept_handler, t->sock, EV_READ);
    ev_set_priority(accept_watcher, -2);
    accept_watcher->data = ctx;

    ev_timer* timeout_watcher = &ctx->timeout_watcher;
    ev_timer_init(timeout_watcher, tcp_timeout_handler, 0, ctx->max_timeout);
    ev_set_priority(timeout_watcher, -1);
    timeout_watcher->data = ctx;

    // per-conn read and write handlers occupy priorities 0 and 1, respectively

    ev_prepare* prep_watcher = &ctx->prep_watcher;
    ev_prepare_init(prep_watcher, set_rcu_offline);
    prep_watcher->data = ctx;

    ev_async* stop_watcher = &ctx->stop_watcher;
    ev_async_init(stop_watcher, stop_handler);
    ev_set_priority(stop_watcher, 2);
    stop_watcher->data = ctx;

    struct ev_loop* loop = ctx->loop = ev_loop_new(EVFLAG_AUTO);
    if (!loop)
        log_fatal("ev_loop_new() failed");

    ev_async_start(loop, stop_watcher);
    ev_io_start(loop, accept_watcher);
    ev_prepare_start(loop, prep_watcher);
    ev_unref(loop); // prepare should not hold a ref, but should run to the end

    rcu_register_thread();
    ctx->rcu_is_online = true;

    ev_run(loop, 0);

    rcu_unregister_thread();

    // de-allocate explicitly when debugging, for leaks
#ifndef NDEBUG
    ev_loop_destroy(loop);
    dnspacket_ctx_debug_cleanup(ctx->dnsp_ctx);
    free(ctx);
#endif

    return NULL;
}
