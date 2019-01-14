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
#include "proxy.h"

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
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <ev.h>
#include <urcu-qsbr.h>

typedef enum {
    ST_PROXY = 0,
    ST_IDLE,
    ST_READING,
} conn_state_t;

typedef enum {
    TH_RUN = 0,   // normal runtime operation
    TH_GRACE = 1, // initial 5s grace during shutdown
    TH_SHUT = 2,  // final 5s grace during shutdown
} thr_state_t;

struct conn;
typedef struct conn conn_t;

// per-thread state
typedef struct {
    // These pointers and values are fixed for the life of the thread:
    dnspacket_stats_t* stats;
    dnsp_ctx_t* pctx;
    struct ev_loop* loop;
    double server_timeout;
    unsigned max_clients;
    bool do_proxy;
    // The rest below will mutate:
    ev_io accept_watcher;
    ev_prepare prep_watcher;
    ev_async stop_watcher;
    ev_timer timeout_watcher;
    conn_t* connq_head; // doubly-linked-list, most-idle at head
    conn_t* connq_tail; // last element, least-idle
    unsigned num_conns; // count of all conns, also len of connq list
    thr_state_t st;
    bool rcu_is_online;
} thread_t;

// per-connection state
struct conn {
    conn_t* next; // doubly-linked-list
    conn_t* prev; // doubly-linked-list
    thread_t* thr;
    ev_io read_watcher;
    ev_tstamp idle_start;
    gdnsd_anysin_t asin;
    unsigned size;
    unsigned size_done;
    conn_state_t state;
    dso_state_t dso; // shared w/ dnspacket layer
    uint8_t buffer[MAX_RESPONSE_BUF + 2];
};

static pthread_mutex_t registry_lock = PTHREAD_MUTEX_INITIALIZER;
static thread_t** registry = NULL;
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
        thread_t* thr = registry[i];
        ev_async* stop_watcher = &thr->stop_watcher;
        ev_async_send(thr->loop, stop_watcher);
    }
}

F_NONNULL
static void register_thread(thread_t* thr)
{
    pthread_mutex_lock(&registry_lock);
    gdnsd_assert(registry_init < registry_size);
    registry[registry_init++] = thr;
    pthread_mutex_unlock(&registry_lock);
}

// This adjust the timer to the next connq_head expiry or stops it if no
// connections are left in the queue.
F_NONNULL
static void connq_adjust_timer(thread_t* thr)
{
    // Adjust timer event as approrpriate
    ev_timer* tmo = &thr->timeout_watcher;
    if (thr->connq_head) {
        // when in either shutdown phase, we do not update the timer, as we're
        // on a single fixed 5 second firing at this point, but we will stop it
        // below if the last connection dies and we've nothing left to do.
        if (likely(thr->st == TH_RUN)) {
            // 100ms floor/fudge factor
            ev_tstamp next_interval = thr->server_timeout + 0.1 - (ev_now(thr->loop) - thr->connq_head->idle_start);
            if (next_interval < 0.1)
                next_interval = 0.1;
            tmo->repeat = next_interval;
            ev_timer_again(thr->loop, tmo);
        }
    } else {
        gdnsd_assert(!thr->num_conns);
        ev_timer_stop(thr->loop, tmo);
    }
}

// Pull a connection out of the queue and adjust everything else for sanity.
// This could be to destroy it, or could be to move it to the tail.  Does not
// touch the value of the next or prev pointers of the conn, but does touch the
// neighbors reachable through them.
F_NONNULL
static void connq_pull_conn(thread_t* thr, conn_t* conn)
{
    gdnsd_assert(thr->num_conns);
    thr->num_conns--;

    if (conn->next) {
        gdnsd_assert(conn != thr->connq_tail);
        conn->next->prev = conn->prev;
    } else {
        gdnsd_assert(conn == thr->connq_tail);
        thr->connq_tail = conn->prev;
    }

    if (conn->prev) {
        gdnsd_assert(conn != thr->connq_head);
        conn->prev->next = conn->next;
    } else {
        gdnsd_assert(conn == thr->connq_head);
        thr->connq_head = conn->next;
        connq_adjust_timer(thr);
    }
}

// Closes the connection's fd and then takes care of all the follow-on state
// changes and cleanups.
F_NONNULL
static void connq_destruct_conn(thread_t* thr, conn_t* conn, const bool rst, const bool manage_queue)
{
    gdnsd_assert(thr->num_conns);

    ev_io* read_watcher = &conn->read_watcher;
    ev_io_stop(thr->loop, read_watcher);

    const int fd = read_watcher->fd;
    if (rst) {
        // A real error or timeout happened and we explicitly desire to cause a RST if we can
        const struct linger lin = { .l_onoff = 1, .l_linger = 0 };
        if (setsockopt(read_watcher->fd, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin)))
            log_err("setsockopt(%s, SO_LINGER, {1, 0}) failed: %s", logf_anysin(&conn->asin), logf_errno());
    }
    if (close(fd))
        log_err("close(%s) failed: %s", logf_anysin(&conn->asin), logf_errno());

    if (manage_queue)
        connq_pull_conn(thr, conn);
    free(conn);
}

// Append a new connection at the tail of the idle list and set its idle_start
F_NONNULL
static void connq_append_new_conn(thread_t* thr, conn_t* conn)
{
    // This element is not part of the linked list yet
    gdnsd_assert(thr->connq_head != conn);
    gdnsd_assert(thr->connq_tail != conn);
    gdnsd_assert(!conn->next);
    gdnsd_assert(!conn->prev);

    // accept() handler is gone when in either shutdown phase
    gdnsd_assert(thr->st == TH_RUN);

    conn->idle_start = ev_now(thr->loop);
    thr->num_conns++;

    // If there's no existing head, the conn list was empty before this one, so
    // it's a very simple case to handle:
    if (!thr->connq_head) {
        gdnsd_assert(thr->num_conns == 1);
        gdnsd_assert(!thr->connq_tail);
        thr->connq_head = thr->connq_tail = conn;
        connq_adjust_timer(thr);
        return;
    }

    // Otherwise we append to the tail of the list
    gdnsd_assert(thr->connq_tail);
    gdnsd_assert(!thr->connq_tail->next);
    conn->prev = thr->connq_tail;
    conn->next = NULL;
    thr->connq_tail->next = conn;
    thr->connq_tail = conn;

    // and then if we've just maxed out the connection count, we have to kill a conn
    if (thr->num_conns == thr->max_clients) {
        log_debug("TCP DNS conn from %s reset by server: killed due to thread connection load (most-idle)", logf_anysin(&thr->connq_head->asin));
        stats_own_inc(&conn->thr->stats->tcp.close_s_kill);
        connq_destruct_conn(thr, thr->connq_head, true, true);
    }
}

// Called when a connection completes a transaction (reads a legit request, and
// writes the full response to the TCP layer) and returns to its
// inter-transaction ST_IDLE state, causing us to reset its idle timeout state
F_NONNULL
static void connq_refresh_conn(thread_t* thr, conn_t* conn)
{
    gdnsd_assert(conn->state == ST_IDLE);
    conn->idle_start = ev_now(thr->loop);

    // If this is the only connection, just adjust the timer
    if (thr->num_conns == 1) {
        gdnsd_assert(conn == thr->connq_head);
        gdnsd_assert(conn == thr->connq_tail);
        connq_adjust_timer(thr);
        return;
    }

    // If we're already at the tail, nothing left to do
    if (conn == thr->connq_tail)
        return;

    // Otherwise, pull it (which will adjust timer if the conn pulled was the
    // head) and place it at the tail
    connq_pull_conn(thr, conn);
    conn->prev = thr->connq_tail;
    conn->next = NULL;
    thr->connq_tail->next = conn;
    thr->connq_tail = conn;
    thr->num_conns++; // connq_pull_conn decrements, but we're re-inserting here
}

F_NONNULL
static void timeout_handler(struct ev_loop* loop V_UNUSED, ev_timer* t, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_TIMER);
    thread_t* thr = t->data;
    gdnsd_assert(thr);
    gdnsd_assert(thr->num_conns <= thr->max_clients);

    // In all cases (even final 5s shutdown timers), if the connection count
    // drops to zero the timer gets stopped, so we always should have one or
    // more connections if this timer callback fires at all:
    gdnsd_assert(thr->num_conns);
    gdnsd_assert(thr->connq_head);

    conn_t* conn = thr->connq_head;

    // End of the 5s final shutdown phase: immediately close all connections and let the thread exit
    if (unlikely(thr->st == TH_SHUT)) {
        log_debug("TCP DNS thread shutdown: immediately dropping (RST) %u delinquent connections while exiting", thr->num_conns);
        while (conn) {
            conn_t* next_conn = conn->next;
            connq_destruct_conn(thr, conn, true, false); // no queue mgmt
            stats_own_inc(&thr->stats->tcp.close_s_err);
            conn = next_conn;
        }
        // Stop ourselves, we should be the only remaining active watcher
        ev_timer* tmo = &thr->timeout_watcher;
        ev_timer_stop(thr->loop, tmo);
        // Once we return here the eventloop will drop out of ev_run and the
        // whole thread will do final cleanup and exit, so these values don't
        // matter, but may as well set them correctly for debugging and/or
        // general sanity.
        thr->connq_head = NULL;
        thr->connq_tail = NULL;
        thr->num_conns = 0;
        return;
    }

    // End of the 5s graceful shutdown phase: set st = TH_SHUT for the above
    // block, ask clients to close (server sends DSO RD or FIN), and start
    // another fixed 5s timer invocation to come back and hit the above.
    if (unlikely(thr->st == TH_GRACE)) {
        log_debug("TCP DNS thread shutdown: demanding clients to close %u remaining conns immediatley and waiting up to 5s", thr->num_conns);
        thr->st = TH_SHUT;
        while (conn) {
            conn_t* next_conn = conn->next;
            // Reset all states to ST_IDLE to avoid confusion.  They should
            // mostly be there anyways, unless they're stuck in ST_READING with
            // a half-completed read of a request, in which case we no longer
            // case about responding to it anyways.
            conn->state = ST_IDLE;
            if (conn->dso.estab) {
                // send unidirectional RetryDelay, could destroy conn if cannot send
            } else {
                shutdown(conn->read_watcher.fd, SHUT_WR);
            }
            conn = next_conn;
        }
        ev_timer* tmo = &thr->timeout_watcher;
        tmo->repeat = 5.0;
        ev_timer_again(thr->loop, tmo);
        return;
    }

    // If not at the end of either shutdown phase, this is just normal runtime
    // connection timeout expiry handling:

    // Server-side cutoff timestamp is server_timeout in the past
    const double cutoff = ev_now(thr->loop) - thr->server_timeout;

    // Expire from head of idle list until we find an unexpired one (if any)
    while (conn && conn->idle_start <= cutoff) {
        conn_t* next_conn = conn->next;
        log_debug("TCP DNS conn from %s reset by server: timeout", logf_anysin(&conn->asin));
        stats_own_inc(&conn->thr->stats->tcp.close_s_ok);
        // Note final "manage_queue" argument is false.  We adjust the queue
        // pointers and the timer at the bottom here in a very simple way once,
        // instead of the full generic adjustments per loop iteration, since
        // we're pulling only from the front of the queue.
        connq_destruct_conn(thr, conn, true, false);
        thr->num_conns--;
        conn = next_conn;
    }

    if (!conn) {
        gdnsd_assert(!thr->num_conns);
        thr->connq_head = thr->connq_tail = NULL;
    } else {
        gdnsd_assert(thr->num_conns);
        thr->connq_head = conn;
    }

    connq_adjust_timer(thr);
}

F_NONNULL
static void stop_handler(struct ev_loop* loop, ev_async* w, int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_ASYNC);
    thread_t* thr = w->data;
    gdnsd_assert(thr);
    gdnsd_assert(thr->st == TH_RUN); // this handler stops itself and transitions out of TH_RUN

    // Stop the accept() watcher and the async watcher for this stop handler
    ev_async* stop_watcher = &thr->stop_watcher;
    ev_async_stop(loop, stop_watcher);
    ev_io* accept_watcher = &thr->accept_watcher;
    ev_io_stop(loop, accept_watcher);

    // If there are no active connections, the thread's timeout watcher should
    // be inactive as well, and so the two watchers we stopped above were the
    // only ones keeping the loop running, and we can just return now without
    // going through all our graceful behaviors for live connections.
    if (!thr->num_conns) {
        ev_timer* tw V_UNUSED = &thr->timeout_watcher;
        gdnsd_assert(!ev_is_active(tw));
        gdnsd_assert(!thr->connq_head);
        gdnsd_assert(!thr->connq_tail);
        return;
    }

    log_debug("TCP DNS thread shutdown: gracefully requesting clients to close %u remaining conns when able and waiting up to 5s", thr->num_conns);

    // Switch thread state to the initial graceful shutdown phase
    thr->st = TH_GRACE;

    // Inform dnspacket layer that future EDNS TCP Keepalive responses and DSO
    // Keepalive responses should report zero:
    dnspacket_ctx_set_grace(thr->pctx);

    // Following from the above about eventloop watchers, In general, from this
    // point forward only the per-connection watchers and the timeout watcher
    // are keeping the eventloop running, so if all connections end, any
    // running timer will be stopped and there will be no events left (so e.g.
    // it's possible for the thread to exit 0.1 seconds into the initial
    // 5s grace period and never even reach the final 5s shutdown phase, if all
    // clients happen to drop off nicely).

    // send unidirectional KeepAlive w/ inactivity=0 to all DSO clients
    conn_t* conn = thr->connq_head;
    gdnsd_assert(conn);
    while (conn) {
        if (conn->dso.estab) {
            // send unidirectional KeepAlive w/ inactivity=0, could destroy conn if cannot send
        }
        conn = conn->next;
    }

    // Up until now, the timeout watcher was firing dynamically according to
    // server timeout and connection idleness refreshes, always pointing at
    // the idleness expiry point of the head-most (most-idle) connection in the
    // queue.  Now it is reset to fire once 5 seconds from now to transition
    // from TH_GRACE to TH_SHUT and wait another 5 seconds there before
    // exiting.
    // Technically by the DSO spec, we should allow our configured client-side
    // timer divided by four for this window (from the time each connection was
    // last active), but that could be as high as 7.5 minutes, which is
    // unreasonable for stopping a server instance.
    ev_timer* tmo = &thr->timeout_watcher;
    tmo->repeat = 5.0;
    ev_timer_again(thr->loop, tmo);
}

// rv true means caller should return immediately (connection closed or read is
// incomplete and needs to block in the loop again)
F_NONNULL
static bool conn_do_read(thread_t* thr, conn_t* conn)
{
    gdnsd_assert(conn->state != ST_PROXY); // PROXY protocol parser doesn't use conn_do_read()
    uint8_t* destination = &conn->buffer[conn->size_done];
    const size_t wanted = conn->size - conn->size_done;

    const ssize_t pktlen = recv(conn->read_watcher.fd, destination, wanted, 0);
    if (pktlen < 1) {
        if (!pktlen) { // EOF
            if (conn->size_done) {
                log_debug("TCP DNS conn from %s closed by client while reading: unexpected EOF", logf_anysin(&conn->asin));
                stats_own_inc(&thr->stats->tcp.recvfail);
                stats_own_inc(&thr->stats->tcp.close_s_err);
            } else {
                gdnsd_assert(conn->state == ST_IDLE);
                if (unlikely(thr->st == TH_SHUT)) {
                    if (conn->dso.estab) {
                        log_debug("TCP DNS conn from %s closed by client while shutting down after DSO RetryDelay", logf_anysin(&conn->asin));
                        stats_own_inc(&thr->stats->tcp.close_c);
                    } else {
                        log_debug("TCP DNS conn from %s closed by client while shutting down after server half-close", logf_anysin(&conn->asin));
                        stats_own_inc(&thr->stats->tcp.close_s_ok);
                    }
                } else {
                    log_debug("TCP DNS conn from %s closed by client while idle (ideal close)", logf_anysin(&conn->asin));
                    stats_own_inc(&thr->stats->tcp.close_c);
                }
            }
            connq_destruct_conn(thr, conn, false, true);
        } else if (!ERRNO_WOULDBLOCK) {
            log_debug("TCP DNS conn from %s reset by server: error while reading: %s", logf_anysin(&conn->asin), logf_errno());
            stats_own_inc(&thr->stats->tcp.recvfail);
            stats_own_inc(&thr->stats->tcp.close_s_err);
            connq_destruct_conn(thr, conn, true, true);
        }
        return true;
    }

    conn->size_done += pktlen;
    if (unlikely(conn->size_done < conn->size))
        return true;

    return false;
}

F_NONNULL
static void read_handler(struct ev_loop* loop V_UNUSED, ev_io* w, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_READ);
    conn_t* conn = w->data;
    gdnsd_assert(conn);
    thread_t* thr = conn->thr;
    gdnsd_assert(thr);

    gdnsd_assert(conn);

    // TH_SHUT means we already sent FIN via shutdown(), or in the
    // case of DSO have already sent a RetryDelay unidirectional packet, and
    // we're just trying to drain the read buffer and cleanly reach the
    // client's FIN before our final 5s timer expires.  If conn_do_read()
    // reaches an error state or a client close, it will take care of
    // connection cleanup.
    if (unlikely(thr->st == TH_SHUT)) {
        conn->size = sizeof(conn->buffer);
        conn->size_done = 0;
        (void)conn_do_read(thr, conn);
        return;
    }

    if (conn->state == ST_PROXY) {
        const int pp = parse_proxy(conn->read_watcher.fd, &conn->asin);
        if (unlikely(pp)) {
            if (pp == -1) {
                log_debug("PROXY parse fail from %s, resetting connection", logf_anysin(&conn->asin));
                stats_own_inc(&thr->stats->tcp.proxy_fail);
                stats_own_inc(&thr->stats->tcp.close_s_err);
                connq_destruct_conn(thr, conn, true, true);
            }
            return;
        }
        conn->state = ST_IDLE;
    }

    if (conn->state == ST_IDLE) {
        conn->size = 2U;
        gdnsd_assert(conn->size_done < conn->size);
        if (conn_do_read(thr, conn))
            return;
        gdnsd_assert(conn->size_done == 2U);

        conn->size += (((unsigned)conn->buffer[0] << 8U) + (unsigned)conn->buffer[1]);
        if (unlikely(conn->size < (12U + 2U) || conn->size > (DNS_RECV_SIZE + 2U))) {
            log_debug("TCP DNS conn from %s reset by server while reading: bad query length %u", logf_anysin(&conn->asin), conn->size - 2U);
            stats_own_inc(&thr->stats->tcp.recvfail);
            stats_own_inc(&thr->stats->tcp.close_s_err);
            connq_destruct_conn(thr, conn, true, true);
            return;
        }
        conn->state = ST_READING;
    }

    if (conn_do_read(thr, conn))
        return;

    // Process the query and write a response
    gdnsd_assert(conn->size_done == conn->size);

    if (!thr->rcu_is_online) {
        thr->rcu_is_online = true;
        rcu_thread_online();
    }

    conn->dso.last_was_ka = false;
    conn->size = process_dns_query(thr->pctx, &conn->asin, &conn->buffer[2], &conn->dso, conn->size - 2U);
    if (!conn->size) {
        log_debug("TCP DNS conn from %s reset by server: dropped invalid query", logf_anysin(&conn->asin));
        stats_own_inc(&thr->stats->tcp.close_s_err);
        connq_destruct_conn(thr, conn, true, true);
        return;
    }

    // Set the response size as the 2 byte TCP length prefix for the data
    conn->buffer[0] = (uint8_t)(conn->size >> 8U);
    conn->buffer[1] = (uint8_t)(conn->size & 0xFF);
    conn->size += 2U;

    // We only make a single attempt to send the whole response, right here
    // from the same callback that finished receiving the full request, and the
    // TCP stack must accept the whole thing immediately or we give up on the
    // connection and RST.  We could (and have in the past) actually allow
    // blocking and returning to the eventloop here and handle things more
    // gracefully if the outbound buffers/tcp-windows are full, and it would be
    // more "correct" in some abstract sense.  However, it adds complexity and
    // new failure modes (and critically, doesn't always allow the sending of
    // unidrectional DSO messages at any moment), and the bottom line is a
    // reasonable client shouldn't be stuffing requests at us so fast that its
    // own TCP receive window and/or our reasonable server-side output buffers
    // can't handle the responses.
    const ssize_t send_rv = send(w->fd, conn->buffer, conn->size, 0);
    if (unlikely(send_rv < conn->size)) {
        if (send_rv < 0 && !ERRNO_WOULDBLOCK)
            log_debug("TCP DNS conn from %s reset by server: failed while writing: %s", logf_anysin(&conn->asin), logf_errno());
        else
            log_debug("TCP DNS conn from %s reset by server: cannot buffer whole response", logf_anysin(&conn->asin));
        stats_own_inc(&thr->stats->tcp.sendfail);
        stats_own_inc(&thr->stats->tcp.close_s_err);
        connq_destruct_conn(thr, conn, true, true);
        return;
    }

    // Back to ST_IDLE to listen for another request
    conn->state = ST_IDLE;
    conn->size_done = 0;
    conn->size = 0;

    // We don't refresh the timeout or mutate the queue if this transaction was just a DSO keepalive
    if (!conn->dso.last_was_ka)
        connq_refresh_conn(thr, conn);
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

    thread_t* thr = w->data;

    conn_t* conn = xcalloc(sizeof(*conn));
    memcpy(&conn->asin, &asin, sizeof(asin));

    stats_own_inc(&thr->stats->tcp.conns);
    if (thr->do_proxy) {
        stats_own_inc(&thr->stats->tcp.proxy);
        conn->state = ST_PROXY;
    } else {
        conn->state = ST_IDLE;
    }

    conn->thr = thr;
    connq_append_new_conn(thr, conn);

    ev_io* read_watcher = &conn->read_watcher;
    ev_io_init(read_watcher, read_handler, sock, EV_READ);
    ev_set_priority(read_watcher, 0);
    read_watcher->data = conn;
    ev_io_start(loop, read_watcher);

    // Even if TCP_DEFER_ACCEPT and SO_ACCEPTFILTER are both unavailable,
    // there's a chance that under load the request data from a legitimate
    // client already arrived before we processed the accept(), so
    // optimistically try to read() immediately and avoid a chance at this
    // connection being killed for idleness before its first read:
    read_handler(loop, &conn->read_watcher, EV_READ);
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
    if (t->sock == -1) { // not acquired via replace
        t->sock = socket(isv6 ? PF_INET6 : PF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
        if (t->sock < 0)
            log_fatal("Failed to create IPv%c TCP socket: %s", isv6 ? '6' : '4', logf_errno());
        need_bind = true;
    }

    sockopt_bool_fatal(TCP, asin, t->sock, SOL_SOCKET, SO_REUSEADDR, 1);
    sockopt_bool_fatal(TCP, asin, t->sock, SOL_SOCKET, SO_REUSEPORT, 1);

    sockopt_bool_fatal(TCP, asin, t->sock, SOL_TCP, TCP_NODELAY, 1);

#ifdef TCP_DEFER_ACCEPT
    // Clamp TCP_DEFER_ACCEPT timeout to no more than 30s
    int defaccept_timeout = (int)addrconf->tcp_timeout;
    if (defaccept_timeout > 30)
        defaccept_timeout = 30;
    sockopt_int_fatal(TCP, asin, t->sock, SOL_TCP, TCP_DEFER_ACCEPT, defaccept_timeout);
#endif

#ifdef TCP_FASTOPEN
    // This is non-fatal for now because many OSes may require tuning/config to
    // allow this to work, but we do want to default it on in cases where it
    // works out of the box correctly.
    sockopt_int_warn(TCP, asin, t->sock, SOL_TCP, TCP_FASTOPEN, (int)addrconf->tcp_fastopen);
#endif

    if (isv6) {
        sockopt_bool_fatal(TCP, asin, t->sock, SOL_IPV6, IPV6_V6ONLY, 1);

        // as with our default max_edns_response_v6, assume minimum MTU only to
        // avoid IPv6 mtu/frag loss issues.  Clamping to min mtu should
        // commonly set MSS to 1220.
#if defined IPV6_USE_MIN_MTU
        sockopt_bool_fatal(TCP, asin, t->sock, SOL_IPV6, IPV6_USE_MIN_MTU, 1);
#elif defined IPV6_MTU
#  ifndef IPV6_MIN_MTU
#    define IPV6_MIN_MTU 1280
#  endif
        // This sockopt doesn't have matching get+set; get needs a live
        // connection and reports the connection's path MTU, so we have to just
        // set it here blindly...
        const int min_mtu = IPV6_MIN_MTU;
        if (setsockopt(t->sock, SOL_IPV6, IPV6_MTU, &min_mtu, sizeof(min_mtu)) == -1)
            log_fatal("Failed to set IPV6_MTU on TCP socket: %s", logf_errno());
#endif
    }

    if (need_bind)
        socks_bind_sock("TCP DNS", t->sock, asin);
}

static void set_rcu_offline(struct ev_loop* loop V_UNUSED, ev_prepare* w V_UNUSED, int revents V_UNUSED)
{
    thread_t* thr = w->data;
    if (thr->rcu_is_online) {
        thr->rcu_is_online = false;
        rcu_thread_offline();
    }
}

static void set_accf(const dns_addr_t* addrconf V_UNUSED, const int sock V_UNUSED)
{
#ifdef SO_ACCEPTFILTER
    struct accept_filter_arg afa_exist;
    struct accept_filter_arg afa_want;
    socklen_t afa_exist_size = sizeof(afa_exist);
    memset(&afa_exist, 0, sizeof(afa_exist));
    memset(&afa_want, 0, sizeof(afa_want));
    strcpy(afa_want.af_name, addrconf->tcp_proxy ? "dataready" : "dnsready");

    const int getrv = getsockopt(sock, SOL_SOCKET, SO_ACCEPTFILTER, &afa_exist, &afa_exist_size);
    if (getrv && errno != EINVAL) {
        // If no existing filter is installed (or not listening), the retval is
        // EINVAL, but any other weird error should log and stop related option
        // processing here
        log_err("Failed to get current SO_ACCEPTFILTER on TCP socket %s: %s",
                logf_anysin(&addrconf->addr), logf_errno());
    } else {
        // If getsockopt failed with EINVAL we're in a fresh state, so just
        // install the desired filter.  If getsockopt succeeded and the filter
        // didn't match, we'll need to first clear the existing filter out
        if (getrv || afa_exist_size != sizeof(afa_want) || memcmp(&afa_want, &afa_exist, sizeof(afa_want))) {
            if (!getrv)
                if (setsockopt(sock, SOL_SOCKET, SO_ACCEPTFILTER, NULL, 0))
                    log_err("Failed to clear existing '%s' SO_ACCEPTFILTER on TCP socket %s: %s", afa_exist.af_name, logf_anysin(&addrconf->addr), logf_errno());
            if (setsockopt(sock, SOL_SOCKET, SO_ACCEPTFILTER, &afa_want, sizeof(afa_want))) {
                log_err("Failed to install '%s' SO_ACCEPTFILTER on TCP socket %s: %s", afa_want.af_name, logf_anysin(&addrconf->addr), logf_errno());
                // If we failed at "dnsready" for the non-proxy case, try
                // "dataready" just in case that one happens to be loaded;
                // it's better than nothing and matches what we get on Linux
                // with just TCP_DEFER_ACCEPT
                if (!addrconf->tcp_proxy) {
                    strcpy(afa_want.af_name, "dataready");
                    if (setsockopt(sock, SOL_SOCKET, SO_ACCEPTFILTER, &afa_want, sizeof(afa_want)))
                        log_err("Failed to install '%s' SO_ACCEPTFILTER on TCP socket %s: %s", afa_want.af_name, logf_anysin(&addrconf->addr), logf_errno());
                }
            }
        }
    }
#endif
}

void* dnsio_tcp_start(void* thread_asvoid)
{
    gdnsd_thread_setname("gdnsd-io-tcp");

    const dns_thread_t* t = thread_asvoid;
    gdnsd_assert(!t->is_udp);

    const dns_addr_t* addrconf = t->ac;

    thread_t* thr = xcalloc(sizeof(*thr));

    const int backlog = (int)(addrconf->tcp_backlog ? addrconf->tcp_backlog : SOMAXCONN);
    if (listen(t->sock, backlog) == -1)
        log_fatal("Failed to listen(s, %i) on TCP socket %s: %s", backlog, logf_anysin(&addrconf->addr), logf_errno());

    set_accf(addrconf, t->sock);

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    // These are fixed values for the life of the thread based on config:
    thr->server_timeout = (double)(addrconf->tcp_timeout * 2);
    thr->max_clients = addrconf->tcp_clients_per_thread;
    thr->do_proxy = addrconf->tcp_proxy;

    ev_io* accept_watcher = &thr->accept_watcher;
    ev_io_init(accept_watcher, accept_handler, t->sock, EV_READ);
    ev_set_priority(accept_watcher, -2);
    accept_watcher->data = thr;

    ev_timer* timeout_watcher = &thr->timeout_watcher;
    ev_timer_init(timeout_watcher, timeout_handler, 0, thr->server_timeout);
    ev_set_priority(timeout_watcher, -1);
    timeout_watcher->data = thr;

    // per-conn read watcher occupies priority 0 (default)

    ev_prepare* prep_watcher = &thr->prep_watcher;
    ev_prepare_init(prep_watcher, set_rcu_offline);
    prep_watcher->data = thr;

    ev_async* stop_watcher = &thr->stop_watcher;
    ev_async_init(stop_watcher, stop_handler);
    ev_set_priority(stop_watcher, 2);
    stop_watcher->data = thr;

    struct ev_loop* loop = thr->loop = ev_loop_new(EVFLAG_AUTO);
    if (!loop)
        log_fatal("ev_loop_new() failed");

    ev_async_start(loop, stop_watcher);
    ev_io_start(loop, accept_watcher);
    ev_prepare_start(loop, prep_watcher);
    ev_unref(loop); // prepare should not hold a ref, but should run to the end

    // register_thread() hooks us into the ev_async-based shutdown-handling
    // code, therefore we must have thr->loop and thr->stop_watcher initialized
    // and ready before we register here
    register_thread(thr);

    // dnspacket_ctx_init() is what releases threads through the startup gates,
    // and main.c's call to dnspacket_wait_stats() waits for all threads to
    // have reached this point before entering the main runtime loop.
    // Therefore, this must happen after register_thread() above, to ensure
    // that all tcp threads are properly registered with the shutdown handler
    // before we begin processing possible future shutdown events.
    thr->pctx = dnspacket_ctx_init_tcp(&thr->stats, addrconf->tcp_pad, addrconf->tcp_timeout);

    rcu_register_thread();
    thr->rcu_is_online = true;

    ev_run(loop, 0);

    rcu_unregister_thread();

    ev_loop_destroy(loop);
    dnspacket_ctx_cleanup(thr->pctx);
    free(thr);

    return NULL;
}
