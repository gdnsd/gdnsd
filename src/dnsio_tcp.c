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
#include <sys/uio.h>

#include <ev.h>
#include <urcu-qsbr.h>

// libev prio map:
// +2: thread async stop watcher (highest prio)
// +1: conn check/read watchers (only 1 per conn active at any time)
//  0: thread timeout watcher
// -1: thread accept watcher
// -2: thread idle watcher (lowest prio)

// Size of our read buffer.  We always attempt filling it on a read if TCP
// buffers have anything avail, and then drain all full requests from it and
// move any remaining partial request to the bottom before reading again.
#define TCP_READBUF 4096U
#if __STDC_VERSION__ >= 201112L // C11
_Static_assert(TCP_READBUF >= (DNS_RECV_SIZE + 2U), "TCP readbuf fits >= 1 maximal req");
#endif

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
    size_t max_clients;
    bool do_proxy;
    // The rest below will mutate:
    ev_io accept_watcher;
    ev_prepare prep_watcher;
    ev_idle idle_watcher;
    ev_async stop_watcher;
    ev_timer timeout_watcher;
    conn_t* connq_head; // doubly-linked-list, most-idle at head
    conn_t* connq_tail; // last element, least-idle
    size_t num_conns; // count of all conns, also len of connq list
    size_t check_mode_conns; // conns using check_watcher at present
    thr_state_t st;
    bool rcu_is_online;
} thread_t;

// per-connection state
struct conn {
    conn_t* next; // doubly-linked-list
    conn_t* prev; // doubly-linked-list
    thread_t* thr;
    ev_io read_watcher;
    ev_check check_watcher;
    ev_tstamp idle_start;
    gdnsd_anysin_t sa;
    bool need_proxy_init;
    dso_state_t dso; // shared w/ dnspacket layer
    size_t readbuf_head;
    size_t readbuf_bytes;
    union {
        proxy_hdr_t proxy_hdr;
        uint8_t readbuf[TCP_READBUF];
    };
    // These two must be adjacent, as a single send() points at them as if
    // they're one buffer.  This should be portable since uint8_t can't require
    // alignment padding after a uint16_t.
    uint16_t pktbuf_size_hdr;
    uint8_t pktbuf[MAX_RESPONSE_BUF];
};

static pthread_mutex_t registry_lock = PTHREAD_MUTEX_INITIALIZER;
static thread_t** registry = NULL;
static size_t registry_size = 0;
static size_t registry_init = 0;

void dnsio_tcp_init(size_t num_threads)
{
    registry_size = num_threads;
    registry = xcalloc_n(registry_size, sizeof(*registry));
}

void dnsio_tcp_request_threads_stop(void)
{
    gdnsd_assert(registry_size == registry_init);
    for (size_t i = 0; i < registry_init; i++) {
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

// Assert all the things we assume about connection tracking sanity.  They're
// not always true while things are under manipulation, but they should all be
// true once a given set of manipulations are complete.
F_NONNULL
static void connq_assert_sane(thread_t* thr V_UNUSED)
{
    if (!thr->num_conns) {
        gdnsd_assert(!thr->connq_head);
        gdnsd_assert(!thr->connq_tail);
    } else {
        gdnsd_assert(thr->num_conns <= thr->max_clients);
        gdnsd_assert(thr->connq_head);
        gdnsd_assert(thr->connq_tail);
        gdnsd_assert(!thr->connq_head->prev);
        gdnsd_assert(!thr->connq_tail->next);
#ifndef NDEBUG
        size_t ct = 0;
        conn_t* c = thr->connq_head;
        while (c) {
            ct++;
            if (c != thr->connq_tail)
                gdnsd_assert(c->next);
            if (c != thr->connq_head)
                gdnsd_assert(c->prev);
            c = c->next;
        }
        gdnsd_assert(ct == thr->num_conns);
#endif
    }
}

// This adjust the timer to the next connq_head expiry or stops it if no
// connections are left in the queue. when in either shutdown phase, we do not
// update the timer, but we will stop it.  There is a 100ms floor/fudge factor
F_NONNULL
static void connq_adjust_timer(thread_t* thr)
{
    connq_assert_sane(thr);
    ev_timer* tmo = &thr->timeout_watcher;
    if (thr->connq_head) {
        if (likely(thr->st == TH_RUN)) {
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
    connq_assert_sane(thr);
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
    connq_assert_sane(thr);
}

// Closes and destroys a connection, and optionally manages it out of the queue
F_NONNULL
static void connq_destruct_conn(thread_t* thr, conn_t* conn, const bool rst, const bool manage_queue)
{
    gdnsd_assert(thr->num_conns);

    ev_io* read_watcher = &conn->read_watcher;
    ev_io_stop(thr->loop, read_watcher);
    ev_check* check_watcher = &conn->check_watcher;
    ev_check_stop(thr->loop, check_watcher);

    const int fd = read_watcher->fd;
    if (rst) {
        const struct linger lin = { .l_onoff = 1, .l_linger = 0 };
        if (setsockopt(read_watcher->fd, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin)))
            log_err("setsockopt(%s, SO_LINGER, {1, 0}) failed: %s", logf_anysin(&conn->sa), logf_errno());
    }
    if (close(fd))
        log_err("close(%s) failed: %s", logf_anysin(&conn->sa), logf_errno());

    if (manage_queue)
        connq_pull_conn(thr, conn);
    free(conn);
}

// Append a new connection at the tail of the idle list and set its idle_start
F_NONNULL
static void connq_append_new_conn(thread_t* thr, conn_t* conn)
{
    connq_assert_sane(thr);
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

    connq_assert_sane(thr);

    // and then if we've just maxed out the connection count, we have to kill a conn
    if (thr->num_conns == thr->max_clients) {
        log_debug("TCP DNS conn from %s reset by server: killed due to thread connection load (most-idle)", logf_anysin(&thr->connq_head->sa));
        stats_own_inc(&conn->thr->stats->tcp.close_s_kill);
        connq_destruct_conn(thr, thr->connq_head, true, true);
    }
}

// Called when a connection completes a transaction (reads a legit request, and
// writes the full response to the TCP layer), causing us to reset its idleness
F_NONNULL
static void connq_refresh_conn(thread_t* thr, conn_t* conn)
{
    connq_assert_sane(thr);
    gdnsd_assert(!conn->need_proxy_init);
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
    connq_assert_sane(thr);
}

F_NONNULL
static void timeout_handler(struct ev_loop* loop V_UNUSED, ev_timer* t, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_TIMER);
    thread_t* thr = t->data;
    gdnsd_assert(thr);
    connq_assert_sane(thr);

    // Timer never fires unless there are connections, in all cases
    conn_t* conn = thr->connq_head;
    gdnsd_assert(conn);

    // End of the 5s final shutdown phase: immediately close all connections and let the thread exit
    if (unlikely(thr->st == TH_SHUT)) {
        log_debug("TCP DNS thread shutdown: immediately dropping (RST) %zu delinquent connections while exiting", thr->num_conns);
        while (conn) {
            conn_t* next_conn = conn->next;
            connq_destruct_conn(thr, conn, true, false); // no queue mgmt
            stats_own_inc(&thr->stats->tcp.close_s_err);
            conn = next_conn;
        }
        // Stop ourselves, we should be the only remaining active watcher
        ev_timer* tmo = &thr->timeout_watcher;
        ev_timer_stop(thr->loop, tmo);
        thr->connq_head = NULL;
        thr->connq_tail = NULL;
        thr->num_conns = 0;
        return; // eventloop will end now, and shortly after the whole thread
    }

    // End of the 5s graceful phase (start 5s shutdown phase)
    if (unlikely(thr->st == TH_GRACE)) {
        log_debug("TCP DNS thread shutdown: demanding clients to close %zu remaining conns immediatley and waiting up to 5s", thr->num_conns);
        thr->st = TH_SHUT;
        while (conn) {
            conn_t* next_conn = conn->next;
            ev_check* checkw = &conn->check_watcher;
            // If any connection is still spooling buffered reqs in check mode,
            // flip back to read watcher mode for shutdown drain.
            if (ev_is_active(checkw)) {
                gdnsd_assert(thr->check_mode_conns);
                ev_check_stop(thr->loop, checkw);
                ev_io* readw = &conn->read_watcher;
                gdnsd_assert(!ev_is_active(readw));
                ev_io_start(thr->loop, readw);
                thr->check_mode_conns--;
            }
            // Wipe any outstanding read buffer state:
            conn->readbuf_bytes = 0;
            conn->readbuf_head = 0;
            if (conn->dso.estab) {
                // send unidirectional RetryDelay, could destroy conn if cannot send
            } else {
                shutdown(conn->read_watcher.fd, SHUT_WR);
            }
            conn = next_conn;
        }
        gdnsd_assert(!thr->check_mode_conns);
        ev_timer* tmo = &thr->timeout_watcher;
        tmo->repeat = 5.0;
        ev_timer_again(thr->loop, tmo);
        return;
    }

    // Normal runtime timer fire for real conn expiry, expire from head of idle
    // list until we find an unexpired one (if any)
    const double cutoff = ev_now(thr->loop) - thr->server_timeout;
    while (conn && conn->idle_start <= cutoff) {
        conn_t* next_conn = conn->next;
        log_debug("TCP DNS conn from %s reset by server: timeout", logf_anysin(&conn->sa));
        stats_own_inc(&conn->thr->stats->tcp.close_s_ok);
        // Note final "manage_queue" argument is false.
        connq_destruct_conn(thr, conn, true, false);
        thr->num_conns--;
        conn = next_conn;
    }

    // Manual queue management, since we only pulled from the head
    if (!conn) {
        gdnsd_assert(!thr->num_conns);
        thr->connq_head = thr->connq_tail = NULL;
    } else {
        gdnsd_assert(thr->num_conns);
        conn->prev = NULL;
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
    connq_assert_sane(thr);

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
        return;
    }

    log_debug("TCP DNS thread shutdown: gracefully requesting clients to close %zu remaining conns when able and waiting up to 5s", thr->num_conns);

    // Switch thread state to the initial graceful shutdown phase
    thr->st = TH_GRACE;

    // Inform dnspacket layer we're in graceful shutdown phase (zero timeouts)
    dnspacket_ctx_set_grace(thr->pctx);

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
    // connection idleness, always pointing at the expiry point of the
    // head-most (most-idle) connection in the queue.  Now it is reset to fire
    // once 5 seconds from now to transition from TH_GRACE to TH_SHUT and wait
    // another 5 seconds there before exiting.
    ev_timer* tmo = &thr->timeout_watcher;
    tmo->repeat = 5.0;
    ev_timer_again(thr->loop, tmo);
}

// Checks the status of the next request in the buffer, if any, and takes a few
// sanitizing actions along the way.
// TLDR: -1 == killed conn, 0 == need more read, 1+ == size of full req avail
F_NONNULL
static ssize_t conn_check_next_req(thread_t* thr, conn_t* conn)
{
    // No bytes, just ensure head is reset to zero and ask for more reading
    if (!conn->readbuf_bytes) {
        conn->readbuf_head = 0;
        return 0;
    }

    // If even 1 byte is available, we can already pre-check for egregious
    // oversize, but we need two bytes for full sanity.
    size_t req_size = conn->readbuf[conn->readbuf_head];
    req_size <<= 8;
    bool undersized = false;
    if (conn->readbuf_bytes > 1) {
        req_size += conn->readbuf[conn->readbuf_head + 1];
        if (unlikely(req_size < 12U))
            undersized = true;
    }
    if (unlikely(undersized || req_size > DNS_RECV_SIZE)) {
        log_debug("TCP DNS conn from %s reset by server while reading: bad TCP request length", logf_anysin(&conn->sa));
        stats_own_inc(&thr->stats->tcp.recvfail);
        stats_own_inc(&thr->stats->tcp.close_s_err);
        connq_destruct_conn(thr, conn, true, true);
        return -1;
    }

    // If we don't have a full request buffered, move any legitimate (so far)
    // partial req to the bottom (if necc) and ask for more reading.
    if (conn->readbuf_bytes < (req_size + 2U)) {
        if (conn->readbuf_head) {
            memmove(conn->readbuf, &conn->readbuf[conn->readbuf_head], conn->readbuf_bytes);
            conn->readbuf_head = 0;
        }
        return 0;
    }

    return (ssize_t)req_size;
}

// Assumes a full request packet (starting with the 12 byte DNS header) is
// available starting at "conn->readbuf[conn->readbuf_head + 2U]" and the
// length indicated by the 2-byte length prefix from TCP DNS is indicated in
// req_size, and that the size is legal (already checked for >= 12 bytes and <=
// max).  Will copy out the request, process it, write a response, and then
// manage the read buffer state and the check/read watcher states.
F_NONNULL
static void conn_respond(thread_t* thr, conn_t* conn, const size_t req_size)
{
    gdnsd_assert(req_size >= 12U && req_size <= DNS_RECV_SIZE);

    // Move 1 full request from readbuf to pktbuf, advancing head and decrementing bytes
    memcpy(conn->pktbuf, &conn->readbuf[conn->readbuf_head + 2U], req_size);
    const size_t req_bufsize = req_size + 2U;
    conn->readbuf_head += req_bufsize;
    conn->readbuf_bytes -= req_bufsize;

    // Bring RCU online and generate an answer
    if (!thr->rcu_is_online) {
        thr->rcu_is_online = true;
        rcu_thread_online();
    }
    conn->dso.last_was_ka = false;
    size_t resp_size = process_dns_query(thr->pctx, &conn->sa, conn->pktbuf, &conn->dso, req_size);
    if (!resp_size) {
        log_debug("TCP DNS conn from %s reset by server: dropped invalid query", logf_anysin(&conn->sa));
        stats_own_inc(&thr->stats->tcp.close_s_err);
        connq_destruct_conn(thr, conn, true, true);
        return;
    }

    ev_io* readw = &conn->read_watcher;
    ev_check* checkw = &conn->check_watcher;

    // We only make one attempt to send the whole response, and do not accept
    // EAGAIN.  This is incorrect in theory, but it makes sense in practice for
    // our use-case: a reasonable client shouldn't be stuffing requests at us
    // so fast that its own TCP receive window and/or our reasonable output
    // buffers can't handle the resulting responses, and if some fault is
    // responsible then we need to tear down anyways.

    gdnsd_assert(resp_size <= MAX_RESPONSE_BUF);
    conn->pktbuf_size_hdr = htons((uint16_t)resp_size);
    const size_t resp_send_size = resp_size + 2U;
    const ssize_t send_rv = send(readw->fd, &conn->pktbuf_size_hdr, resp_send_size, 0);
    if (unlikely(send_rv < (ssize_t)resp_send_size)) {
        if (send_rv < 0 && !ERRNO_WOULDBLOCK)
            log_debug("TCP DNS conn from %s reset by server: failed while writing: %s", logf_anysin(&conn->sa), logf_errno());
        else
            log_debug("TCP DNS conn from %s reset by server: cannot buffer whole response", logf_anysin(&conn->sa));
        stats_own_inc(&thr->stats->tcp.sendfail);
        stats_own_inc(&thr->stats->tcp.close_s_err);
        connq_destruct_conn(thr, conn, true, true);
        return;
    }

    // We don't refresh timeout if this txn was just a DSO KA
    if (!conn->dso.last_was_ka)
        connq_refresh_conn(thr, conn);

    // Check status of next readbuf req, decide which watcher should be active
    const ssize_t ccnr_rv = conn_check_next_req(thr, conn);
    if (ccnr_rv < 0) // ccnr closed the conn for illegal next req size
        return;
    if (!ccnr_rv) { // No full req available, need to hit the read_handler next
        if (ev_is_active(checkw)) {
            ev_check_stop(thr->loop, checkw);
            gdnsd_assert(!ev_is_active(readw));
            ev_io_start(thr->loop, readw);
            thr->check_mode_conns--;
        } else {
            gdnsd_assert(ev_is_active(readw));
        }
    } else { // Full req available, need to hit the check_handler next
        if (ev_is_active(readw)) {
            ev_io_stop(thr->loop, readw);
            gdnsd_assert(!ev_is_active(checkw));
            ev_check_start(thr->loop, checkw);
            thr->check_mode_conns++;
        } else {
            gdnsd_assert(ev_is_active(checkw));
        }
    }
}

F_NONNULL
static void check_handler(struct ev_loop* loop V_UNUSED, ev_check* w, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_CHECK);
    conn_t* conn = w->data;
    gdnsd_assert(conn);
    thread_t* thr = conn->thr;
    gdnsd_assert(thr);

    gdnsd_assert(!conn->need_proxy_init);

    // We only arrive here if we have a legit-sized fully-buffered request
    gdnsd_assert(conn->readbuf_bytes > 2U);
    const size_t req_size = (((size_t)conn->readbuf[conn->readbuf_head + 0] << 8U) + (size_t)conn->readbuf[conn->readbuf_head + 1]);
    gdnsd_assert(req_size >= 12U && req_size <= DNS_RECV_SIZE);
    gdnsd_assert(conn->readbuf_bytes >= (req_size + 2U));
    conn_respond(thr, conn, req_size);
}

// This does the actual recv() call and immediate post-processing (incl conn
// termination on EOF or error), expects no empty space at buffer start.
// rv true means caller should return immediately (connection closed or read
// gave no new bytes and wants to block in the eventloop again).  rv false
// means one or more new bytes were added to the readbuf.
F_NONNULL
static bool conn_do_recv(thread_t* thr, conn_t* conn)
{
    gdnsd_assert(!conn->readbuf_head);
    gdnsd_assert(conn->readbuf_bytes < (DNS_RECV_SIZE + 2U));
    gdnsd_assert(conn->readbuf_bytes < sizeof(conn->readbuf));
    const size_t wanted = sizeof(conn->readbuf) - conn->readbuf_bytes;

    const ssize_t recvrv = recv(conn->read_watcher.fd, &conn->readbuf[conn->readbuf_bytes], wanted, 0);
    if (recvrv < 1) {
        if (!recvrv) { // 0 (EOF)
            if (conn->readbuf_bytes) {
                log_debug("TCP DNS conn from %s closed by client while reading: unexpected EOF", logf_anysin(&conn->sa));
                stats_own_inc(&thr->stats->tcp.recvfail);
                stats_own_inc(&thr->stats->tcp.close_s_err);
            } else {
                if (unlikely(thr->st == TH_SHUT)) {
                    if (conn->dso.estab) {
                        log_debug("TCP DNS conn from %s closed by client while shutting down after DSO RetryDelay", logf_anysin(&conn->sa));
                        stats_own_inc(&thr->stats->tcp.close_c);
                    } else {
                        log_debug("TCP DNS conn from %s closed by client while shutting down after server half-close", logf_anysin(&conn->sa));
                        stats_own_inc(&thr->stats->tcp.close_s_ok);
                    }
                } else {
                    log_debug("TCP DNS conn from %s closed by client while idle (ideal close)", logf_anysin(&conn->sa));
                    stats_own_inc(&thr->stats->tcp.close_c);
                }
            }
            connq_destruct_conn(thr, conn, false, true);
        } else { // -1 (errno)
            if (!ERRNO_WOULDBLOCK) {
                log_debug("TCP DNS conn from %s reset by server: error while reading: %s", logf_anysin(&conn->sa), logf_errno());
                stats_own_inc(&thr->stats->tcp.recvfail);
                stats_own_inc(&thr->stats->tcp.close_s_err);
                connq_destruct_conn(thr, conn, true, true);
            } else {
                // else it's -1 + errno=EAGAIN|EWOULDBLOCK and we just return true
            }
        }
        return true;
    }
    size_t pktlen = (size_t)recvrv;
    gdnsd_assert(pktlen <= wanted);
    gdnsd_assert((conn->readbuf_bytes + pktlen) <= sizeof(conn->readbuf));
    conn->readbuf_bytes += pktlen;
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

    // The read handler is never invoked with empty space at the buffer start
    gdnsd_assert(!conn->readbuf_head);
    if (conn_do_recv(thr, conn))
        return; // no new bytes or conn closed
    gdnsd_assert(conn->readbuf_bytes);

    // TH_SHUT means all conns are just draining junk reads looking for FIN
    if (unlikely(thr->st == TH_SHUT)) {
        conn->readbuf_bytes = 0; // throw away any received bytes
        return;
    }

    if (conn->need_proxy_init) {
        conn->need_proxy_init = false;
        const size_t consumed = proxy_parse(&conn->sa, &conn->proxy_hdr, conn->readbuf_bytes);
        gdnsd_assert(consumed <= conn->readbuf_bytes);
        if (!consumed) {
            log_debug("PROXY parse fail from %s, resetting connection", logf_anysin(&conn->sa));
            stats_own_inc(&thr->stats->tcp.proxy_fail);
            stats_own_inc(&thr->stats->tcp.close_s_err);
            connq_destruct_conn(thr, conn, true, true);
            return;
        }
        conn->readbuf_bytes -= consumed;
        if (conn->readbuf_bytes) {
            // If there's more data avail after PROXY, move it down so we're
            // transparent to the normal handling of the first req below.
            memmove(conn->readbuf, &conn->readbuf[consumed], conn->readbuf_bytes);
        } else {
            return;
        }
    }

    const ssize_t ccnr_rv = conn_check_next_req(thr, conn);
    if (ccnr_rv < 1) // ccnr either closed on err or wants us to read more
        return;
    conn_respond(thr, conn, (size_t)ccnr_rv);
}

F_NONNULL
static void accept_handler(struct ev_loop* loop, ev_io* w, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_READ);

    gdnsd_anysin_t sa;
    memset(&sa, 0, sizeof(sa));
    sa.len = GDNSD_ANYSIN_MAXLEN;

    const int sock = accept4(w->fd, &sa.sa, &sa.len, SOCK_NONBLOCK | SOCK_CLOEXEC);

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

    log_debug("Received TCP DNS connection from %s", logf_anysin(&sa));

    thread_t* thr = w->data;

    conn_t* conn = xcalloc(sizeof(*conn));
    memcpy(&conn->sa, &sa, sizeof(sa));

    stats_own_inc(&thr->stats->tcp.conns);
    if (thr->do_proxy) {
        stats_own_inc(&thr->stats->tcp.proxy);
        conn->need_proxy_init = true;
    }

    conn->thr = thr;
    connq_append_new_conn(thr, conn);

    ev_io* read_watcher = &conn->read_watcher;
    ev_io_init(read_watcher, read_handler, sock, EV_READ);
    ev_set_priority(read_watcher, 1);
    read_watcher->data = conn;
    ev_io_start(loop, read_watcher);

    ev_check* check_watcher = &conn->check_watcher;
    ev_check_init(check_watcher, check_handler);
    ev_set_priority(check_watcher, 1);
    check_watcher->data = conn;

    // Always optimistically attempt to read a req at conn start.  Even if
    // TCP_DEFER_ACCEPT and SO_ACCEPTFILTER are both unavailable, there's a
    // chance that under load the request data is already present.
    read_handler(loop, read_watcher, EV_READ);
}

F_NONNULL
static void idle_handler(struct ev_loop* loop V_UNUSED, ev_idle* w V_UNUSED, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_IDLE);
    // no-op, just here for the side-effect of nonblocking loop iterations
}

F_NONNULL
static void prep_handler(struct ev_loop* loop V_UNUSED, ev_prepare* w V_UNUSED, int revents V_UNUSED)
{
    thread_t* thr = w->data;
    gdnsd_assert(thr);

    ev_idle* iw = &thr->idle_watcher;
    if (thr->check_mode_conns) {
        if (!ev_is_active(iw))
            ev_idle_start(thr->loop, iw);
        if (thr->rcu_is_online)
            rcu_quiescent_state();
    } else {
        if (ev_is_active(iw))
            ev_idle_stop(thr->loop, iw);
        if (thr->rcu_is_online) {
            thr->rcu_is_online = false;
            rcu_thread_offline();
        }
    }
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

#ifndef IPV6_MIN_MTU
#define IPV6_MIN_MTU 1280
#endif

void tcp_dns_listen_setup(dns_thread_t* t)
{
    const dns_addr_t* addrconf = t->ac;
    gdnsd_assert(addrconf);

    const gdnsd_anysin_t* sa = &addrconf->addr;
    gdnsd_assert(sa);

    const bool isv6 = sa->sa.sa_family == AF_INET6 ? true : false;
    gdnsd_assert(isv6 || sa->sa.sa_family == AF_INET);

    bool need_bind = false;
    if (t->sock == -1) { // not acquired via replace
        t->sock = socket(isv6 ? PF_INET6 : PF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
        if (t->sock < 0)
            log_fatal("Failed to create IPv%c TCP socket: %s", isv6 ? '6' : '4', logf_errno());
        need_bind = true;
    }

    sockopt_bool_fatal(TCP, sa, t->sock, SOL_SOCKET, SO_REUSEADDR, 1);
    sockopt_bool_fatal(TCP, sa, t->sock, SOL_SOCKET, SO_REUSEPORT, 1);

    sockopt_bool_fatal(TCP, sa, t->sock, SOL_TCP, TCP_NODELAY, 1);

#ifdef TCP_DEFER_ACCEPT
    // Clamp TCP_DEFER_ACCEPT timeout to no more than 30s
    int defaccept_timeout = (int)addrconf->tcp_timeout;
    if (defaccept_timeout > 30)
        defaccept_timeout = 30;
    sockopt_int_fatal(TCP, sa, t->sock, SOL_TCP, TCP_DEFER_ACCEPT, defaccept_timeout);
#endif

#ifdef TCP_FASTOPEN
    // This is non-fatal for now because many OSes may require tuning/config to
    // allow this to work, but we do want to default it on in cases where it
    // works out of the box correctly.
    sockopt_int_warn(TCP, sa, t->sock, SOL_TCP, TCP_FASTOPEN, (int)addrconf->tcp_fastopen);
#endif

    if (isv6) {
        sockopt_bool_fatal(TCP, sa, t->sock, SOL_IPV6, IPV6_V6ONLY, 1);

        // as with our default max_edns_response_v6, assume minimum MTU only to
        // avoid IPv6 mtu/frag loss issues.  Clamping to min mtu should
        // commonly set MSS to 1220.
#if defined IPV6_USE_MIN_MTU
        sockopt_bool_fatal(TCP, sa, t->sock, SOL_IPV6, IPV6_USE_MIN_MTU, 1);
#elif defined IPV6_MTU
        // This sockopt doesn't have matching get+set; get needs a live
        // connection and reports the connection's path MTU, so we have to just
        // set it here blindly...
        const int min_mtu = IPV6_MIN_MTU;
        if (setsockopt(t->sock, SOL_IPV6, IPV6_MTU, &min_mtu, sizeof(min_mtu)) == -1)
            log_fatal("Failed to set IPV6_MTU on TCP socket: %s", logf_errno());
#endif
    }

    if (need_bind)
        socks_bind_sock("TCP DNS", t->sock, sa);
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

    ev_idle* idle_watcher = &thr->idle_watcher;
    ev_idle_init(idle_watcher, idle_handler);
    ev_set_priority(idle_watcher, -2);
    idle_watcher->data = thr;

    ev_io* accept_watcher = &thr->accept_watcher;
    ev_io_init(accept_watcher, accept_handler, t->sock, EV_READ);
    ev_set_priority(accept_watcher, -1);
    accept_watcher->data = thr;

    ev_timer* timeout_watcher = &thr->timeout_watcher;
    ev_timer_init(timeout_watcher, timeout_handler, 0, thr->server_timeout);
    ev_set_priority(timeout_watcher, 0);
    timeout_watcher->data = thr;

    ev_prepare* prep_watcher = &thr->prep_watcher;
    ev_prepare_init(prep_watcher, prep_handler);
    prep_watcher->data = thr;

    ev_async* stop_watcher = &thr->stop_watcher;
    ev_async_init(stop_watcher, stop_handler);
    ev_set_priority(stop_watcher, 2);
    stop_watcher->data = thr;

    struct ev_loop* loop = ev_loop_new(EVFLAG_AUTO);
    if (!loop)
        log_fatal("ev_loop_new() failed");
    thr->loop = loop;

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
