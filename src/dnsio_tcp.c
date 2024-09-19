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
#include "cdl.h"

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/misc.h>
#include <gdnsd/net.h>
#include <gdnsd/grcu.h>

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
#include <math.h>
#include <stdalign.h>
#include <stdatomic.h>

#include <ev.h>

// libev prio map:
// +2: thread async stop watcher (highest prio)
// +1: conn check/read watchers (only 1 per conn active at any time)
//  0: thread timeout watcher
// -1: thread accept watcher
// -2: thread idle watcher (lowest prio)

// Size of our read buffer.  We always attempt filling it on a read if TCP
// buffers have anything avail, and then drain all full requests from it and
// move any remaining partial request to the bottom before reading again.
// It's sized to fit several typical requests, and also such that "struct conn"
// comes in just a little under a 4K page in size on x86_64/Linux (and thus
// probably is no more than 1 page on all reasonable targets).  If the rest of
// the structure grows later, this may need adjustment.  There's a static
// assert about this below the definition of "struct conn".  This is just an
// efficiency hack of course.
#define TCP_READBUF 3840U
static_assert(TCP_READBUF >= (DNS_RECV_SIZE + 2U), "TCP readbuf fits >= 1 maximal req");
static_assert(TCP_READBUF >= sizeof(union proxy_hdr), "TCP readbuf >= PROXY header");

// TCP timeout timers may fire up to this many seconds late (even relative to
// the ev_now of the loop, which may already be slightly-late) to be more
// efficient at batching expiries and to deal better with timing edge cases.
#define TIMEOUT_FUDGE 0.25

union tcp_pkt {
    struct {
        // These two must be adjacent, as a single send() points at them as if
        // they're one buffer.
        uint16_t pktbuf_size_hdr;
        union pkt pkt;
    };
    uint8_t pktbuf_raw[sizeof(uint16_t) + sizeof(union pkt)];
};

// Ensure no padding between pktbuf_size_hdr and pkt, above
static_assert(alignof(union pkt) <= alignof(uint16_t), "No padding for pkt");

// per-thread state
struct thred {
    // These pointers and values are fixed for the life of the thread:
    struct dns_stats* stats;
    struct dnsp_ctx* pctx;
    struct ev_loop* loop;
    struct conn** churn; // save struct conn allocations from previously-closed conns
    union tcp_pkt* tpkt;
    double server_timeout;
    size_t max_clients;
    unsigned churn_alloc;
    bool do_proxy;
    bool tcp_pad;
    // The rest below will mutate at least somewhat:
    struct thred* next;
    ev_io accept_watcher;
    ev_prepare prep_watcher;
    ev_idle idle_watcher;
    ev_async stop_watcher;
    ev_timer timeout_watcher;
    CDL_ROOT(struct conn) connq;
    size_t check_mode_conns; // conns using check_watcher at present
    unsigned churn_count; // number of struct conn cached in "churn"
    bool grace_mode; // final 5s grace mode flag
    bool grcu_is_online;
};

// per-connection state
struct conn {
    CDL_ENTRY(struct conn) connq_entry;
    struct thred* thr;
    ev_io read_watcher;
    ev_check check_watcher;
    ev_tstamp idle_start;
    struct anysin sa;
    bool need_proxy_init;
    struct dso_state dso; // shared w/ dnspacket layer
    size_t readbuf_head;
    size_t readbuf_bytes;
    union {
        union proxy_hdr proxy_hdr;
        uint8_t readbuf[TCP_READBUF];
    };
};

// See above at definition of TCP_READBUF
static_assert(sizeof(struct conn) <= 4096U, "TCP conn <= 4KB");

// The init/count and condvar-gating here are to ensure that all of the started
// threads finish registering themselves before the main thread tries to stop
// them all via the registry (otherwise we might leak a thread and never ask it
// to stop).  Since only the stopping function needs to gate on this, we
// execute the gating part at stop time, which in almost all cases will
// already have the correct condition and not even wait or block on the mutex,
// unless stop is attempted very very early.
static pthread_mutex_t thred_reg_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t thred_reg_cond = PTHREAD_COND_INITIALIZER;
static struct thred* thred_reg_head = NULL;
static size_t threds_count = 0;
static size_t threds_registered = 0;

void dnsio_tcp_init(size_t num_threads)
{
    threds_count = num_threads;
}

F_NONNULL
static void thred_register(struct thred* thr)
{
    pthread_mutex_lock(&thred_reg_lock);
    thr->next = thred_reg_head;
    thred_reg_head = thr;
    threds_registered++;
    pthread_cond_signal(&thred_reg_cond);
    pthread_mutex_unlock(&thred_reg_lock);
}

// Note the atomic_signal_fence below, which is intended to be a full barrier
// against the *compiler* re-ordering the load of thr->next below the
// ev_async_send.  Without this, there's technically a race: the thread running
// this function could be preempted right after ev_async_send has done its main
// job (notifying the affected thread via pipe write), and while it's suspended
// the affected thread could receive its notification and terminate itself,
// making the memory pointed at by thr invalid, and thus making any typical
// load of thr->next at the bottom of the loop unsafe.
void dnsio_tcp_request_threads_stop(void)
{
    pthread_mutex_lock(&thred_reg_lock);
    while (threds_registered < threds_count)
        pthread_cond_wait(&thred_reg_cond, &thred_reg_lock);
    struct thred* thr = thred_reg_head;
    while (thr) {
        struct thred* nxt = thr->next;
        atomic_signal_fence(memory_order_seq_cst);
        ev_async* stop_watcher = &thr->stop_watcher;
        ev_async_send(thr->loop, stop_watcher);
        thr = nxt;
    }
    pthread_mutex_unlock(&thred_reg_lock);
}

F_NONNULL
static void connq_set_timer(struct thred* thr, const struct conn* head)
{
    gdnsd_assert(!CDL_IS_EMPTY(&thr->connq));
    gdnsd_assert(CDL_IS_HEAD(&thr->connq, head));

    if (likely(!thr->grace_mode)) {
        ev_timer* tmo = &thr->timeout_watcher;
        ev_tstamp next_interval = thr->server_timeout + TIMEOUT_FUDGE
                                  - (ev_now(thr->loop) - head->idle_start);
        if (next_interval < TIMEOUT_FUDGE)
            next_interval = TIMEOUT_FUDGE;
        tmo->repeat = next_interval;
        ev_timer_again(thr->loop, tmo);
    }
}

// Closes and destroys a connection and removes it from the connq.  Does *not*
// stop/adjust any timeout timer unless the final conn is destructed while in
// the final 5s grace mode.
F_NONNULL
static void connq_destruct_conn(struct thred* thr, struct conn* conn, const bool rst)
{
    gdnsd_assert(!CDL_IS_EMPTY(&thr->connq));

    ev_io* read_watcher = &conn->read_watcher;
    ev_io_stop(thr->loop, read_watcher);
    ev_check* check_watcher = &conn->check_watcher;
    if (ev_is_active(check_watcher)) {
        ev_check_stop(thr->loop, check_watcher);
        gdnsd_assume(thr->check_mode_conns);
        thr->check_mode_conns--;
    }

    const int fd = read_watcher->fd;
    if (rst) {
        const struct linger lin = { .l_onoff = 1, .l_linger = 0 };
        if (setsockopt(read_watcher->fd, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin)))
            log_neterr("setsockopt(%s, SO_LINGER, {1, 0}) failed: %s", logf_anysin(&conn->sa), logf_errno());
    }
    if (close(fd))
        log_neterr("close(%s) failed: %s", logf_anysin(&conn->sa), logf_errno());

    CDL_DEL(&thr->connq, connq_entry, conn);

    if (thr->churn_count < thr->churn_alloc) {
        memset(conn, 0, sizeof(*conn));
        thr->churn[thr->churn_count++] = conn;
    } else {
        free(conn);
    }

    // If we're in grace mode and just removed the final connection, go ahead
    // and stop the timer to let the thread exit without waiting the full 5s
    // grace period pointlessly.
    if (unlikely(thr->grace_mode) && CDL_IS_EMPTY(&thr->connq)) {
        ev_timer* timeout_watcher = &thr->timeout_watcher;
        ev_timer_stop(thr->loop, timeout_watcher);
    }
}

// Append a new connection at the tail of the idle list and set its idle_start
F_NONNULL
static void connq_append_new_conn(struct thred* thr, struct conn* conn)
{
    // accept() handler is gone when in grace phase
    gdnsd_assert(!thr->grace_mode);

    // Set the idle_start metadata for this connection:
    conn->idle_start = ev_now(thr->loop);

    // Add to the end of the list (the newest connection by definition has the
    // longest expiry remaining):
    CDL_ADD_TAIL(&thr->connq, connq_entry, conn);

    if (CDL_IS_HEAD(&thr->connq, conn)) {
        // If the list was empty and we became the head by inserting at the
        // end, and the timer was not running at all, we need to start it up
        // (if it's still running from a previously-closed connection, we avoid
        // timer churn as an optimization):
        gdnsd_assert(CDL_GET_COUNT(&thr->connq) == 1U);
        ev_timer* timeout_watcher = &thr->timeout_watcher;
        if (!ev_is_active(timeout_watcher))
            connq_set_timer(thr, conn);
    } else if (CDL_GET_COUNT(&thr->connq) == thr->max_clients) {
        // If we've just maxed out the connection count, we have to kill a conn
        // ungracefully.  Arguably, we could do smarter things sooner for DSO
        // clients (e.g. on reaching X% of max connection count, send the
        // most-idle DSO session a zero inactivity unidirectional keepalive, or
        // a retrydelay), but it's tricky to think through the implications
        // here given mixed clients (fairness between DSO/non-DSO, whether the
        // most-idle DSO is anywhere near the most-idle end of the list, etc)
        struct conn* head = CDL_GET_HEAD(&thr->connq);
        log_neterr("TCP DNS conn from %s reset by server: killed due to thread connection load (most-idle)", logf_anysin(&head->sa));
        connq_destruct_conn(thr, head, true);
        stats_own_inc(&thr->stats->tcp.close_s_kill);
    }
}

// Called when a connection completes a transaction (reads a legit request and
// writes the full response to the TCP layer), causing us to reset its idleness
F_NONNULL
static void connq_refresh_conn(struct thred* thr, struct conn* conn)
{
    gdnsd_assert(!conn->need_proxy_init);
    gdnsd_assert(!CDL_IS_EMPTY(&thr->connq));

    // First, refresh the actual idle_start metadata of this conn; regardless
    // of list position, this must be tracked accurately:
    conn->idle_start = ev_now(thr->loop);

    // Move to the end of the queue idempotently (the most recently-active is
    // always the longest to next timeout expiry):
    CDL_MOVE_TO_TAIL(&thr->connq, connq_entry, conn);
}

// Expects response data to already be in conn->pktbuf, of size resp_size.
// Used for writing normal responses, and also for DSO unidirectionals
F_NONNULL
static bool conn_write_packet(struct thred* thr, struct conn* conn, size_t resp_size)
{
    gdnsd_assume(resp_size);
    union tcp_pkt* tpkt = thr->tpkt;
    tpkt->pktbuf_size_hdr = htons((uint16_t)resp_size); // cppcheck-suppress redundantInitialization
    const size_t resp_send_size = resp_size + 2U;
    const ev_io* readw = &conn->read_watcher;
    const ssize_t send_rv = send(readw->fd, tpkt->pktbuf_raw, resp_send_size, 0);
    if (unlikely(send_rv < (ssize_t)resp_send_size)) {
        if (send_rv < 0 && !ERRNO_WOULDBLOCK)
            log_debug("TCP DNS conn from %s reset by server: failed while writing: %s", logf_anysin(&conn->sa), logf_errno());
        else
            log_debug("TCP DNS conn from %s reset by server: cannot buffer whole response", logf_anysin(&conn->sa));
        connq_destruct_conn(thr, conn, true);
        stats_own_inc(&thr->stats->tcp.sendfail);
        stats_own_inc(&thr->stats->tcp.close_s_err);
        return true;
    }
    return false;
}

// DSO unidirectional send of KeepAlive with KA=inf + Inact=0
F_NONNULL
static void conn_send_dso_uni(struct thred* thr, struct conn* conn)
{
    uint8_t* buf = thr->tpkt->pkt.raw;

    // For DSO uni, the 12 byte header is all zero except the opcode
    memset(buf, 0, 12U);
    buf[2] = DNS_OPCODE_DSO << 3;
    size_t offset = 12;

    // Construct DSO Keepalive pkt w/ KA=info + Inact=0
    gdnsd_put_una16(htons(DNS_DSO_KEEPALIVE), &buf[offset]);
    offset += 2;
    gdnsd_put_una16(htons(8U), &buf[offset]);
    offset += 2;
    gdnsd_put_una32(0xFFFFFFFFU, &buf[offset]);
    offset += 4;
    gdnsd_put_una32(0, &buf[offset]);
    offset += 4;
    gdnsd_assert(offset == 24U);

    // Add crypto padding if configured for the listener
    if (thr->tcp_pad) {
        const unsigned pad_dlen = PAD_BLOCK_SIZE - offset - 4U;
        gdnsd_put_una16(htons(DNS_DSO_PADDING), &buf[offset]);
        offset += 2U;
        gdnsd_put_una16(htons(pad_dlen), &buf[offset]);
        offset += 2U;
        memset(&buf[offset], 0, pad_dlen);
        offset += pad_dlen;
        gdnsd_assert(offset == PAD_BLOCK_SIZE);
    }

    // write response, may tear down connection if no immediate full write
    conn_write_packet(thr, conn, offset);
}

F_NONNULL
static void timeout_handler(struct ev_loop* loop, ev_timer* timeout_watcher, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_TIMER);
    struct thred* thr = timeout_watcher->data;
    gdnsd_assume(thr);

    // End of the 5s grace phase: immediately close all connections and let the thread exit
    if (unlikely(thr->grace_mode)) {
        log_debug("TCP DNS thread shutdown: immediately dropping (RST) %zu delinquent connections while exiting", CDL_GET_COUNT(&thr->connq));
        CDL_FOR_EACH_SAFE(&thr->connq, struct conn, connq_entry, conn) {
            connq_destruct_conn(thr, conn, true);
            stats_own_inc(&thr->stats->tcp.close_s_err);
        }
        gdnsd_assert(CDL_IS_EMPTY(&thr->connq));
        // Stop timer, should be last remaining watcher, leading to loop end
        ev_timer_stop(loop, timeout_watcher);
    }

    // Here we process normal runtime timeout expiries.  Note that during
    // general runtime operations elsewhere in the code, we avoid excessive
    // timer manipulations due to connections arriving, closing, or bumping
    // activity, as an optimization.  We prefer to just leave the current timer
    // running (which at worst fires a little earlier than necessary, not
    // later) and then do our fixups here once per timeout event (vs lots of
    // timer re-set churn when lots of connections are churning).
    // Aside from things that happen at shutdown time, and the timer reset/stop
    // at the bottom of this function, the only other time we explicitly re-set
    // the timer is when a new connection arrives while the timer is stopped
    // (initial state, or because this function found or caused an empty
    // connection list earlier and stopped it).  When we arrive here on a timer
    // firing, we have no idea whether the list has any connections left and/or
    // whether any of them are actually expired, but we do know that it's
    // sorted in timeout order, so we expire from the front of the list as
    // warranted and then re-set the timer (or stop it) as appropriate:

    const double cutoff = ev_now(loop) - thr->server_timeout;
    CDL_FOR_EACH_SAFE(&thr->connq, struct conn, connq_entry, conn) {
        if (conn->idle_start > cutoff)
            break;
        log_debug("TCP DNS conn from %s reset by server: timeout", logf_anysin(&conn->sa));
        connq_destruct_conn(thr, conn, true);
        stats_own_inc(&thr->stats->tcp.close_s_ok);
    }

    if (!CDL_IS_EMPTY(&thr->connq))
        connq_set_timer(thr, CDL_GET_HEAD(&thr->connq));
    else
        ev_timer_stop(loop, timeout_watcher);
}

F_NONNULL
static void stop_handler(struct ev_loop* loop, ev_async* w, int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_ASYNC);
    struct thred* thr = w->data;
    gdnsd_assume(thr);
    gdnsd_assert(!thr->grace_mode); // this handler stops itself on grace entry

    // Stop the accept() watcher and the async watcher for this stop handler
    ev_async* stop_watcher = &thr->stop_watcher;
    ev_async_stop(loop, stop_watcher);
    ev_io* accept_watcher = &thr->accept_watcher;
    ev_io_stop(loop, accept_watcher);

    ev_timer* timeout_watcher = &thr->timeout_watcher;

    // If there are no active connections, idempotently stop the timeout
    // watcher in case it's still running (we don't always stop it immediately
    // when the last conn closes in the general case).
    if (CDL_IS_EMPTY(&thr->connq)) {
        ev_timer_stop(loop, timeout_watcher);
        return;
    }

    log_debug("TCP DNS thread shutdown: gracefully requesting clients to close %zu remaining conns when able and waiting up to 5s", CDL_GET_COUNT(&thr->connq));

    // Switch thread state to the "graceful" shutdown phase
    thr->grace_mode = true;

    // Inform dnspacket layer we're in graceful shutdown phase (zero timeouts)
    dnspacket_ctx_set_grace(thr->pctx);

    // send unidirectional KeepAlive w/ inactivity=0 to all DSO clients
    CDL_FOR_EACH_SAFE(&thr->connq, struct conn, connq_entry, conn) {
        // conn_send_dso_uni can destruct on failure, hence the SAFE loop
        if (conn->dso.estab)
            conn_send_dso_uni(thr, conn);
    }

    if (CDL_IS_EMPTY(&thr->connq)) {
        // The attempted DSO sends above could close (due to error) all the
        // remaining connections, in which case we can stop the timer now,
        // which is the last remaining watcher, and the loop will end.
        ev_timer_stop(loop, timeout_watcher);
    } else {
        // If we still have live connections at this point, we will wait 5 more
        // seconds for them to naturally close (possibly in response to our DSO
        // KA, or an EDNS KA on a response) in "grace" mode before RSTing all
        // that remain:
        timeout_watcher->repeat = 5.0;
        ev_timer_again(loop, timeout_watcher);
    }
}

// Checks the status of the next request in the buffer, if any, and takes a few
// sanitizing actions along the way.
// TLDR: -1 == killed conn, 0 == need more read, 1+ == size of full req avail
F_NONNULL
static ssize_t conn_check_next_req(struct thred* thr, struct conn* conn)
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
        connq_destruct_conn(thr, conn, true);
        stats_own_inc(&thr->stats->tcp.recvfail);
        stats_own_inc(&thr->stats->tcp.close_s_err);
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
static void conn_respond(struct thred* thr, struct conn* conn, const size_t req_size)
{
    gdnsd_assume(req_size >= 12U && req_size <= DNS_RECV_SIZE);
    union tcp_pkt* tpkt = thr->tpkt;

    // Move 1 full request from readbuf to pkt, advancing head and decrementing bytes
    memcpy(tpkt->pkt.raw, &conn->readbuf[conn->readbuf_head + 2U], req_size);
    const size_t req_bufsize = req_size + 2U;
    conn->readbuf_head += req_bufsize;
    conn->readbuf_bytes -= req_bufsize;

    // Bring RCU online (or quiesce) and generate an answer
    if (!thr->grcu_is_online) {
        thr->grcu_is_online = true;
        grcu_thread_online();
    } else {
        grcu_quiescent_state();
    }

    conn->dso.last_was_ka = false;
    size_t resp_size = process_dns_query(thr->pctx, &conn->sa, &tpkt->pkt, &conn->dso, req_size);
    if (!resp_size) {
        log_debug("TCP DNS conn from %s reset by server: dropped invalid query", logf_anysin(&conn->sa));
        connq_destruct_conn(thr, conn, true);
        stats_own_inc(&thr->stats->tcp.close_s_err);
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

    gdnsd_assume(resp_size <= MAX_RESPONSE_BUF);
    if (conn_write_packet(thr, conn, resp_size))
        return; // writer ended up destroying conn

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
            gdnsd_assume(!ev_is_active(readw));
            ev_io_start(thr->loop, readw);
            gdnsd_assume(thr->check_mode_conns);
            thr->check_mode_conns--;
        } else {
            gdnsd_assert(ev_is_active(readw));
        }
    } else { // Full req available, need to hit the check_handler next
        if (ev_is_active(readw)) {
            ev_io_stop(thr->loop, readw);
            gdnsd_assume(!ev_is_active(checkw));
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
    struct conn* conn = w->data;
    gdnsd_assume(conn);
    struct thred* thr = conn->thr;
    gdnsd_assume(thr);

    gdnsd_assert(!conn->need_proxy_init);

    // We only arrive here if we have a legit-sized fully-buffered request
    gdnsd_assume(conn->readbuf_bytes > 2U);
    const size_t req_size = (((size_t)conn->readbuf[conn->readbuf_head + 0] << 8U) + (size_t)conn->readbuf[conn->readbuf_head + 1]);
    gdnsd_assume(req_size >= 12U && req_size <= DNS_RECV_SIZE);
    gdnsd_assume(conn->readbuf_bytes >= (req_size + 2U));
    conn_respond(thr, conn, req_size);
}

// This does the actual recv() call and immediate post-processing (incl conn
// termination on EOF or error).
// rv true means caller should return immediately (connection closed or read
// gave no new bytes and wants to block in the eventloop again).  rv false
// means one or more new bytes were added to the readbuf.
F_NONNULL
static bool conn_do_recv(struct thred* thr, struct conn* conn)
{
    gdnsd_assume(conn->readbuf_bytes < sizeof(conn->readbuf));
    const size_t wanted = sizeof(conn->readbuf) - conn->readbuf_bytes;
    const ssize_t recvrv = recv(conn->read_watcher.fd, &conn->readbuf[conn->readbuf_bytes], wanted, 0);

    if (recvrv == 0) { // (EOF)
        if (conn->readbuf_bytes) {
            log_debug("TCP DNS conn from %s closed by client while reading: unexpected EOF", logf_anysin(&conn->sa));
            stats_own_inc(&thr->stats->tcp.recvfail);
            stats_own_inc(&thr->stats->tcp.close_s_err);
        } else {
            log_debug("TCP DNS conn from %s closed by client while idle (ideal close)", logf_anysin(&conn->sa));
            stats_own_inc(&thr->stats->tcp.close_c);
        }
        connq_destruct_conn(thr, conn, false);
        return true;
    }

    if (recvrv < 0) { // negative return -> errno
        if (!ERRNO_WOULDBLOCK) {
            log_debug("TCP DNS conn from %s reset by server: error while reading: %s", logf_anysin(&conn->sa), logf_errno());
            connq_destruct_conn(thr, conn, true);
            stats_own_inc(&thr->stats->tcp.recvfail);
            stats_own_inc(&thr->stats->tcp.close_s_err);
        }
        return true;
    }

    size_t pktlen = (size_t)recvrv;
    gdnsd_assume(pktlen <= wanted);
    gdnsd_assume((conn->readbuf_bytes + pktlen) <= sizeof(conn->readbuf));
    conn->readbuf_bytes += pktlen;
    return false;
}

F_NONNULL
static void read_handler(struct ev_loop* loop V_UNUSED, ev_io* w, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_READ);
    struct conn* conn = w->data;
    gdnsd_assume(conn);
    struct thred* thr = conn->thr;
    gdnsd_assume(thr);

    if (conn_do_recv(thr, conn))
        return; // no new bytes or conn closed
    gdnsd_assume(conn->readbuf_bytes);

    if (conn->need_proxy_init) {
        conn->need_proxy_init = false;
        const size_t consumed = proxy_parse(&conn->sa, &conn->proxy_hdr, conn->readbuf_bytes);
        gdnsd_assume(consumed <= conn->readbuf_bytes);
        if (!consumed) {
            log_neterr("PROXY parse fail from %s, resetting connection", logf_anysin(&conn->sa));
            connq_destruct_conn(thr, conn, true);
            stats_own_inc(&thr->stats->tcp.proxy_fail);
            stats_own_inc(&thr->stats->tcp.close_s_err);
            return;
        }
        conn->readbuf_bytes -= consumed;
        conn->readbuf_head += consumed;
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

    struct thred* thr = w->data;

    struct anysin sa;
    memset(&sa, 0, sizeof(sa));
    sa.len = GDNSD_ANYSIN_MAXLEN;

    const int sock = accept4(w->fd, &sa.sa, &sa.len, SOCK_NONBLOCK | SOCK_CLOEXEC);

    if (unlikely(sock < 0)) {
        if (ERRNO_WOULDBLOCK || errno == EINTR) {
            // Simple retryable failures, do nothing
        } else if ((errno == ENFILE || errno == EMFILE) && !CDL_IS_EMPTY(&thr->connq)) {
            // If we ran out of fds and there's an idle one we can close, try
            // to do that, just like we do when we hit our internal limits
            struct conn* head = CDL_GET_HEAD(&thr->connq);
            log_neterr("TCP DNS conn from %s reset by server: attempting to"
                       " free resources because: accept4() failed: %s",
                       logf_anysin(&head->sa), logf_errno());
            connq_destruct_conn(thr, head, true);
            stats_own_inc(&thr->stats->tcp.acceptfail);
            stats_own_inc(&thr->stats->tcp.close_s_kill);
        } else {
            // For all other errnos (or E[MN]FILE without a conn to kill,
            // because we're not actually the offending thread...), just do a
            // ratelimited log output and bump the stat.
            log_neterr("TCP DNS: accept4() failed: %s", logf_errno());
            stats_own_inc(&thr->stats->tcp.acceptfail);
        }
        return;
    }

    log_debug("Received TCP DNS connection from %s", logf_anysin(&sa));

    struct conn* conn;
    if (thr->churn_count)
        conn = thr->churn[--thr->churn_count];
    else
        conn = xcalloc(sizeof(*conn));
    memcpy(&conn->sa, &sa, sizeof(sa));

    stats_own_inc(&thr->stats->tcp.conns);
    if (thr->do_proxy) {
        conn->need_proxy_init = true;
        stats_own_inc(&thr->stats->tcp.proxy);
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
static void prep_handler(struct ev_loop* loop, ev_prepare* w V_UNUSED, int revents V_UNUSED)
{
    struct thred* thr = w->data;
    gdnsd_assume(thr);

    ev_idle* iw = &thr->idle_watcher;
    if (thr->check_mode_conns) {
        if (!ev_is_active(iw)) {
            ev_idle_start(loop, iw);
            ev_unref(loop);
        }
        if (thr->grcu_is_online)
            grcu_quiescent_state();
    } else {
        if (ev_is_active(iw)) {
            ev_ref(loop);
            ev_idle_stop(loop, iw);
        }
        if (thr->grcu_is_online) {
            thr->grcu_is_online = false;
            grcu_thread_offline();
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

void tcp_dns_listen_setup(struct dns_thread* t)
{
    const struct dns_addr* addrconf = t->ac;
    gdnsd_assume(addrconf);

    const struct anysin* sa = &addrconf->addr;

    const bool isv6 = sa->sa.sa_family == AF_INET6 ? true : false;
    gdnsd_assert(isv6 || sa->sa.sa_family == AF_INET);

    bool need_bind = false;
    if (t->sock == -1) { // not acquired via replace
        t->sock = socket(sa->sa.sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
        if (t->sock < 0)
            log_fatal("Failed to create IPv%c TCP socket: %s", isv6 ? '6' : '4', logf_errno());
        need_bind = true;
    }

    sockopt_bool_fatal(TCP, sa, t->sock, SOL_SOCKET, SO_REUSEADDR, 1);
    // We need SO_REUSEPORT for functional reasons
    sockopt_bool_fatal(TCP, sa, t->sock, SOL_SOCKET, SO_REUSEPORT, 1);
#ifdef SO_REUSEPORT_LB
    // If BSD's SO_REUSEPORT_LB is available, try to upgrade to that for better
    // balancing, but merely warn on failure because it's new and there could
    // be a compiletime vs runtime diff.
    sockopt_bool_warn(TCP, sa, t->sock, SOL_SOCKET, SO_REUSEPORT_LB, 1);
#endif

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

    const int backlog = (int)(addrconf->tcp_backlog ? addrconf->tcp_backlog : SOMAXCONN);
    if (listen(t->sock, backlog) == -1)
        log_fatal("Failed to listen(s, %i) on TCP socket %s: %s", backlog, logf_anysin(&addrconf->addr), logf_errno());
}

static void set_accf(const struct dns_addr* addrconf V_UNUSED, const int sock V_UNUSED)
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

    const struct dns_thread* t = thread_asvoid;
    const struct dns_addr* addrconf = t->ac;
    gdnsd_assume(addrconf);

    struct thred thr = { 0 };

    set_accf(addrconf, t->sock);

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    // These are fixed values for the life of the thread based on config:
    thr.server_timeout = (double)(addrconf->tcp_timeout * 2);
    thr.max_clients = addrconf->tcp_clients_per_thread;
    thr.do_proxy = addrconf->tcp_proxy;
    thr.tcp_pad = addrconf->tcp_pad;

    // Set up the struct conn churn buffer, which saves some per-new-connection
    // memory allocation churn by saving up to sqrt(max_clients) old struct
    // conn storage for reuse
    const double ca = sqrt(thr.max_clients); // avoids a pointless warning
    thr.churn_alloc = (unsigned)ca;
    gdnsd_assume(thr.churn_alloc >= 4U); // because tcp_cpt min is 16U
    thr.churn = xmalloc_n(thr.churn_alloc, sizeof(*thr.churn));

    thr.tpkt = xcalloc(sizeof(*thr.tpkt));

    ev_idle* idle_watcher = &thr.idle_watcher;
    ev_idle_init(idle_watcher, idle_handler);
    ev_set_priority(idle_watcher, -2);
    idle_watcher->data = &thr;

    ev_io* accept_watcher = &thr.accept_watcher;
    ev_io_init(accept_watcher, accept_handler, t->sock, EV_READ);
    ev_set_priority(accept_watcher, -1);
    accept_watcher->data = &thr;

    ev_timer* timeout_watcher = &thr.timeout_watcher;
    ev_timer_init(timeout_watcher, timeout_handler, 0, thr.server_timeout);
    ev_set_priority(timeout_watcher, 0);
    timeout_watcher->data = &thr;

    ev_prepare* prep_watcher = &thr.prep_watcher;
    ev_prepare_init(prep_watcher, prep_handler);
    prep_watcher->data = &thr;

    ev_async* stop_watcher = &thr.stop_watcher;
    ev_async_init(stop_watcher, stop_handler);
    ev_set_priority(stop_watcher, 2);
    stop_watcher->data = &thr;

    struct ev_loop* loop = ev_loop_new(EVFLAG_AUTO);
    if (!loop)
        log_fatal("ev_loop_new() failed");
    thr.loop = loop;

    ev_async_start(loop, stop_watcher);
    ev_io_start(loop, accept_watcher);
    ev_prepare_start(loop, prep_watcher);
    ev_unref(loop); // prepare should not hold a ref, but should run to the end

    // thred_register() hooks us into the ev_async-based shutdown-handling
    // code, therefore we must have thr.loop and thr.stop_watcher initialized
    // and ready before we register here
    thred_register(&thr);

    // dnspacket_ctx_init() sets up our stats structure and dnspacket state for
    // runtime use, and registers the stats with statio:
    thr.pctx = dnspacket_ctx_init_tcp(&thr.stats, addrconf->tcp_pad, addrconf->tcp_timeout);

    grcu_register_thread();
    thr.grcu_is_online = true;

    ev_run(loop, 0);

    grcu_unregister_thread();

    ev_loop_destroy(loop);
    dnspacket_ctx_cleanup(thr.pctx);
    for (unsigned i = 0; i < thr.churn_count; i++)
        free(thr.churn[i]);
    free(thr.churn);
    free(thr.tpkt);

    return NULL;
}
