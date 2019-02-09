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
#include "csc.h"
#include "cs.h"
#include "main.h"
#include "statio.h"
#include "main.h"
#include "socks.h"
#include "chal.h"

#include <gdnsd/compiler.h>
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/paths.h>
#include <gdnsd/net.h>
#include "plugins/mon.h"

#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/file.h>
#include <sys/wait.h>

// makes sides of int[] from pipe2() clearer
#define PIPE_RD 0
#define PIPE_WR 1

static const char base_sock[] = "control.sock";
static const char base_lock[] = "control.lock";

typedef enum {
    READING_REQ,
    READING_DATA,
    WAITING_SERVER,
    WRITING_RESP,
    WRITING_RESP_FDS,
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
    char* data;
    ev_io w_read;
    ev_io w_write;
    int fd;
    size_t size;
    size_t size_done;
    css_cstate_t state;
};

typedef struct {
    css_conn_t** q;
    size_t len;
} conn_queue_t;

static void conn_queue_add(conn_queue_t* queue, css_conn_t* c)
{
    queue->q = xrealloc_n(queue->q, queue->len + 1, sizeof(*queue->q));
    queue->q[queue->len++] = c;
}

static void conn_queue_clear(conn_queue_t* queue)
{
    queue->len = 0;
    if (queue->q) {
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
    ev_io w_accept;
    ev_timer w_replace;
    struct ev_loop* loop;
    char* path;
    css_conn_t* clients;
    conn_queue_t reload_zones_queued;
    conn_queue_t reload_zones_active;
    char* argv0;
    socks_cfg_t* socks_cfg;
    css_conn_t* replace_conn_ctl;
    css_conn_t* replace_conn_dmn;
    int* handoff_fds;
    size_t handoff_fds_count;
    pid_t replacement_pid;
};

static void swap_reload_zones_queues(css_t* css)
{
    conn_queue_t x;
    memcpy(&x, &css->reload_zones_queued, sizeof(x));
    memcpy(&css->reload_zones_queued, &css->reload_zones_active, sizeof(x));
    memcpy(&css->reload_zones_active, &x, sizeof(x));
}

F_NONNULL
static void css_conn_cleanup(css_conn_t* c)
{
    css_t* css = c->css;
    gdnsd_assert(css);

    if (c == css->replace_conn_ctl)
        css->replace_conn_ctl = NULL;

    if (c == css->replace_conn_dmn) {
        css->replace_conn_dmn = NULL;
        // If the replacement daemon drops the csock connection or there's some
        // kind of communications error with it that causes us to drop the
        // connection, assume it's failing and send it a SIGKILL, letting our
        // PID watcher do the rest of the cleanup when it exits.
        if (css->replacement_pid) {
            log_err("REPLACE[old daemon]: Communications error with new daemon at pid %li, killing it with SIGKILL",
                    (long)css->replacement_pid);
            kill(css->replacement_pid, SIGKILL);
        }
    }

    // stop/free io-related things
    if (c->data)
        free(c->data);
    ev_io* w_read = &c->w_read;
    ev_io_stop(css->loop, w_read);
    ev_io* w_write = &c->w_write;
    ev_io_stop(css->loop, w_write);
    if (c->fd >= 0)
        close(c->fd);

    // remove from linked list
    if (c == css->clients)
        css->clients = c->next;
    if (c->prev)
        c->prev->next = c->next;
    if (c->next)
        c->next->prev = c->prev;
    free(c);
}

F_NONNULL
static bool respond_blocking_ack(css_conn_t* c)
{
    gdnsd_assert(c->css);
    gdnsd_assert(c->state == WAITING_SERVER);
    c->wbuf.key = RESP_ACK;
    csbuf_set_v(&c->wbuf, 0);
    c->wbuf.d = 0;
    c->state = WRITING_RESP;
    ssize_t pktlen = send(c->fd, c->wbuf.raw, 8, 0);
    if (pktlen != 8) {
        log_err("blocking control socket write of 8 bytes failed with retval %zi, closing: %s", pktlen, logf_errno());
        css_conn_cleanup(c);
        return true;
    }
    return false;
}

F_NONNULL
static void css_conn_write_data(css_conn_t* c)
{
    gdnsd_assert(c->state == WRITING_RESP_DATA);
    gdnsd_assert(c->data);
    gdnsd_assert(c->size);
    const size_t wanted = c->size - c->size_done;
    gdnsd_assert(wanted > 0);
    const ssize_t pktlen = send(c->fd, &c->data[c->size_done], wanted, MSG_DONTWAIT);
    if (pktlen < 0) {
        if (ERRNO_WOULDBLOCK)
            return;
        log_err("control socket write of %zu bytes failed with retval %zi, closing: %s", wanted, pktlen, logf_errno());
        css_conn_cleanup(c);
        return;
    }

    c->size_done += (size_t)pktlen;
    if (c->size_done == c->size) {
        free(c->data);
        c->data = NULL;
        c->size = 0;
        c->size_done = 0;
        ev_io* w_write = &c->w_write;
        ev_io_stop(c->css->loop, w_write);
        ev_io* w_read = &c->w_read;
        ev_io_start(c->css->loop, w_read);
        c->state = READING_REQ;
    }
}

F_NONNULL
static bool css_conn_write_resp(css_conn_t* c)
{
    gdnsd_assert(c->state == WRITING_RESP || c->state == WRITING_RESP_FDS);

    union {
        struct cmsghdr c;
        char cmsg_buf[CMSG_SPACE(sizeof(int) * SCM_MAX_FDS)];
    } u;
    struct iovec iov = { .iov_base = c->wbuf.raw, .iov_len  = 8 };
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    size_t send_fd_count = SCM_MAX_FDS;
    if (c->state == WRITING_RESP_FDS) {
        const size_t fd_todo = c->size - c->size_done;
        if (fd_todo < SCM_MAX_FDS)
            send_fd_count = fd_todo;
        const size_t send_fd_len = sizeof(int) * send_fd_count;
        memset(u.cmsg_buf, 0, sizeof(u.cmsg_buf));
        msg.msg_control = u.cmsg_buf;
        msg.msg_controllen = CMSG_LEN(send_fd_len);
        struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        gdnsd_assert(cmsg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(send_fd_len);
        memcpy(CMSG_DATA(cmsg), &c->css->handoff_fds[c->size_done], send_fd_len);
    }

    ssize_t pktlen = sendmsg(c->fd, &msg, MSG_DONTWAIT);
    if (pktlen != 8) {
        if (pktlen < 0 && ERRNO_WOULDBLOCK)
            return false;
        log_err("control socket write of 8 bytes failed with retval %zi, closing: %s", pktlen, logf_errno());
        css_conn_cleanup(c);
        return false;
    }

    if (c->state == WRITING_RESP_FDS) {
        c->size_done += send_fd_count;
        if (c->size_done < c->size)
            return false;
        c->size = 0;
        c->size_done = 0;
    } else if (c->data) {
        c->state = WRITING_RESP_DATA;
        return true;
    }

    ev_io* w_write = &c->w_write;
    ev_io_stop(c->css->loop, w_write);
    ev_io* w_read = &c->w_read;
    ev_io_start(c->css->loop, w_read);
    c->state = READING_REQ;
    return false;
}

F_NONNULL
static void css_conn_write(struct ev_loop* loop V_UNUSED, ev_io* w, int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_WRITE);
    css_conn_t* c = w->data;
    gdnsd_assert(c);
    gdnsd_assert(c->state == WRITING_RESP || c->state == WRITING_RESP_FDS || c->state == WRITING_RESP_DATA);


    if (c->state != WRITING_RESP_DATA && !css_conn_write_resp(c))
        return;
    css_conn_write_data(c);
}

// If "data" is set, it's a buffer of extended response data to send after the
// initial 8-byte response (and then free once sent), and "d" contains the
// length of the data.
// If "send_fds" is set, send the SCM_RIGHTS fd list response for REQ_TAKE.
// "send_fds" requires: key=RESP_ACK, v=0, d=0, data=NULL
F_NONNULLX(1)
static void respond(css_conn_t* c, const char key, const uint32_t v, const uint32_t d, char* data, bool send_fds)
{
    gdnsd_assert(c->css);
    gdnsd_assert(c->state == WAITING_SERVER);
    gdnsd_assert(v <= 0xFFFFFF);
    gdnsd_assert(!(data && send_fds)); // we don't support setting both

    c->wbuf.key = key;
    csbuf_set_v(&c->wbuf, v);
    c->wbuf.d = d;
    c->state = WRITING_RESP;
    if (data) {
        c->data = data;
        c->size = d;
        c->size_done = 0;
    } else if (send_fds) {
        gdnsd_assert(key == RESP_ACK);
        gdnsd_assert(!v);
        gdnsd_assert(!d);
        c->state = WRITING_RESP_FDS;
        csbuf_set_v(&c->wbuf, c->css->handoff_fds_count);
        c->size = c->css->handoff_fds_count;
        c->size_done = 0;
    }
    ev_io* w_write = &c->w_write;
    ev_io_start(c->css->loop, w_write);
}

F_NONNULL
static void respond_tak2(struct ev_loop* loop, css_conn_t* c)
{
    size_t csets_count = 0;
    size_t csets_size = 0;
    uint8_t* csets_data = csets_serialize(loop, &csets_count, &csets_size);
    respond(c, RESP_ACK, (uint32_t)csets_count, (uint32_t)csets_size, (char*)csets_data, false);
}

bool css_stop_ok(css_t* css)
{
    return !css->replacement_pid;
}

F_NONNULL
static void css_watch_replace(struct ev_loop* loop, ev_timer* w, int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_TIMER);
    css_t* css = w->data;
    gdnsd_assert(css);
    gdnsd_assert(css->replacement_pid);

    // libev's default SIGCHLD handler auto-reaps for us
    // If the process that was attempting a replace operation died, and we're
    // still here, so we have some cleanup to do...
    if (kill(css->replacement_pid, 0)) {
        log_err("REPLACE[old daemon]: New daemon at PID %li died, resuming normal operations",
                (long)css->replacement_pid);
        ev_timer_stop(loop, w);

        if (css->replace_conn_ctl)
            respond(css->replace_conn_ctl, RESP_FAIL, 0, 0, NULL, false);

        if (css->replace_conn_dmn)
            css_conn_cleanup(css->replace_conn_dmn);

        // re-set our states so that further stop/replace/replace actions can happen
        css->replacement_pid = 0;
        css->replace_conn_ctl = NULL;
        css->replace_conn_dmn = NULL;

        // Re-start our accept watcher
        ev_io* w_accept = &css->w_accept;
        ev_io_start(css->loop, w_accept);
    }
}

//   We have to do a double-fork here to satisfy systemd, otherwise when we
// notify it of the new MainPID from the new child while the old parent daemon
// still exists, the new child's parent isn't (yet) systemd, and so it
// considers it an "alien" MainPID (which it complains about, and never
// un-complains or fixes it when the old parent daemon eventually exits,
// re-parenting the new child to systemd properly via orphanage).
//   Note also that if we don't serially reap (waitpid) the middle PID, we'd
// face a race on whether the re-parenting to systemd happens before the
// notification from the new child.  libev already has a SIGCHLD auto-reaper
// running, which will race with our own reaper to no ill effect.  We just need
// to be sure the pid is gone completely before continuing.
//   However, we also still need to track the final PID of the new child in the
// original daemon, in order to prevent races between multiple replacements, so
// we'll also have to set up a pipe() to communicate the final PID back to the
// parent from the middle process.
// Thanks, systemd :P
static pid_t spawn_replacement(const char* argv0)
{
    // Set up the more-complicated exec args, to be used much deeper during
    // execlp() of the final replacement child
    const char* cfpath = gdnsd_get_config_dir();
    char flags[5] = { '-', 'R', '\0', '\0', '\0' };
    unsigned fidx = 2;
    if (gdnsd_log_get_debug())
        flags[fidx++] = 'D';
    if (gdnsd_log_get_syslog())
        flags[fidx++] = 'l';

    // Before forking, block all signals and save the old mask
    //   to avoid a race condition where local sighandlers execute
    //   in the child between fork and exec().
    sigset_t all_sigs;
    sigfillset(&all_sigs);
    sigset_t saved_mask;
    sigemptyset(&saved_mask);
    if (pthread_sigmask(SIG_SETMASK, &all_sigs, &saved_mask))
        log_fatal("pthread_sigmask() failed");

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC))
        log_fatal("pipe() failed: %s", logf_errno());

    pid_t middle_pid = fork();
    if (middle_pid == -1)
        log_fatal("fork() failed: %s", logf_errno());

    if (!middle_pid) { // middle-child
        close(pipefd[PIPE_RD]);
        pid_t replacement_pid = fork();
        if (replacement_pid == -1)
            log_fatal("fork() failed: %s", logf_errno());

        if (!replacement_pid) { // final-child
            close(pipefd[PIPE_WR]);
            gdnsd_reset_signals_for_exec();
            execlp(argv0, argv0, "-c", cfpath, flags, "start", NULL);
            log_fatal("execlp(%s) failed: %s", argv0, logf_errno());
        }

        // --- middle-parent code
        uint32_t sendpid = (uint32_t)replacement_pid;
        if (write(pipefd[PIPE_WR], &sendpid, 4) != 4)
            log_fatal("write() of PID during replacement spawn failed: %s", logf_errno());
        _exit(0);
    }

    // --- original-parent code

    uint32_t recvpid;
    close(pipefd[PIPE_WR]);
    if (read(pipefd[PIPE_RD], &recvpid, 4) != 4)
        log_fatal("read() of PID during replacement spawn failed: %s", logf_errno());
    close(pipefd[PIPE_RD]);
    pid_t replacement_pid = (pid_t)recvpid;

    int status;
    pid_t wp_rv = waitpid(middle_pid, &status, 0);
    if (wp_rv < 0) {
        // We can assume ECHILD means the libev SIGCHLD handler beat us to waitpid()
        if (errno != ECHILD)
            log_fatal("waitpid(%li) for temporary middle process during replacement spawn failed: %s",
                      (long)middle_pid, logf_errno());
    } else {
        if (wp_rv != middle_pid)
            log_fatal("waitpid(%li) for temporary middle process during replacement spawn caught process %li instead",
                      (long)middle_pid, (long)wp_rv);
        if (status)
            log_err("waitpid(%li) for temporary middle process during replacement spawn returned bad status %i",
                    (long)middle_pid, status);
    }

    // restore previous signal mask from before fork
    if (pthread_sigmask(SIG_SETMASK, &saved_mask, NULL))
        log_fatal("pthread_sigmask() failed");

    return replacement_pid;
}

// When a takeover starts (replacement_pid is assigned), send an immediate
// RESP_LATR to all waiting reload-zones clients (even active ones with a
// thread already running), so they'll retry against the new daemon.
static void latr_all_reloaders(css_t* css)
{
    for (size_t i = 0; i < css->reload_zones_active.len; i++) {
        log_info("REPLACE[old daemon]: Deferring reload-zones request while replace in progress");
        respond(css->reload_zones_active.q[i], RESP_LATR, 0, 0, NULL, false);
    }
    for (size_t i = 0; i < css->reload_zones_queued.len; i++) {
        log_info("REPLACE[old daemon]: Deferring reload-zones request while replace in progress");
        respond(css->reload_zones_queued.q[i], RESP_LATR, 0, 0, NULL, false);
    }
    conn_queue_clear(&css->reload_zones_active);
    conn_queue_clear(&css->reload_zones_queued);
}

F_NONNULL
static void css_conn_read(struct ev_loop* loop, ev_io* w, int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_READ);
    css_conn_t* c = w->data;
    css_t* css = c->css;
    gdnsd_assert(c);
    gdnsd_assert(css);
    gdnsd_assert(c->state == READING_REQ || c->state == READING_DATA);

    if (c->state == READING_DATA) {
        gdnsd_assert(c->data);
        gdnsd_assert(c->size);
        size_t wanted = c->size - c->size_done;
        gdnsd_assert(wanted > 0);

        ssize_t pktlen = recv(c->fd, &c->data[c->size_done], wanted, MSG_DONTWAIT);
        if (pktlen <= 0) {
            if (pktlen < 0 && ERRNO_WOULDBLOCK)
                return;
            if (pktlen == 0)
                log_err("control socket client disconnected when we expected %zu more bytes from it", wanted);
            else
                log_err("control socket read of %zu data bytes failed with retval %zi, closing: %s", wanted, pktlen, logf_errno());
            css_conn_cleanup(c);
            return;
        }

        c->size_done += (size_t)pktlen;

        if (c->size_done == c->size) {
            ev_io_stop(loop, w);
            c->state = WAITING_SERVER;

            // we'd switch here if more than one, but REQ_CHAL is the only key that leads here for now
            gdnsd_assert(c->rbuf.key == REQ_CHAL);

            char resp_key = RESP_ACK;
            if (css->replacement_pid) {
                log_info("Deferring acme-dns-01 request while replace in progress");
                resp_key = RESP_LATR;
            } else if (cset_create(loop, 0, csbuf_get_v(&c->rbuf), c->size_done, (uint8_t*)c->data)) {
                resp_key = RESP_FAIL;
            }

            free(c->data);
            c->data = NULL;
            c->size = 0;
            c->size_done = 0;
            respond(c, resp_key, 0, 0, NULL, false);
        }

        return;
    }

    const ssize_t pktlen = recv(c->fd, c->rbuf.raw, 8, MSG_DONTWAIT);
    if (pktlen != 8) {
        if (pktlen < 0 && ERRNO_WOULDBLOCK)
            return;
        if (pktlen == 0)
            log_devdebug("control socket client disconnected cleanly during read");
        else
            log_err("control socket read of 8 bytes failed with retval %zi, closing: %s", pktlen, logf_errno());
        css_conn_cleanup(c);
        return;
    }

    // REQ_CHAL is the only case so far where the client sends data after the
    // 8-byte standard request, using "d" as the raw data length and "v" as the
    // count of challenges sent in the data.
    if (c->rbuf.key == REQ_CHAL) {
        const unsigned count = csbuf_get_v(&c->rbuf);
        const unsigned dlen = c->rbuf.d;
        if (!count || count > CHAL_MAX_COUNT || !dlen || dlen > CHAL_MAX_DLEN) {
            log_err("Challenge request has illegal sizes (%u count, %u data), closing", count, dlen);
            css_conn_cleanup(c);
        } else {
            c->state = READING_DATA;
            c->size_done = 0;
            c->size = dlen;
            c->data = xmalloc(dlen);
        }
        return;
    }

    ev_io_stop(loop, w);
    c->state = WAITING_SERVER;

    double nowish;
    size_t stats_size;
    size_t states_size;
    size_t dns_fds_send;
    char* stats_msg;
    char* states_msg;
    pid_t take_pid;
    ev_timer* w_replace = &css->w_replace;
    ev_io* w_accept = &css->w_accept;

    switch (c->rbuf.key) {
    case REQ_INFO:
        respond(c, RESP_ACK, css->status_v, css->status_d, NULL, false);
        break;
    case REQ_STOP:
        if (css->replacement_pid) {
            if (c != css->replace_conn_dmn) {
                log_info("Deferring stop request while replace in progress");
                respond(c, RESP_LATR, 0, 0, NULL, false);
                break;
            } else {
                log_info("REPLACE[old daemon]: Exiting cleanly at request of new daemon");
                // Note from here we won't re-enter the eventloop anyways, so
                // no further requests can be processed and the replacement_pid
                // flag isn't very useful anymore.  Explicitly re-setting it to
                // zero avoids the eventual css_conn_cleanup of this connection
                // (during css_delete(), or due to some communications failure
                // with the blocking acks below) trying to kill the new daemon
                // off because it thinks it's a fail-to-takeover sort of
                // situation.
                css->replacement_pid = 0;
            }
        } else {
            log_info("Exiting cleanly due to control socket client request");
        }
        // Note this is the point of no return for the old daemon in "replace",
        // as we'll never re-enter the main thread's runtime eventloop to
        // process further control socket message (or other events).
        ev_break(loop, EVBREAK_ALL);
        // ACK to the client that sent REQ_STOP
        // In non-replace cases (plain stop from e.g. gdnsdctl), set the fd
        // to -1 here so that we don't close it during css_delete, as the
        // response above was our last interaction with it.  In replace cases,
        // there's one more interaction during the final stats handoff, and the
        // new daemon doesn't wait on our close anyways.
        if (!respond_blocking_ack(c) && c != css->replace_conn_dmn)
            c->fd = -1;
        // If "gdnsdctl replace" is connected and driving the process, finally
        // give it an ACK response to its REQ_REPL, as we're now past the point
        // of no return on the replace operation, and also set its fd to -1 to
        // let it close as the process dies as above.
        if (css->replace_conn_ctl) {
            gdnsd_assert(c == css->replace_conn_dmn);
            if (!respond_blocking_ack(css->replace_conn_ctl))
                css->replace_conn_ctl->fd = -1;
        }
        break;
    case REQ_STAT:
        nowish = ev_now(loop);
        stats_size = 0;
        stats_msg = statio_get_json((time_t)nowish, &stats_size);
        gdnsd_assert(stats_size <= UINT32_MAX);
        respond(c, RESP_ACK, 0, (uint32_t)stats_size, stats_msg, false);
        break;
    case REQ_STATE:
        states_size = 0;
        states_msg = gdnsd_mon_states_get_json(&states_size);
        gdnsd_assert(states_size <= UINT32_MAX);
        respond(c, RESP_ACK, 0, (uint32_t)states_size, states_msg, false);
        break;
    case REQ_ZREL:
        if (css->replacement_pid) {
            log_info("Deferring reload-zones request while replace in progress");
            respond(c, RESP_LATR, 0, 0, NULL, false);
            break;
        }
        conn_queue_add(&css->reload_zones_queued, c);
        if (!css->reload_zones_active.len) {
            swap_reload_zones_queues(css);
            spawn_async_zones_reloader_thread();
        }
        break;
    case REQ_CHALF:
        if (css->replacement_pid) {
            log_info("Deferring acme-dns-01-flush request while replace in progress");
            respond(c, RESP_LATR, 0, 0, NULL, false);
        } else {
            cset_flush(loop);
            respond(c, RESP_ACK, 0, 0, 0, false);
        }
        break;
    case REQ_REPL:
        if (css->replacement_pid) {
            log_info("Deferring replace request while another replace already in progress");
            respond(c, RESP_LATR, 0, 0, NULL, false);
            break;
        }
        log_debug("REPLACE[old daemon]: Accepting replace command, spawning replacement server...");
        gdnsd_assert(!css->replace_conn_ctl);
        gdnsd_assert(!css->replace_conn_dmn);
        css->replace_conn_ctl = c;
        css->replacement_pid = spawn_replacement(css->argv0);
        log_info("REPLACE[old daemon]: Accepted replace command, spawned replacement daemon at PID %li", (long)css->replacement_pid);
        ev_timer_start(css->loop, w_replace);
        latr_all_reloaders(css);
        break;
    case REQ_TAK1:
        take_pid = (pid_t)c->rbuf.d;
        if (css->replacement_pid && css->replacement_pid != take_pid) {
            log_warn("Denying takeover notification from PID %li while replace is already in progress with PID %li", (long)take_pid, (long)css->replacement_pid);
            // could argue for LATR or FAIL here, but currently the new daemon doesn't wait and retry anyways
            respond(c, RESP_LATR, 0, 0, NULL, false);
            break;
        }
        log_debug("Accepted takeover notification from PID %li", (long)take_pid);
        css->replacement_pid = take_pid;
        gdnsd_assert(!css->replace_conn_dmn);
        css->replace_conn_dmn = c;
        ev_timer_start(css->loop, w_replace);
        latr_all_reloaders(css);
        respond(c, RESP_ACK, 0, 0, NULL, false);
        break;
    case REQ_TAK2:
        take_pid = (pid_t)c->rbuf.d;
        if (!css->replacement_pid || take_pid != css->replacement_pid || c != css->replace_conn_dmn) {
            log_warn("Denying illegal takeover phase 2 from PID %li while replace is already in progress with PID %li", (long)take_pid, (long)css->replacement_pid);
            respond(c, RESP_FAIL, 0, 0, NULL, false);
            break;
        }
        log_debug("Accepted takeover phase 2 (challenge data req) from PID %li", (long)take_pid);
        respond_tak2(css->loop, c);
        break;
    case REQ_TAKE:
        take_pid = (pid_t)c->rbuf.d;
        if (!css->replacement_pid || take_pid != css->replacement_pid || c != css->replace_conn_dmn) {
            log_err("Denying illegal takeover request without pre-notification");
            respond(c, RESP_FAIL, 0, 0, NULL, false);
            css_conn_cleanup(c);
            break;
        }
        gdnsd_assert(css->handoff_fds_count >= 2LU);
        dns_fds_send = css->handoff_fds_count - 2LU;
        log_info("REPLACE[old daemon]: Accepting takeover request from replacement PID %li, sending %zu DNS sockets", (long)take_pid, dns_fds_send);
        ev_io_stop(css->loop, w_accept); // there can be only one
        respond(c, RESP_ACK, 0, 0, NULL, true);
        break;
    default:
        log_err("Unknown request type %hhx from control socket", (uint8_t)c->rbuf.key);
        respond(c, RESP_UNK, 0, 0, NULL, false);
    }
}

F_NONNULL
static void css_accept(struct ev_loop* loop V_UNUSED, ev_io* w, int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_READ);
    css_t* css = w->data;
    gdnsd_assert(css);

    const int fd = accept4(w->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);

    if (unlikely(fd < 0)) {
        switch (errno) {
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

    // set up the per-connection state and start reading requests...
    css_conn_t* c = xcalloc(sizeof(*c));
    c->css = css;
    c->fd = fd;
    ev_io* w_read = &c->w_read;
    ev_io_init(w_read, css_conn_read, fd, EV_READ);
    ev_io* w_write = &c->w_write;
    ev_io_init(w_write, css_conn_write, fd, EV_WRITE);
    w_read->data = c;
    w_write->data = c;

    // set up buffer/watcher state to read input length
    c->state = READING_REQ;
    ev_io_start(css->loop, w_read);

    // insert into front of linked list
    if (css->clients) {
        c->next = css->clients;
        css->clients->prev = c;
    }
    css->clients = c;
}

static void socks_import_fd(socks_cfg_t* socks_cfg, const int fd)
{
    gdnsd_anysin_t fd_sin;
    memset(&fd_sin, 0, sizeof(fd_sin));
    fd_sin.len = GDNSD_ANYSIN_MAXLEN;

    if (getsockname(fd, &fd_sin.sa, &fd_sin.len) || fd_sin.len > GDNSD_ANYSIN_MAXLEN) {
        if (errno == EBADF)
            log_err("REPLACE[new daemon]: Socket handoff: Ignoring invalid file descriptor %i", fd);
        else if (fd_sin.len > GDNSD_ANYSIN_MAXLEN)
            log_err("REPLACE[new daemon]: Socket handoff: getsockname(%i) returned oversize address, closing", fd);
        else
            log_err("REPLACE[new daemon]: Socket handoff: getsockname(%i) failed, closing: %s", fd, logf_errno());
        if (errno != EBADF)
            close(fd);
        return;
    }

    int fd_sin_type = 0;
    socklen_t fd_sin_type_size = sizeof(fd_sin_type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &fd_sin_type, &fd_sin_type_size)
            || fd_sin_type_size != sizeof(fd_sin_type)
            || (fd_sin_type != SOCK_DGRAM && fd_sin_type != SOCK_STREAM)) {
        log_err("REPLACE[new daemon]: Socket handoff: cannot get type of fd %i @ %s, closing: %s", fd, logf_anysin(&fd_sin), logf_errno());
        close(fd);
        return;
    }
    const bool fd_sin_is_udp = (fd_sin_type == SOCK_DGRAM);

    for (unsigned i = 0; i < socks_cfg->num_dns_threads; i++) {
        dns_thread_t* dt = &socks_cfg->dns_threads[i];
        if (dt->sock == -1 && dt->is_udp == fd_sin_is_udp
                && !memcmp(&dt->ac->addr, &fd_sin, sizeof(fd_sin))) {
            dt->sock = fd;
            return;
        }
    }

    log_info("REPLACE[new daemon]: Socket handoff: closing excess socket for address %s", logf_anysin(&fd_sin));
    close(fd);
}

static void socks_import_fds(socks_cfg_t* socks_cfg, const int* fds, const size_t nfds)
{
    for (size_t i = 0; i < nfds; i++)
        socks_import_fd(socks_cfg, fds[i]);
}

/*********************
 * Public interfaces *
 *********************/

css_t* css_new(const char* argv0, socks_cfg_t* socks_cfg, csc_t** csc_p)
{
    csc_t* csc = NULL;
    if (csc_p) {
        csc = *csc_p;
        gdnsd_assert(csc);
    }

    int sock_fd = -1;
    char* lock_path = gdnsd_resolve_path_run(base_lock, NULL);
    int lock_fd = open(lock_path, O_RDONLY | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (lock_fd < 0)
        log_fatal("cannot open control sock lock at %s: %s", lock_path, logf_errno());

    if (flock(lock_fd, LOCK_EX | LOCK_NB)) {
        if (errno != EWOULDBLOCK)
            log_fatal("cannot lock control sock lock at %s: %s", lock_path, logf_errno());
        close(lock_fd);
        lock_fd = -1;
        if (!csc) {
            free(lock_path);
            return NULL;
        }
    } else if (csc) {
        log_warn("REPLACE[new daemon]: old daemon at %li appears to have exited while we were starting, executing a normal non-replace startup!",
                 (long)csc_get_server_pid(csc));
        csc_delete(csc);
        csc = NULL;
        *csc_p = NULL;
    }

    free(lock_path);

    if (csc) {
        csbuf_t req;
        csbuf_t resp;
        memset(&req, 0, sizeof(req));
        req.key = REQ_TAKE;
        req.d = (uint32_t)getpid();
        int* resp_fds = NULL;
        if (csc_txn_getfds(csc, &req, &resp, &resp_fds))
            log_fatal("REPLACE[new daemon]: Takeover request failed");
        gdnsd_assert(resp_fds);
        gdnsd_assert(csbuf_get_v(&resp) > 2U);
        gdnsd_assert(sock_fd == -1);
        gdnsd_assert(lock_fd == -1);
        // cppcheck-suppress resourceLeak (cppcheck can't follow the logic)
        lock_fd = resp_fds[0];
        sock_fd = resp_fds[1];
        size_t dns_fd_count = csbuf_get_v(&resp) - 2U;
        log_info("REPLACE[new daemon]: Takeover request accepted, received %zu DNS sockets", dns_fd_count);
        socks_import_fds(socks_cfg, &resp_fds[2], dns_fd_count);
        free(resp_fds);
    }

    css_t* css = xcalloc(sizeof(*css));
    css->lock_fd = lock_fd;
    css->argv0 = xstrdup(argv0);
    css->socks_cfg = socks_cfg;
    css->status_d = (uint32_t)getpid();
    uint8_t x;
    uint8_t y;
    uint8_t z;
    if (3 != sscanf(PACKAGE_VERSION, "%hhu.%hhu.%hhu", &x, &y, &z))
        log_fatal("BUG: Cannot parse our own package version");
    css->status_v = csbuf_make_v(x, y, z);

    if (sock_fd > -1) {
        css->fd = sock_fd;
    } else {
        css->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (css->fd < 0)
            log_fatal("Creating AF_UNIX socket failed: %s", logf_errno());

        char* sock_path = gdnsd_resolve_path_run(base_sock, NULL);
        struct sockaddr_un addr;
        const socklen_t addr_len = gdnsd_sun_set_path(&addr, sock_path);
        if (unlink(sock_path) && errno != ENOENT)
            log_fatal("unlink(%s) failed: %s", sock_path, logf_errno());

        // umask()-switching around the bind() seems safer against possible
        // perms races on various platforms than doing a chmod between bind()
        // and listen().  Note umask() isn't thread-safe, but css_new() is
        // called before any threads are created.
        const mode_t oldmask = umask(S_IXUSR | S_IRWXG | S_IRWXO); // 0177
        if (bind(css->fd, (struct sockaddr*)&addr, addr_len))
            log_fatal("bind() of unix domain socket %s failed: %s", sock_path, logf_errno());
        umask(oldmask);

        if (listen(css->fd, 100))
            log_fatal("Failed to listen() on control socket %s: %s", sock_path, logf_errno());
        free(sock_path);
    }

    ev_io* w_accept = &css->w_accept;
    ev_io_init(w_accept, css_accept, css->fd, EV_READ);
    w_accept->data = css;

    ev_timer* w_replace = &css->w_replace;
    ev_timer_init(w_replace, css_watch_replace, 1.0, 1.0);
    w_replace->data = css;

    return css;
}

void css_start(css_t* css, struct ev_loop* loop)
{
    css->loop = loop;
    ev_io* w_accept = &css->w_accept;
    ev_io_start(css->loop, w_accept);
    gdnsd_assert(css->socks_cfg->num_dns_threads);
    css->handoff_fds_count = css->socks_cfg->num_dns_threads + 2U;
    gdnsd_assert(css->handoff_fds_count <= 0xFFFFFF);
    css->handoff_fds = xmalloc_n(css->handoff_fds_count, sizeof(*css->handoff_fds));
    css->handoff_fds[0] = css->lock_fd;
    css->handoff_fds[1] = css->fd;
    for (unsigned i = 0; i < css->socks_cfg->num_dns_threads; i++)
        css->handoff_fds[i + 2] = css->socks_cfg->dns_threads[i].sock;
    log_debug("Entering runtime loop in main thread, listening to control socket");
}

bool css_notify_zone_reloaders(css_t* css, const bool failed)
{
    // Notify log and all waiting control sock clients of success/fail
    for (size_t i = 0; i < css->reload_zones_active.len; i++)
        respond(css->reload_zones_active.q[i], failed ? RESP_FAIL : RESP_ACK, 0, 0, NULL, NULL);

    // clear out the queue of clients waiting for reload status
    conn_queue_clear(&css->reload_zones_active);

    // Swap queues, and spawn another new update thread if more waiting clients
    // piled up during the previous reload
    swap_reload_zones_queues(css);

    // If the new active queue already had waiters,
    // return true to start another reload
    return !!css->reload_zones_active.len;
}

// During a "replace", this is the final communication over the daemon<->daemon
// control socket, and happens very late.  We're already past the point of no
// return (new sent REQ_STOP to old, and old ACK'd it), stats continuity
// isn't critical to operations, and no further communications are intended
// (including no response to this message) so failures here are non-fatal.
void css_send_stats_handoff(css_t* css)
{
    // no-op if we don't have a takeover connection from a newer daemon
    if (!css->replace_conn_dmn)
        return;

    css_conn_t* c = css->replace_conn_dmn;
    size_t dlen = 0;
    char* data = statio_serialize(&dlen);

    csbuf_t handoff;
    memset(&handoff, 0, sizeof(handoff));
    handoff.key = REQ_SHAND;
    csbuf_set_v(&handoff, 0);
    handoff.d = (uint32_t)dlen;
    ssize_t pktlen = send(c->fd, handoff.raw, 8, 0);
    if (pktlen != 8) {
        log_err("REPLACE[old daemon]: Stats handoff failed: blocking control socket write of 8 bytes failed with retval %zi: %s", pktlen, logf_errno());
        free(data);
        return;
    }

    size_t done = 0;
    while (done < dlen) {
        const size_t wanted = dlen - done;
        const ssize_t sent = send(c->fd, &data[done], wanted, 0);
        if (sent < 0) {
            log_err("REPLACE[old daemon]: Stats handoff failed: %zu-byte send() failed: %s", wanted, logf_errno());
            free(data);
            return;
        }
        done += (size_t)sent;
    }

    free(data);
}

void css_delete(css_t* css)
{
    // clean out active connections...
    css_conn_t* c = css->clients;
    while (c) {
        css_conn_t* next = c->next;
        css_conn_cleanup(c);
        c = next;
    }
    gdnsd_assert(!css->num_clients);

    // free up the reload queues
    conn_queue_clear(&css->reload_zones_queued);
    conn_queue_clear(&css->reload_zones_active);

    if (css->handoff_fds)
        free(css->handoff_fds);
    ev_io* w_accept = &css->w_accept;
    ev_io_stop(css->loop, w_accept);
    ev_timer* w_replace = &css->w_replace;
    ev_timer_stop(css->loop, w_replace);
    close(css->fd);
    close(css->lock_fd); // Closing the lock fd implicitly clears the lock
    free(css->argv0);
    free(css);
}
