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
#include "csc.h"

#include <gdnsd/compiler.h>
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/paths.h>
#include <gdnsd/net.h>

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/file.h>

static const char repl_pfx_normal[] = "";
static const char repl_pfx_replace[] = "REPLACE[new daemon]: ";
static const char repl_pfx_replace_old[] = "REPLACE[new daemon]: old ";

struct csc_s_ {
    int fd;
    unsigned timeout;
    pid_t server_pid;
    char* path;
    char server_vers[16];
    const char* repl_pfx;
    const char* repl_pfx_old;
};

static bool csc_get_status(csc_t* csc)
{
    csbuf_t req, resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_INFO;
    if (csc_txn(csc, &req, &resp))
        return true;

    csc->server_pid = (pid_t)resp.d;
    int snp_rv = snprintf(csc->server_vers, 16, "%hhu.%hhu.%hhu",
                          resp.v0, resp.v1, resp.v2);
    gdnsd_assert(snp_rv >= 5 && snp_rv < 16);
    return false;
}

csc_t* csc_new(const unsigned timeout, const bool replace)
{
    csc_t* csc = xcalloc(sizeof(*csc));
    csc->timeout = timeout;
    csc->repl_pfx = replace ? repl_pfx_replace : repl_pfx_normal;
    csc->repl_pfx_old = replace ? repl_pfx_replace_old : repl_pfx_normal;

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        log_fatal("%sCreating AF_UNIX socket failed: %s", csc->repl_pfx, logf_errno());
    csc->fd = fd;

    const struct timeval tmout = { .tv_sec = timeout, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tmout, sizeof(tmout)))
        log_fatal("%sFailed to set SO_RCVTIMEO on control socket: %s", csc->repl_pfx, logf_errno());
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tmout, sizeof(tmout)))
        log_fatal("%sFailed to set SO_SNDTIMEO on control socket: %s", csc->repl_pfx, logf_errno());

    char* path = gdnsd_resolve_path_run("control.sock", NULL);
    csc->path = path;

    struct sockaddr_un addr;
    sun_set_path(&addr, path);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)))
        log_fatal("%sconnect() to unix domain socket %s failed: %s", csc->repl_pfx, path, logf_errno());

    if (csc_get_status(csc))
        log_fatal("%sFailed to get daemon status over control socket %s", csc->repl_pfx, csc->path);

    return csc;
}

pid_t csc_get_server_pid(const csc_t* csc)
{
    return csc->server_pid;
}

const char* csc_get_server_version(const csc_t* csc)
{
    return csc->server_vers;
}

F_NONNULL
bool csc_txn_getfds(csc_t* csc, const csbuf_t* req, csbuf_t* resp, int** resp_fds)
{
    ssize_t pktlen = send(csc->fd, req->raw, 8, 0);
    if (pktlen != 8) {
        log_err("8-byte send() failed with retval %zi: %s", pktlen, logf_errno());
        return true;
    }

    union {
        struct cmsghdr c;
        char cmsg_buf[CMSG_SPACE(sizeof(int) * SCM_MAX_FDS)];
    } u;
    struct iovec iov = { .iov_base = resp->raw, .iov_len  = 8 };
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    size_t fds_wanted = 0; // don't know till first recvmsg
    size_t fds_recvd = 0;
    int* fds = NULL;

    do {
        memset(u.cmsg_buf, 0, sizeof(u.cmsg_buf));
        msg.msg_control = u.cmsg_buf;
        msg.msg_controllen = sizeof(u.cmsg_buf);

        pktlen = recvmsg(csc->fd, &msg, MSG_CMSG_CLOEXEC);
        if (pktlen != 8 || msg.msg_flags & MSG_CTRUNC) {
            if (pktlen != 8)
                log_err("8-byte recvmsg() failed with retval %zi: %s", pktlen, logf_errno());
            if (msg.msg_flags & MSG_CTRUNC)
                log_err("recvmsg() got truncated ancillary data");
            if (fds)
                free(fds);
            return true;
        }

        if (!fds) {
            // first time through loop
            if (resp->key != RESP_ACK)
                return true;
            fds_wanted = csbuf_get_v(resp);
            gdnsd_assert(fds_wanted > 2);
            fds = xmalloc_n(fds_wanted, sizeof(*fds));
        } else {
            // all later iterations of the loop
            gdnsd_assert(RESP_ACK == resp->key);
            gdnsd_assert(fds_wanted == csbuf_get_v(resp));
        }

        bool got_some_fds = false;

        if (msg.msg_controllen) {
            for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
                    const size_t dlen = cmsg->cmsg_len - CMSG_LEN(0);
                    gdnsd_assert((dlen % sizeof(int)) == 0);
                    const size_t nfds = dlen / sizeof(int);
                    if (nfds + fds_recvd <= fds_wanted) {
                        memcpy(&fds[fds_recvd], CMSG_DATA(cmsg), dlen);
                        fds_recvd += nfds;
                        got_some_fds = true;
                    } else {
                        log_err("REPLACE[new daemon]: Received more SCM_RIGHTS fds than expected!");
                    }
                }
            }
        }

        if (!got_some_fds) {
            log_err("REPLACE[new daemon]: recvmsg() failed to get SCM_RIGHTS fds after %zu of %zu expected", fds_recvd, fds_wanted);
            free(fds);
            return true;
        }
    } while (fds_recvd < fds_wanted);

    *resp_fds = fds;
    return false;
}

bool csc_txn(csc_t* csc, const csbuf_t* req, csbuf_t* resp)
{
    ssize_t pktlen = send(csc->fd, req->raw, 8, 0);
    if (pktlen != 8) {
        log_err("8-byte send() failed with retval %zi: %s", pktlen, logf_errno());
        return true;
    }

    pktlen = recv(csc->fd, resp->raw, 8, 0);
    if (pktlen != 8) {
        log_err("8-byte recv() failed with retval %zi: %s", pktlen, logf_errno());
        return true;
    }
    if (resp->key != RESP_ACK)
        return true;

    return false;
}

bool csc_txn_getdata(csc_t* csc, const csbuf_t* req, csbuf_t* resp, char** resp_data)
{
    if (csc_txn(csc, req, resp))
        return true;

    gdnsd_assert(resp->d);
    const size_t total = resp->d;
    char* rd = xmalloc(total);
    size_t done = 0;

    while (done < total) {
        const size_t wanted = total - done;
        const ssize_t pktlen = recv(csc->fd, &rd[done], wanted, 0);
        if (pktlen < 0) {
            free(rd);
            log_err("%zu-byte recv() failed: %s", wanted, logf_errno());
            return true;
        }
        done += (size_t)pktlen;
    }

    *resp_data = rd;
    return false;
}

bool csc_txn_senddata(csc_t* csc, const csbuf_t* req, csbuf_t* resp, char* req_data)
{
    gdnsd_assert(req->d);

    ssize_t pktlen = send(csc->fd, req->raw, 8, 0);
    if (pktlen != 8) {
        log_err("8-byte send() failed with retval %zi: %s", pktlen, logf_errno());
        return true;
    }

    const size_t total = req->d;
    size_t done = 0;

    while (done < total) {
        const size_t wanted = total - done;
        const ssize_t sent = send(csc->fd, &req_data[done], wanted, 0);
        if (sent < 0) {
            free(req_data);
            log_err("%zu-byte send() failed: %s", wanted, logf_errno());
            return true;
        }
        done += (size_t)sent;
    }

    free(req_data);

    pktlen = recv(csc->fd, resp->raw, 8, 0);
    if (pktlen != 8) {
        log_err("8-byte recv() failed with retval %zi: %s", pktlen, logf_errno());
        return true;
    }
    if (resp->key != RESP_ACK)
        return true;

    return false;
}

bool csc_wait_stopping_server(csc_t* csc, const char* pfx)
{
    // wait_stopping_server is used both by the old daemon and gdnsdctl during
    // replace, so gdnsdctl needs to provide its own custom prefix
    if (!pfx)
        pfx = csc->repl_pfx_old;

    // Wait for server to close our csock fd as it exits
    char x;
    ssize_t recv_rv = recv(csc->fd, &x, 1, 0);
    if (recv_rv) {
        if (recv_rv < 0)
            log_err("%sdaemon connection error while waiting for close: %s", pfx, logf_errno());
        else
            log_err("%sdaemon send unexpected data byte '%c' while waiting for close", pfx, x);
        return true;
    }

    // Wait timeout in 10ms increments for pid to exit
    const struct timespec ts = { 0, 10000000 };
    size_t tries = 100U * csc->timeout;
    while (tries--) {
        nanosleep(&ts, NULL);
        if (kill(csc->server_pid, 0)) {
            log_info("%sdaemon at PID %li exited as commanded", pfx, (long)csc->server_pid);
            return false;
        }
    }

    log_err("%sdaemon at PID %li did not exit within ~%u seconds after stop, giving up", pfx, (long)csc->server_pid, csc->timeout);
    return true;
}

bool csc_stop_server(csc_t* csc)
{
    csbuf_t req, resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_STOP;
    if (csc_txn(csc, &req, &resp)) {
        log_err("%sdaemon at PID %li failed stop command", csc->repl_pfx_old, (long)csc->server_pid);
        return true;
    }
    log_debug("%sdaemon at PID %li accepted stop command", csc->repl_pfx_old, (long)csc->server_pid);
    return false;
}

void csc_delete(csc_t* csc)
{
    close(csc->fd);
    free(csc->path);
    free(csc);
}
