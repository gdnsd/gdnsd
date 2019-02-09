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

struct csc_s_ {
    int fd;
    pid_t server_pid;
    char* path;
    char server_vers[16];
    uint8_t svers_major;
    uint8_t svers_minor;
    uint8_t svers_patch;
};

static bool csc_get_status(csc_t* csc)
{
    csbuf_t req;
    csbuf_t resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_INFO;
    if (csc_txn(csc, &req, &resp))
        return true;

    csc->server_pid = (pid_t)resp.d;
    csc->svers_major = resp.v0;
    csc->svers_minor = resp.v1;
    csc->svers_patch = resp.v2;

    // During some release >= 3.1.0, we can remove 2.99.x-beta compat here by
    // making resp.v0 < 3 a fatal condition

    int snp_rv = snprintf(csc->server_vers, 16, "%hhu.%hhu.%hhu",
                          resp.v0, resp.v1, resp.v2);
    gdnsd_assert(snp_rv >= 5 && snp_rv < 16);
    return false;
}

csc_t* csc_new(const unsigned timeout, const char* pfx)
{
    csc_t* csc = xcalloc(sizeof(*csc));
    csc->path = gdnsd_resolve_path_run("control.sock", NULL);

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        log_fatal("%sCreating AF_UNIX socket failed: %s", pfx, logf_errno());
    csc->fd = fd;

    if (timeout) {
        const struct timeval tmout = { .tv_sec = timeout, .tv_usec = 0 };
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tmout, sizeof(tmout)))
            log_fatal("%sFailed to set SO_RCVTIMEO on control socket: %s", pfx, logf_errno());
        if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tmout, sizeof(tmout)))
            log_fatal("%sFailed to set SO_SNDTIMEO on control socket: %s", pfx, logf_errno());
    }

    struct sockaddr_un addr;
    const socklen_t addr_len = gdnsd_sun_set_path(&addr, csc->path);
    if (connect(fd, (struct sockaddr*)&addr, addr_len)) {
        log_err("%sconnect() to unix domain socket %s failed: %s", pfx, csc->path, logf_errno());
        close(fd);
        free(csc->path);
        free(csc);
        csc = NULL;
    } else if (csc_get_status(csc)) {
        log_err("%sFailed to get daemon status over control socket %s", pfx, csc->path);
        close(fd);
        free(csc->path);
        free(csc);
        csc = NULL;
    }

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

bool csc_server_version_gte(const csc_t* csc, const uint8_t major, const uint8_t minor, const uint8_t patch)
{
    return (
               csc->svers_major > major
               || (csc->svers_major == major && csc->svers_minor > minor)
               || (csc->svers_major == major && csc->svers_minor == minor && csc->svers_patch >= patch)
           );
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
                log_err("recvmsg(): ancillary data for socket handoff was truncated (open files ulimit too small?)");
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

csc_txn_rv_t csc_txn(csc_t* csc, const csbuf_t* req, csbuf_t* resp)
{
    ssize_t pktlen = send(csc->fd, req->raw, 8, 0);
    if (pktlen != 8) {
        log_err("8-byte send() failed with retval %zi: %s", pktlen, logf_errno());
        return CSC_TXN_FAIL_SOFT;
    }

    pktlen = recv(csc->fd, resp->raw, 8, 0);
    if (pktlen != 8) {
        log_err("8-byte recv() failed with retval %zi: %s", pktlen, logf_errno());
        return CSC_TXN_FAIL_SOFT;
    }

    if (resp->key == RESP_ACK)
        return CSC_TXN_OK;

    if (resp->key == RESP_LATR)
        return CSC_TXN_FAIL_SOFT;

    return CSC_TXN_FAIL_HARD;
}

csc_txn_rv_t csc_txn_getdata(csc_t* csc, const csbuf_t* req, csbuf_t* resp, char** resp_data)
{
    csc_txn_rv_t rv = csc_txn(csc, req, resp);
    if (rv != CSC_TXN_OK)
        return rv;

    char* rd = NULL;

    if (resp->d) {
        const size_t total = resp->d;
        rd = xmalloc(total);
        size_t done = 0;

        while (done < total) {
            const size_t wanted = total - done;
            const ssize_t pktlen = recv(csc->fd, &rd[done], wanted, 0);
            if (pktlen <= 0) {
                free(rd);
                log_err("%zu-byte recv() failed: %s", wanted, logf_errno());
                return CSC_TXN_FAIL_HARD;
            }
            done += (size_t)pktlen;
        }
    }

    *resp_data = rd;
    return CSC_TXN_OK;
}

csc_txn_rv_t csc_txn_senddata(csc_t* csc, const csbuf_t* req, csbuf_t* resp, char* req_data)
{
    gdnsd_assert(req->d);

    ssize_t pktlen = send(csc->fd, req->raw, 8, 0);
    if (pktlen != 8) {
        log_err("8-byte send() failed with retval %zi: %s", pktlen, logf_errno());
        return CSC_TXN_FAIL_SOFT;
    }

    const size_t total = req->d;
    size_t done = 0;

    while (done < total) {
        const size_t wanted = total - done;
        const ssize_t sent = send(csc->fd, &req_data[done], wanted, 0);
        if (sent < 0) {
            free(req_data);
            log_err("%zu-byte send() failed: %s", wanted, logf_errno());
            return CSC_TXN_FAIL_SOFT;
        }
        done += (size_t)sent;
    }

    free(req_data);

    pktlen = recv(csc->fd, resp->raw, 8, 0);
    if (pktlen != 8) {
        log_err("8-byte recv() failed with retval %zi: %s", pktlen, logf_errno());
        return CSC_TXN_FAIL_SOFT;
    }

    if (resp->key == RESP_ACK)
        return CSC_TXN_OK;

    if (resp->key == RESP_LATR)
        return CSC_TXN_FAIL_SOFT;

    return CSC_TXN_FAIL_HARD;
}

bool csc_wait_stopping_server(csc_t* csc)
{
    // Wait for server to close our csock fd as it exits
    char x;
    ssize_t recv_rv = recv(csc->fd, &x, 1, 0);
    if (recv_rv == 0)
        return false;
    return true;
}

csc_txn_rv_t csc_stop_server(csc_t* csc)
{
    csbuf_t req;
    csbuf_t resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_STOP;
    return csc_txn(csc, &req, &resp);
}

size_t csc_get_stats_handoff(csc_t* csc, uint64_t** raw_u64)
{
    // During some release >= 3.1.0, we can remove 2.99.x-beta compat here by
    // assuming all daemons with listening control sockets have a major >= 3
    // and send stats handoff
    if (!csc_server_version_gte(csc, 2, 99, 200))
        return 0;

    csbuf_t handoff;
    memset(&handoff, 0, sizeof(handoff));

    ssize_t pktlen = recv(csc->fd, handoff.raw, 8, 0);
    if (pktlen != 8) {
        log_err("REPLACE[new daemon]: Stats handoff failed: 8-byte recv() failed with retval %zi: %s", pktlen, logf_errno());
        return 0;
    }

    if (handoff.key != REQ_SHAND) {
        log_err("REPLACE[new daemon]: Stats handoff failed: wrong key %hhx", handoff.key);
        return 0;
    }

    // Current dlen for this is 200 bytes, it's unlikely we'll ever have so
    // many stats defined that we reach 64K, and this avoids potential buggy
    // situations where the old server asks us to malloc huge sizes below
    if (!handoff.d || handoff.d > UINT16_MAX) {
        log_err("REPLACE[new daemon]: Stats handoff failed: bad data length %" PRIu32, handoff.d);
        return 0;
    }

    const size_t total = handoff.d;
    void* raw_data = xmalloc(total);
    char* raw_char = raw_data;
    size_t done = 0;

    while (done < total) {
        const size_t wanted = total - done;
        pktlen = recv(csc->fd, &raw_char[done], wanted, 0);
        if (pktlen <= 0) {
            free(raw_data);
            log_err("REPLACE[new daemon]: Stats handoff failed: %zu-byte recv() failed: %s", wanted, logf_errno());
            return 0;
        }
        done += (size_t)pktlen;
    }

    *raw_u64 = (uint64_t*)raw_data;
    return done;
}

void csc_delete(csc_t* csc)
{
    close(csc->fd);
    free(csc->path);
    free(csc);
}
