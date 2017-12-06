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
    unsigned timeout;
    pid_t server_pid;
    char* path;
    char server_vers[16];
};

static bool csc_get_status(csc_t* csc) {
    csbuf_t req, resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_INFO;
    if(csc_txn(csc, &req, &resp))
        return true;

    csc->server_pid = (pid_t)resp.d;
    int snp_rv = snprintf(csc->server_vers, 16, "%hhu.%hhu.%hhu",
                          resp.v0, resp.v1, resp.v2);
    gdnsd_assert(snp_rv >= 5 && snp_rv < 16);
    return false;
}

csc_t* csc_new(const unsigned timeout) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(fd < 0)
        log_fatal("socket(AF_UNIX, SOCK_STREAM, 0) failed: %s", logf_errno());

    const struct timeval tmout = { .tv_sec = timeout, .tv_usec = 0 };
    if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tmout, sizeof(tmout)))
        log_fatal("Failed to set SO_RCVTIMEO on control socket socket: %s", logf_errno());
    if(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tmout, sizeof(tmout)))
        log_fatal("Failed to set SO_SNDTIMEO on control socket socket: %s", logf_errno());

    char* path = gdnsd_resolve_path_run("control.sock", NULL);

    struct sockaddr_un addr;
    sun_set_path(&addr, path);
    if(connect(fd, (struct sockaddr*)&addr, sizeof(addr)))
        log_fatal("connect() to unix domain socket %s failed: %s", path, logf_errno());

    csc_t* csc = xcalloc(1, sizeof(*csc));
    csc->fd = fd;
    csc->path = path;
    csc->timeout = timeout;

    if(csc_get_status(csc))
        log_fatal("Failed to get server status over control socket %s", csc->path);

    return csc;
}

pid_t csc_get_server_pid(const csc_t* csc) {
    return csc->server_pid;
}

const char* csc_get_server_version(const csc_t* csc) {
    return csc->server_vers;
}

bool csc_txn(csc_t* csc, const csbuf_t* req, csbuf_t* resp) {
    ssize_t pktlen = send(csc->fd, req->raw, 8, 0);
    if(pktlen != 8) {
        log_err("8-byte send() failed with retval %zi: %s", pktlen, logf_errno());
        return true;
    }

    pktlen = recv(csc->fd, resp->raw, 8, 0);
    if(pktlen != 8) {
        log_err("8-byte recv() failed with retval %zi: %s", pktlen, logf_errno());
        return true;
    }

    if(resp->key != RESP_ACK)
        return true;

    return false;
}

bool csc_txn_getdata(csc_t* csc, const csbuf_t* req, csbuf_t* resp, char** resp_data) {
    if(csc_txn(csc, req, resp))
        return true;

    gdnsd_assert(resp->d);
    const size_t total = resp->d;
    char* rd = xmalloc(total);
    size_t done = 0;

    while(done < total) {
        const size_t wanted = total - done;
        const ssize_t pktlen = recv(csc->fd, &rd[done], wanted, 0);
        if(pktlen < 0) {
            free(rd);
            log_err("%zu-byte recv() failed: %s", wanted, logf_errno());
            return true;
        }
        done += (size_t)pktlen;
    }

    *resp_data = rd;
    return false;
}

bool csc_stop_server(csc_t* csc) {
    csbuf_t req, resp;
    memset(&req, 0, sizeof(req));
    req.key = REQ_STOP;
    if(csc_txn(csc, &req, &resp)) {
        log_err("Server stop transaction failed");
        return true;
    }

    // Wait for server to close our csock fd as it exits
    char x;
    ssize_t recv_rv = recv(csc->fd, &x, 1, 0);
    if(recv_rv) {
        if(recv_rv < 0)
            log_err("Error while waiting for server close: %s", logf_errno());
        else
            log_err("Got data byte '%c' while waiting for server close", x);
        return true;
    }

    // Wait timeout in 10ms increments for pid to exit
    const struct timespec ts = { 0, 10000000 };
    size_t tries = 100U * csc->timeout;
    while(tries--) {
        nanosleep(&ts, NULL);
        if(kill(csc->server_pid, 0))
            return false;
    }
    return true;
}

void csc_delete(csc_t* csc) {
    close(csc->fd);
    free(csc->path);
    free(csc);
}
