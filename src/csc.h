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

#ifndef GDNSD_CSC_H
#define GDNSD_CSC_H

#include <gdnsd/compiler.h>

#include "cs.h"

#include <stdbool.h>
#include <sys/types.h>
#include <inttypes.h>
#include <stddef.h>

// Opaque server and client objects
struct csc_s_;
typedef struct csc_s_ csc_t;

// Enum for certain transaction retvals below
// OK -> Transaction successful
// FAIL_HARD -> Transaction actively rejected by daemon with RESP_FAIL
// FAIL_SOFT -> Communications error or daemon sent RESP_LATR
typedef enum {
    CSC_TXN_OK = 0,
    CSC_TXN_FAIL_HARD = 1,
    CSC_TXN_FAIL_SOFT = 2,
} csc_txn_rv_t;

// Note this client API assumes a simple, relatively-stateless commandline
// client with blocking serial execution, or the special case uses of this
// object by daemon takeover operations.  All network i/o is blocking.  Other
// clients could be written which are more asynch and advanced.

// Opens a control socket connection handle.
// "timeout" is in seconds, and sets socket-level send+receive timeouts.
//           if this is zero, no timeouts are set and blocking is indefinite.
// "pfx" is a constant string used to prefix log outputs for the replace case
// Fails fatally on certain un-retryable failures (failure to allocate a unix
// socket fd, failure set timeouts on socket, or control socket pathname too
// long for platform limits).  Returns NULL on retryable failures (failure to
// connect, failure to get a valid response to a basic status inquiry over the
// new socket).  If return value is non-NULL, the object is connected validly
// to a live daemon and knows the daemon's basic status info (pid, version).
F_NONNULL
csc_t* csc_new(const unsigned timeout, const char* pfx);

// Get basic info about server on other side of controlsock (this is fetched
// via the "status" command immediately after starting a new connection above,
// and these APIs return the client-side cached data).
F_NONNULL F_PURE
pid_t csc_get_server_pid(const csc_t* csc);
F_NONNULL F_PURE F_RETNN
const char* csc_get_server_version(const csc_t* csc);

// Boolean check if server version is >= M.m.p, using the same cached version
// info as csc_get_server_version() above
F_NONNULL F_PURE
bool csc_server_version_gte(const csc_t* csc, const uint8_t major, const uint8_t minor, const uint8_t patch);

// Performs a basic req->resp transaction using csbuf_t objects, with no
// extra or ancillary data moving in either direction.
F_NONNULL
csc_txn_rv_t csc_txn(csc_t* csc, const csbuf_t* req, csbuf_t* resp);

// As above, but expects server's resp.d to contain a length of followup data,
// which will be received and placed in newly-allocated storage at *resp_data
// for the caller to consume and free
F_NONNULL
csc_txn_rv_t csc_txn_getdata(csc_t* csc, const csbuf_t* req, csbuf_t* resp, char** resp_data);

// As above, but data is sent with the request instead of received from the
// response.  req_data must be non-NULL and heap-allocated, and will be freed
// by this function before returning.  Caller is responsible for setting req.d
// to the length of the req_data in bytes (non-zero), and req.v to whatever
// value is appropriate for the action.
F_NONNULL
csc_txn_rv_t csc_txn_senddata(csc_t* csc, const csbuf_t* req, csbuf_t* resp, char* req_data);

// As above, but expects server's resp.v to contain a count of file descriptors
// sent over SCM_RIGHTS, which will be received and placed in newly-allocated
// storage at *resp_fds for the caller to consume and free.  This is only
// intended for use in daemon<->daemon takeover connections.
F_NONNULL
bool csc_txn_getfds(csc_t* csc, const csbuf_t* req, csbuf_t* resp, int** resp_fds);

// Request the server to shut down.  Non-failing response (false) means the
// server accepted the command and intends to stop, but does not mean it has
// actually finished shutdown yet.  This is just a simple wrapper around
// csc_txn() sending REQ_STOP.
F_NONNULL
csc_txn_rv_t csc_stop_server(csc_t* csc);

// This function witnesses a server stop by watching for the daemon to
// close the csc object's control socket connection as it is exiting.
// rv true == failure, false == success
F_NONNULL
bool csc_wait_stopping_server(csc_t* csc);

// Used during daemon->daemon takeover, to hand off final stats into the
// baseline of the new daemon.
F_NONNULL
size_t csc_get_stats_handoff(csc_t* csc, uint64_t** raw_u64);

// destructs the control socket handle
F_NONNULL
void csc_delete(csc_t* csc);

#endif // GDNSD_CSC_H
