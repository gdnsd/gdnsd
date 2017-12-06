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

// Opaque server and client objects
struct csc_s_;
typedef struct csc_s_ csc_t;

// Note the current client API assumes a simple, relatively-stateless
// commandline client with blocking serial execution.  All network i/o is
// blocking.

// Opens a control socket connection handle.
// "timeout" is in seconds, and sets socket-level send/receive timeouts
// Fails fatally or returns a valid csc object
F_RETNN
csc_t* csc_new(const unsigned timeout);

// Get basic info about server on other side of controlsock (this is fetched
// via the "status" command immediately after starting a new connection above,
// and these APIs return the client-side cached data).
pid_t csc_get_server_pid(const csc_t* csc);
const char* csc_get_server_version(const csc_t* csc);

// Performs a transaction using csbuf_t's
// retval - false for success, true for failure
F_NONNULL
bool csc_txn(csc_t* csc, const csbuf_t* req, csbuf_t* resp);

// As above, but expects server's resp.d to contain a length of followup data,
// which will be received and placed in newly-allocated storage at *resp_data
// for the caller to consume and free
F_NONNULL
bool csc_txn_getdata(csc_t* csc, const csbuf_t* req, csbuf_t* resp, char** resp_data);

// built in server "stop" management.
F_NONNULL
bool csc_stop_server(csc_t* csc);

// destructs the control socket handle
F_NONNULL
void csc_delete(csc_t* csc);

#endif // GDNSD_CSC_H
