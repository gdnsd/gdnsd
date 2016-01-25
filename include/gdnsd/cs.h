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

#ifndef GDNSD_CS_H
#define GDNSD_CS_H

#include <gdnsd/compiler.h>

#include <stdbool.h>
#include <inttypes.h>
#include <sys/types.h>

#include <ev.h>

// This header provides APIs for a basic control socket server and client.
// The underlying protocol they speak over the socket is simple:
// 1. All data flow is serial client_request->server_response transactions;
//    there is no unprompted server-pushed output, and no new requests from
//    the client will be accepted until after the server response to the
//    previous request is buffered into the socket.
// 2. All messages are single chunks of binary data, with an implementation
//    defined maximum possible length of UINT32_MAX (~4GB).
// 3. Each request or response starts with a 4 byte length value in native
//    byte order.  Length zero is illegal in both directions.
// 4. Any communications error or data sizes exceeding the soft maximums
//    specified when starting the server will result in immediate connection
//    termination and cleanup.
//
// All control-socket servers get two built-in transaction handlers for free:
// "ping" -> responds with "pong"
// "getpid" -> responds with the server's PID in ASCII Decimal form

// Opaque server and client objects
struct gdnsd_css_s_;
typedef struct gdnsd_css_s_ gdnsd_css_t;

struct gdnsd_csc_s_;
typedef struct gdnsd_csc_s_ gdnsd_csc_t;

/**************
 * Server API *
 *************/

// This is the css (control socket server) callback function prototype.
// css - the server object returned from _new()
// clid - unique identifier for this client in this gdnsd_css_t
// buffer - contains client input, is allocated to the greater of
//          max_buffer_(in|out) from gdnsd_css_new()
// len - length of client input
// data - opaque generic context data pointer you provided to gdnsd_css_new()
// retval - true -> close client connection immediately with no response
//                  (even if you called css_respond() inside this call!)
//          false -> hold client open for a response
// note: "buffer" can also be used to buffer your response - your code owns it
//       until you invoke gdnsd_css_respond() with this clid, or
//       invoke gdnsd_css_delete() to tear down the whole server
typedef bool (*gdnsd_css_rcb_t)(gdnsd_css_t* css, uint64_t clid, uint8_t* buffer, uint32_t len, void* data);

#pragma GCC visibility push(default)

// Create a new control socket server:
// path - the fileystem pathname of the socket to create
// rcb - your request read callback
// data - opaque generic context data pointer for your callback
// max_buffer_(in|out) - set limits on input and output sizes, respectively.
//    (the shared buffer will be allocated to the greater of the two values)
// max_clients - server will stop accept()ing new clients when this many are
//    connected in parallel
// timeout - transaction timeout from initial connection open (or end of
//    previous transaction if client sending multiple per connection) for the
//    client to send us a complete request and for us to push the full response
//    back into the socket buffer.  Note this won't/can't be enforced *during*
//    the request-processing callback (which should be fast - it's holding up
//    an eventloop with other things going on...), but will be immediately
//    after it returns if applicable.
F_NONNULLX(1,2) F_MALLOC
gdnsd_css_t* gdnsd_css_new(const char* path, gdnsd_css_rcb_t rcb, void* data, uint32_t max_buffer_in, uint32_t max_buffer_out, unsigned max_clients, unsigned timeout);

// Start accepting connections using libev loop "loop"
F_NONNULL
void gdnsd_css_start(gdnsd_css_t* css, struct ev_loop* loop);

// Re-create the listening socket, without affecting any ongoing clients.
// This will effectively create a new listening socket, unlink the socket
// path, and bind the new socket to the socket path.
F_NONNULL
void gdnsd_css_recreate(gdnsd_css_t* css);

// Respond to a request received via the rcb callback
// clid   - unique client ID from rcb callback
// buffer - contains up to max_buffer_out data
// len    - the length of the actual response in buffer
// note: this can be called from within the rcb read callback
// note: "buffer" can be the buffer received in the rcb callback,
//     or can be a new buffer belonging to the caller.  If it's a
//     new buffer, it will be copied immediately and can be freed
//     or reused after this call returns.  max_buffer_out still
//     applies either way.
// note: there is no indication of success - the response is blind
//     from the caller's perspective - the client could have even
//     closed the connection while waiting, in which case the
//     response will be discarded.
F_NONNULL
void gdnsd_css_respond(gdnsd_css_t* css, uint64_t clid, uint8_t* buffer, uint32_t len);

// Stop all traffic and destruct all resources (css itself is freed as well)
F_NONNULL
void gdnsd_css_delete(gdnsd_css_t* css);

/**************
 * Client API *
 *************/

// Note the current client API assumes a simple, stateless commandline client
// with blocking serial execution, which probably only executes a single
// transaction per invocation.  All network i/o is blocking without explicit
// timeouts; it is assumed the client can wrap transactions in SIGARLM -type
// timeouts if neccessary.  Any failure aborts client execution with an error
// message.

// Opens a control socket connection handle
F_NONNULL F_MALLOC
gdnsd_csc_t* gdnsd_csc_new(const char* path);

// Performs a transaction:
// buffer       - contains request data, will be used to store response data
// req_len      - length of request data
// max_resp_len - maximum acceptable response length - buffer should be
//                allocated sufficiently for this!
// return value - actual length of response data
F_NONNULL
uint32_t gdnsd_csc_txn(gdnsd_csc_t* csc, uint8_t* buffer, uint32_t req_len, uint32_t max_resp_len);

// blocking wait for server to close control socket (e.g. for monitoring other side's requested exit)
F_NONNULL
void gdnsd_csc_closewait(gdnsd_csc_t* csc);

// invoke built-in server "ping" function - retval false for success, true for failure
F_NONNULL
bool gdnsd_csc_ping(gdnsd_csc_t* csc);

// invoke built-in server "getpid" function
F_NONNULL
pid_t gdnsd_csc_getpid(gdnsd_csc_t* csc);

// destructs the control socket handle
F_NONNULL
void gdnsd_csc_delete(gdnsd_csc_t* csc);

#pragma GCC visibility pop

#endif // GDNSD_CS_H
