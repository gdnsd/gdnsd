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

#ifndef GDNSD_CSS_H
#define GDNSD_CSS_H

#include <gdnsd/compiler.h>

#include "csc.h"
#include "socks.h"

#include <stdbool.h>
#include <inttypes.h>
#include <sys/types.h>

#include <ev.h>

// This header provides APIs for a basic control socket server.
// The underlying protocol is simple:
// 1. All data flow is serial client_request->server_response transactions;
//    there is no unprompted server-pushed output, and no new requests from
//    the client will be accepted until after the server response to the
//    previous request is buffered into the socket.
// 2. All messages are single chunks of binary data, with an implementation
//    defined maximum possible length of UINT32_MAX (~4GB).
// 3. Each request or response starts with a 4 byte unsigned length value in
//    native byte order.  Length zero is illegal in both directions.
// 4. Any communications error, or a length value from the client exceeding the
//    server's max_client_req parameter will result in immediate connection
//    termination and cleanup.

// Opaque server objects
struct css_s_;
typedef struct css_s_ css_t;

// Create a new control socket server:
// * argv0 is the original argv[0] of gdnsd, intended to use for spawning a
// replacement.
// * Most errors are fatal, but in the special case that "csc" is NULL and we
// detect the socket is already locked by another daemon instance, this
// function returns NULL.
// * If csc_p is non-NULL, *csc_p must also be non-NULL, and we will attempt
// graceful takeover from the running daemon connected to *csc_p if the control
// socket lock is still held, and fall back to attempting non-takeover startup
// if it is not held.  Either way, either a valid "css" will be returned or
// this function will fail fatally.  If the csc connection was used for
// takeover, *csc will retain its original value.  If it was not used (we were
// able to obtain the lock normally), csc will be closed/deleted and *csc_p set
// to NULL.
F_NONNULLX(1,2)
css_t* css_new(const char* argv0, socks_cfg_t* socks_cfg, csc_t** csc_p);

// Start accepting connections within libev loop "loop".
F_NONNULL
void css_start(css_t* css, struct ev_loop* loop);

// After zone reloading completes in main.c, it calls here to notify waiting
// control socket clients of success/fail.  Return value of true indicates that
// more waiters queued up during the reload, so main.c needs to start yet
// another reload operation.
bool css_notify_zone_reloaders(css_t* css, const bool failed);

// Check whether a stop (e.g. via signal) is currently ok or not (due to
// impending replacement/takeover operation)
bool css_stop_ok(css_t* css);

// Stop all traffic and destruct all resources (css itself is freed as well)
F_NONNULL
void css_delete(css_t* css);

#endif // GDNSD_CSS_H
