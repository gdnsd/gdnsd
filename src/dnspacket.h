/* Copyright © 2012 Brandon L Black <blblack@gmail.com> and Jay Reitz <jreitz@gmail.com>
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

#ifndef GDNSD_DNSPACKET_H
#define GDNSD_DNSPACKET_H

#include "dnswire.h"
#include "statio.h"

#include <gdnsd/compiler.h>

#include <inttypes.h>
#include <stdbool.h>

// Per-connection DSO state-tracking between dnsio_tcp (TCP) + dnspacket at the
// boundary layer of invoking process_dns_query() (PDQ) for each req->resp
typedef struct {
    // last_was_ka: set false by TCP before PDQ always, PDQ sets true if
    // request was a DSO KeepAlive, so that dnsio_tcp knows not to bump the
    // server-side inactivity timer like it would for any other request.
    bool last_was_ka;
    // estab: False by default at conn start, PDQ sets permanently to true if
    // DSO is established by client DSO KeepAlive reception, which changes some
    // code behaviors on both sides.
    bool estab;
} dso_state_t;

struct dnsp_ctx; // opaque to outsiders
typedef struct dnsp_ctx dnsp_ctx_t;

typedef union {
    wire_dns_header_t hdr;
    uint8_t raw[MAX_RESPONSE_BUF];
} pkt_t;

F_HOT F_NONNULLX(1, 2, 3)
unsigned process_dns_query(dnsp_ctx_t* ctx, const gdnsd_anysin_t* sa, pkt_t* packet, dso_state_t* dso, const unsigned packet_len);

F_NONNULL F_WUNUSED F_RETNN
dnsp_ctx_t* dnspacket_ctx_init_udp(struct dns_stats** stats_out, const bool is_ipv6);

F_NONNULL F_WUNUSED F_RETNN
dnsp_ctx_t* dnspacket_ctx_init_tcp(struct dns_stats** stats_out, const bool pad, const unsigned timeout_secs);

// TCP threads call this on their context when they start graceful shutdown,
// telling the dnspacket layer to advertise inactivity timeouts of zero for the
// remainder of the daemon's life.
F_NONNULL
void dnspacket_ctx_set_grace(dnsp_ctx_t* ctx);

F_NONNULL
void dnspacket_ctx_cleanup(dnsp_ctx_t* ctx);

F_NONNULL
void dnspacket_global_setup(void);

#endif // GDNSD_DNSPACKET_H
