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

#include "socks.h"

#include <gdnsd/compiler.h>
#include <gdnsd/stats.h>

#include <inttypes.h>
#include <stdbool.h>

// dnspacket-layer statistics, per-thread
typedef struct {
    bool is_udp;

    // Per-protocol stats
    union {
        struct { // UDP stats
            stats_t recvfail;
            stats_t sendfail;
            stats_t tc;
            stats_t edns_big;
            stats_t edns_tc;
        } udp;
        struct { // TCP stats
            stats_t recvfail;
            stats_t sendfail;
            stats_t conns;
            stats_t close_c;
            stats_t close_s_ok;
            stats_t close_s_err;
            stats_t close_s_kill;
            stats_t proxy;
            stats_t proxy_fail;
        } tcp;
    };

    // DNS layer stats, first 6 directly correspond to RCODEs
    // All 7, summed, represent the total count
    //  of requests received by the DNS layer.  Note that
    //  some of the earlier UDP/TCP-specific failures never make it to
    //  to the DNS layer.
    stats_t noerror;
    stats_t refused;
    stats_t nxdomain;
    stats_t notimp;
    stats_t badvers;
    stats_t formerr;
    stats_t dropped; // no response sent at all, horribly badly formatted

    // Count of requests over IPv6.  The only valid relation to other stats
    // is that you could compare it to the 7-stat sum above for a percentage
    stats_t v6;

    // Again, could be counted as a percentage of the 7-stat sum above
    stats_t edns;

    // A percentage of "edns" above:
    stats_t edns_clientsub;

    // edns requests with the DO (DNSSEC OK) bit set
    stats_t edns_do;

    // cookies: exactly one of these will increment for every client query
    // containing an EDNS Cookie option:
    stats_t edns_cookie_formerr; // RFC-illegal Cookie data length
    stats_t edns_cookie_ok;      // Valid server cookie issued by us
    stats_t edns_cookie_init;    // No server cookie sent at all
    stats_t edns_cookie_bad;     // Invalid server cookie (e.g. expired)
} dnspacket_stats_t;

// Per-connection DSO state-tracking between dnsio_tcp (TCP) + dnspacket at the
// boundary layer of invoking process_dns_query() (PDQ) for each req->resp
typedef struct {
    // last_was_ka: set false by TCP before PDQ always, PDQ sets true if
    // request was a DSO KeepAlive, so that dnsio_tcp knows not to bump the
    // server-side inactivity timer like it would for any other request.
    bool last_was_ka;
    // estab: False by default at thread start, PDQ sets permanently to true if
    // DSO is established by client DSO KeepAlive reception, which changes some
    // code behaviors on both sides.
    bool estab;
} dso_state_t;

struct dnsp_ctx; // opaque to outsiders
typedef struct dnsp_ctx dnsp_ctx_t;

F_HOT F_NONNULLX(1, 2, 3)
unsigned process_dns_query(dnsp_ctx_t* ctx, const gdnsd_anysin_t* sa, uint8_t* packet, dso_state_t* dso, const unsigned packet_len);

F_NONNULL F_WUNUSED F_RETNN
dnsp_ctx_t* dnspacket_ctx_init_udp(dnspacket_stats_t** stats_out, const bool is_ipv6);

F_NONNULL F_WUNUSED F_RETNN
dnsp_ctx_t* dnspacket_ctx_init_tcp(dnspacket_stats_t** stats_out, const bool pad, const unsigned timeout_secs);

// TCP threads call this on their context when they start graceful shutdown,
// telling the dnspacket layer to advertise inactivity timeouts of zero for the
// remainder of the daemon's life.
F_NONNULL
void dnspacket_ctx_set_grace(dnsp_ctx_t* ctx);

F_NONNULL
void dnspacket_ctx_cleanup(dnsp_ctx_t* ctx);

F_NONNULL
void dnspacket_global_setup(const socks_cfg_t* socks_cfg);
F_NONNULL
void dnspacket_wait_stats(const socks_cfg_t* socks_cfg);

extern dnspacket_stats_t** dnspacket_stats;

#endif // GDNSD_DNSPACKET_H
