/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
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

#ifndef GDSND_STATIO_H
#define GDSND_STATIO_H

#include <gdnsd/compiler.h>

#include <sys/types.h>
#include <inttypes.h>
#include <stdbool.h>

#include "socks.h"
#include "stats.h"

// per-thread statistics.  The alignment of the linked list entry at the top
// assures alignment/padding of the whole struct such that it doesn't
// accidentally have false sharing with other per-thread memory that churns
// locally and isn't intended for x-thread access.
struct dns_stats {
    alignas(CACHE_ALIGN) struct dns_stats* next;
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
            stats_t dso_estab;
            stats_t dso_protoerr;
            stats_t dso_typeni;
            stats_t acceptfail;
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

    // DNSSEC NXDC stats:
    stats_t dnssec_nxdc_hit;   // cache hit (previously synthed+cached)
    stats_t dnssec_nxdc_synth; // cache miss -> rate ok -> synth+cache+respond
    // nxdc_signs mirrors nxdc_synth if all signed zones always have exactly
    // one ZSK, but will be larger otherwise, and in mixed/variable ZSK
    // scenarios this will more-closely correlate with CPU impact of crypto ops
    stats_t dnssec_nxdc_signs;
    stats_t dnssec_nxdc_drop;  // cache miss -> rate exceeded -> drop
};

F_NONNULL
void statio_register_thread_stats(struct dns_stats* stats);

F_NONNULL
void statio_init(void);

F_NONNULL F_RETNN
char* statio_get_json(time_t nowish, size_t* len);

F_NONNULL F_MALLOC
char* statio_serialize(size_t* dlen_p);

F_NONNULL
void statio_deserialize(uint64_t* data, size_t dlen);

#endif // GDSND_STATIO_H
