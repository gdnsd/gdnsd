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

#include "config.h"
#include "ltree.h"
#include <gdnsd/misc.h>
#include <gdnsd/stats.h>

#define COMPTARGETS_MAX 256

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
} dnspacket_stats_t;

F_HOT F_NONNULL
unsigned process_dns_query(void* ctx_asvoid, dnspacket_stats_t* stats, const dmn_anysin_t* asin, uint8_t* packet, const unsigned packet_len);

F_MALLOC
dnspacket_stats_t* dnspacket_stats_init(const unsigned this_threadnum, const bool is_udp);
F_MALLOC
void* dnspacket_ctx_init(const bool is_udp);

void dnspacket_global_setup(void);
void dnspacket_wait_stats(void);

extern dnspacket_stats_t** dnspacket_stats;

#endif // GDNSD_DNSPACKET_H
