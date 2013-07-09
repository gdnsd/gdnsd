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
#include "gdnsd/misc.h"

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

typedef struct {
    const uint8_t* original; // Alias to the original uncompressed dname's data (not the len byte)
    const uint8_t* comp_ptr; // where compression occurred on storage (could be off the end if uncompressed)
    unsigned int stored_at; // offset this name was first stored to in the packet, possibly partially compressed
} comptarget_t;

typedef struct {
    const ltree_rrset_addr_t* rrset;
    unsigned prev_offset; // offset into c->addtl_store before this rrset was added
    unsigned prev_arcount; // c->arcount before this rrset was added
} addtl_rrset_t;

// DNS request context.  You must have a unique
//  one of these for each thread that might call
//  into process_dns_query().
typedef struct {
    // The globally unique thread number for this context
    unsigned threadnum;

    // whether the thread using this context is a udp or tcp thread
    bool is_udp;

    // Max response size for this individual request, as determined
    //  by protocol type and EDNS (or lack thereof)
    unsigned int this_max_response;

    // These describe the question
    unsigned int qtype;  // Same numeric values as RFC
    unsigned int qname_comp; // compression pointer for the current query name, starts at 0x000C, changes when following CNAME chains
    unsigned int auth_comp; // ditto, but points at an uncompressed version of the authority for the query name

    // Stores information about each additional rrset processed
    addtl_rrset_t* addtl_rrsets;

    // Compression offsets, these are one per domainname in the whole
    //  packet.  Fully compressed names are not added, so this is really
    //  the number of unique domainnames in a response packet, so 255
    //  should be plenty.
    comptarget_t* comptargets;

    // stats...
    dnspacket_stats_t* stats;

    // used to pseudo-randomly rotate some RRsets (A, AAAA, NS, PTR)
    gdnsd_rstate_t* rand_state;

    // Allocated at dnspacket startup, needs room for gconfig.max_cname_depth * 256
    uint8_t* dync_store;

    // This is sized the same as the main packet buffer (gconfig.max_response), and
    //  used as temporary space for building Additional section records
    uint8_t* addtl_store;

    // this is the packet buffer from the io code
    uint8_t* packet;

    // allocated at startup, memset to zero before each callback
    dynaddr_result_t* dynaddr;

// From this point (answer_addr_rrset) on, all of this gets reset to zero
//  at the start of each request...

    const ltree_rrset_addr_t* answer_addr_rrset;
    client_info_t client_info; // dns source IP + optional EDNS client subnet info for plugins
    unsigned int comptarget_count; // unique domainnames stored to the packet, including the original question
    unsigned int dync_count; // how many results have been stored to dync_store so far
    unsigned int addtl_count; // count of addtl's in addtl_rrsets
    unsigned int addtl_offset; // current offset writing into addtl_store

    unsigned int ancount;
    unsigned int nscount;
    unsigned int arcount;
    unsigned int cname_ancount;

    // EDNS Client Subnet response mask.
    // Not valid/useful unless use_edns_client_subnet is true below.
    // For static responses, this is set to zero by dnspacket.c
    // For dynamic responses, this is set from .ans_dyn{a,cname}.edns_client_mask,
    //   which is in turn defaulted to zero.
    unsigned int edns_client_scope_mask;

    // Whether additional section contains glue (can't be silently truncated)
    bool addtl_has_glue;

    // Whether this request had a valid EDNS0 optrr
    bool use_edns;

    // Client sent EDNS Client Subnet option, and we must respond with one
    bool use_edns_client_subnet;

    // If the above is true, the opcode number used is stored here for use
    //   in the response (0x50fa for deprecated experimental code, or 0x0008
    //   for the new IANA code).
    unsigned clientsub_opt_code;

    // If this is true, the query class was CH
    bool chaos;
} dnspacket_context_t;

F_NONNULL
unsigned int process_dns_query(dnspacket_context_t* c, const anysin_t* asin, uint8_t* packet, const unsigned int packet_len);

F_MALLOC F_WUNUSED
dnspacket_context_t* dnspacket_context_new(const unsigned int this_threadnum, const bool is_udp);

void dnspacket_global_setup(void);
void dnspacket_wait_stats(void);

extern dnspacket_stats_t** dnspacket_stats;

#endif // GDNSD_DNSPACKET_H
