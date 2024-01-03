/* Copyright © 2021 Brandon L Black <blblack@gmail.com>
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

#ifndef GDNSD_DNSSEC_H
#define GDNSD_DNSSEC_H

#include <gdnsd/compiler.h>

#include "ltree.h"

#include <stdbool.h>
#include <inttypes.h>

struct dnssec;

// Call after "gcfg" is available, but before zones+threads
void dnssec_init_global(void);

// This ZSK add interface is specific to our temporary developmental setup with
// auto-generated ephemeral ZSKs.  To be replaced later when we get into
// dealing with proper key management.
F_NONNULL
bool dnssec_add_ephemeral_zsk(struct ltree_node_zroot* zroot, const unsigned algid);

// Called right after zone parsing completes, but before nsec/rrsig processing
// begins, to set up ncache TTL and RRSIG expire/incept stamps
F_NONNULL
void dnssec_set_tstamp_ncache(struct dnssec* sec, const uint32_t tstamp, const uint32_t ncache);

F_NONNULL
void dnssec_destroy(struct dnssec* sec);

// This signs the rrset in "raw" with all the ZSKs in "zroot", and is the high
// level interface used by ltree for the general case.
// "node" must be the node that contains "raw"
// "zroot" must be the zone root for node
// "raw" must be in its unrealized state just after scanning is finished; the
// rrs' uncompressed rdata are stored in the scan_rdata array still.
// This function sets raw->num_rrsig and raw->rrsig_len (but not rrsig_offset),
// and the return value is the full wire-form RRSIG RRSet in a newly-allocated
// buffer of size raw->rrsig_len.
F_NONNULL
uint8_t* dnssec_sign_rrset(const union ltree_node* node, struct ltree_rrset_raw* raw, const struct dnssec* sec);

// Scans the RRSets in "node", which must be in the zone of "zroot", and adds a
// new NSEC RR to the node.  Must be called before rdata realization in the
// ltree processing phases.  Should not be called on nodes inside delegation
// points (glue), only auth data nodes and the delegation points themselves.
F_NONNULL
void dnssec_node_add_nsec(union ltree_node* node, const struct dnssec* sec);

// Online synth of NSEC+RRSIGs for NXDOMAIN case from dnspacket.c. In cases
// where a fixup is require (qname != nxd_name), the fixup below is applied
// afterwards as a post-processing step.
// "buf" should have at least (MAX_RESPONSE_BUF - MAX_RESP_START) of
// bytes available (allocated) that this function can write to.
F_NONNULL
unsigned dnssec_synth_nxd(const struct dnssec* sec, const uint8_t* nxd_name, uint8_t* buf, const unsigned nxd_name_len);

// Given a synthesized NXD has already been written to packet buffer "buf"
// (which is the start of the full output packet buffer) at offset "offset",
// this function will apply compression fixups to adjust for the real query
// name being longer than the owner name of the nxd response itself, which the
// synthesis assumed was the qname initially.
F_NONNULL
void dnssec_nxd_fixup(const struct dnssec* sec, uint8_t* buf, const unsigned offset, const unsigned fixup);

// Just an accessor; dnspacket needs it for an RR count sometimes
F_NONNULL
unsigned dnssec_num_zsks(const struct dnssec* sec);

#endif // GDNSD_DNSSEC_H
