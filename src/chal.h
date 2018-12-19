/* Copyright © 2018 Brandon L Black <blblack@gmail.com>
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

#ifndef GDNSD_CHAL_H
#define GDNSD_CHAL_H

#include <gdnsd/compiler.h>
#include <gdnsd/dname.h>

#include <stdbool.h>
#include <inttypes.h>
#include <sys/types.h>

#include <ev.h>

//   A single challenge is encoded on the control socket wire as a dname-encoded
// domainname (up to 240 bytes total, encodes its own length within that)
// followed by exactly 43 bytes of challenge TXT data (base64url of SHA-256
// with no padding), followed by a single NUL byte (to make debug printing
// easier).
//   Note that actual dnames limit at 256 bytes total, but in order to leave room
// for legally prepending "_acme-challenge.", the whole mechanism is
// necessarily limited to authneticating domainnames up to 240 bytes long by
// our dname format's count.
//   Multiple challenges sent in a single request are simply concatenated.  The
// request's "v" field encodes the total count of challenges and the "d" field
// the total data bytes of all the concatenated challenges.
// We define a maximum sanity limit of 100 challenges per control socket
// request, and thus there's also a maximum possible legal data length
// calculated as 28400 bytes (= 100 * (240 + 44)).
#define CHAL_MAX_COUNT 100U
#define CHAL_MAX_DLEN 28400U

// Parse challenges sent to the control socket, creating a new challenge set.
// Retval true indicates failure to parse and add the challenges.  The control
// socket server code enforces the maximums declared above, and requires both
// numbers to be non-zero as well.  This function asserts those constraints
// without checking them.
// ttl_remain is for daemon->daemon imports, and should be zero for true client
// insertions.
F_NONNULL
bool cset_create(struct ev_loop* loop, size_t ttl_remain, size_t count, size_t dlen, uint8_t* data);

// Returns an allocated data chunk and a count (v) and dlen (d) for sending one
// message which serializes all active cset_t for handoff.  Sets zeros and
// returns NULL if there are no cset_t to serialize.
F_NONNULL F_MALLOC
uint8_t* csets_serialize(struct ev_loop* loop, size_t* csets_count_p, size_t* csets_dlen_p);

// Flush all created above immediately, instead of letting them expire our naturally
// If loop is non-NULL, also stops timer
void cset_flush(struct ev_loop* loop);

// Runtime lookup from dnspacket, must happen inside RCU read-side critical
// section.  Places all matching TXT records into packet starting at offset,
// updates the answer count at *ancount_p, and returns the new end-of-packet
// offset.  If no matching records, returns the offset it was given and does
// not affect packet or *ancount_p.
F_NONNULL F_HOT
bool chal_respond(const unsigned qname_comp, const unsigned qtype, const uint8_t* qname, uint8_t* packet, unsigned* ancount_p, unsigned* offset_p, const unsigned this_max_response);

// Does some basic initialization early
void chal_init(void);

// Quick pre-flight check
F_NONNULL F_UNUSED F_PURE F_HOT
static bool dname_is_acme_chal(const uint8_t* d)
{
    gdnsd_assert(dname_status(d) != DNAME_INVALID);
    return (d[0] > 16U && d[1] == 15U && !memcmp(&d[2], "_acme-challenge", 15U));
}

#endif // GDNSD_CHAL_H
