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

#ifndef GDNSD_MON_H
#define GDNSD_MON_H

#include <inttypes.h>

// For anysin stuff
#include <gdnsd/net.h>

// gdnsd_sttl_t
//  sttl -> state+ttl
//  high-bit is down flag (1 = down, 0 = up)
//  next 3 bits reserved for future use (set to zero, ignored on read)
//    (may want to expose a forced-flag here later, etc)
//  remaining 28 bits are unsigned TTL (max value ~8.5 years)
typedef uint32_t gdnsd_sttl_t;

#define GDNSD_STTL_DOWN          (1U << 31U)
#define GDNSD_STTL_RESERVED_MASK (7U << 28U)
#define GDNSD_STTL_TTL_MASK      ((1U << 28U) - 1U)
#define GDNSD_STTL_TTL_MAX       ((1U << 28U) - 1U)
// ^ identical to above, but better semantics when reading code

// the only hard rule on this data type is zero in the reserved bits for now
#define assert_valid_sttl(_x) dmn_assert(!((_x) & GDNSD_STTL_RESERVED_MASK))

// A simple monitoring plugins calls this helper after every raw
//   state check of a monitored address.  The core tracks long
//   term state history for anti-flap and calculates TTLs on
//   the assumption the plugin is using the provided intervals
//   and has no deeper information than the immediate check result.
// latest -> 0 failed, 1 succeeded
void gdnsd_mon_state_updater(unsigned idx, const bool latest);

// A more-advanced monitoring plugin may wish to do its own
//   anti-flap state-tracking and TTL-calculations, in which
//   case it can use this interface to provide full, direct updates.
void gdnsd_mon_sttl_updater(unsigned idx, gdnsd_sttl_t new_sttl);

// called during load_config to register address healthchecks, returns
//   an index to check state with...
F_NONNULL
unsigned gdnsd_mon_addr(const char* svctype_name, const anysin_t* addr);

// as above for a CNAME
F_NONNULL
unsigned gdnsd_mon_cname(const char* svctype_name, const char* cname, const uint8_t* dname);

// admin-only state registration.  plugin constructs desc
//   within its own scope, e.g.
//     "plugname/resname/dcname" for a datacenter virtual.
//   it is up to the plugin to ensure uniqueness here...
F_NONNULL
unsigned gdnsd_mon_admin(const char* desc);

// State-fetching (one table call per resolve invocation, reused
//   for as many index fetches as necc)
const gdnsd_sttl_t* gdnsd_mon_get_sttl_table(void);

// Given two sttl values, combine them according to the following rules:
//   1) result TTL is the lesser of both TTLs
//   2) if either is down, result is down
// This is meant to be used to combine parallel results, e.g. two
//   service checks on the same IP address.
static inline gdnsd_sttl_t gdnsd_sttl_min2(const gdnsd_sttl_t a, const gdnsd_sttl_t b) {
    const gdnsd_sttl_t a_ttl = a & GDNSD_STTL_TTL_MASK;
    const gdnsd_sttl_t b_ttl = b & GDNSD_STTL_TTL_MASK;
    const gdnsd_sttl_t down = (a | b) & GDNSD_STTL_DOWN;
    return (a_ttl < b_ttl) ? (down | a_ttl) : (down | b_ttl);
}

// As above, but generalized to an array of table indices to support merging
//   several different service_type checks against a single IP for
//   a single resource.
F_NONNULLX(1)
static inline gdnsd_sttl_t gdnsd_sttl_min(const gdnsd_sttl_t* sttl_tbl, const unsigned* idx_ary, const unsigned idx_ary_len) {
    dmn_assert(sttl_tbl);
    gdnsd_sttl_t rv = GDNSD_STTL_TTL_MAX;
    for(unsigned i = 0; i < idx_ary_len; i++)
        rv = gdnsd_sttl_min2(rv, sttl_tbl[idx_ary[i]]);
    return rv;
}

#endif // GDNSD_MON_H
