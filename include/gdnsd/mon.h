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

#include <gdnsd/compiler.h>
#include <gdnsd/net.h>
#include <gdnsd/prcu.h>

#include <inttypes.h>

// gdnsd_sttl_t
//  sttl -> state+ttl
//  high-bit is down flag (1 = down, 0 = up)
//  next-bit is forced flag (1 = forced, 0 = unforced)
//  next 2 bits reserved for future use (set to zero, ignored on read)
//  remaining 28 bits are unsigned TTL (max value ~8.5 years)
typedef uint32_t gdnsd_sttl_t;

static const gdnsd_sttl_t GDNSD_STTL_DOWN          = (1U << 31U);
static const gdnsd_sttl_t GDNSD_STTL_FORCED        = (1U << 30U);
static const gdnsd_sttl_t GDNSD_STTL_RESERVED_MASK = (3U << 28U);
static const gdnsd_sttl_t GDNSD_STTL_TTL_MASK      = ((1U << 28U) - 1U);
static const gdnsd_sttl_t GDNSD_STTL_TTL_MAX       = ((1U << 28U) - 1U);
// ^ identical to above, but better semantics when reading code

// the only hard rule on this data type is zero in the reserved bits for now
#define assert_valid_sttl(_x) dmn_assert(!((_x) & GDNSD_STTL_RESERVED_MASK))

#pragma GCC visibility push(default)

// Parses a string of the form STATE[/TTL], where STATE is UP or DOWN and
//   the TTL is in the legal range 0 through 2^28-1.  Returns 0 on success.
// This is exported mostly so that it can be shared with plugin_extfile,
//   I don't know if anything else will ever use it.
F_NONNULL
bool gdnsd_mon_parse_sttl(const char* sttl_str, gdnsd_sttl_t* sttl_out, unsigned def_ttl);

// sttl log formatter's output looks like:
// "DOWN/1234(FORCED)"
// where (FORCED) is only present on the forced flag,
//   and the special TTLs 0 and 268435455 are given
//   as the strings "MIN" and "MAX" for clarity.
const char* gdnsd_logf_sttl(const gdnsd_sttl_t s);
#define logf_sttl gdnsd_logf_sttl

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
// NOTE: it is not legal for any monitoring plugin to set the FORCED
//   bit in "new_sttl" - this is checked as an assertion!
void gdnsd_mon_sttl_updater(unsigned idx, gdnsd_sttl_t new_sttl);

// called during load_config to register address healthchecks, returns
//   an index to check state with...
F_NONNULL
unsigned gdnsd_mon_addr(const char* svctype_name, const dmn_anysin_t* addr);

// as above for a CNAME
F_NONNULL
unsigned gdnsd_mon_cname(const char* svctype_name, const char* cname, const uint8_t* dname);

// admin-only state registration.  plugin constructs desc
//   within its own scope, e.g.
//     "plugname/resname/dcname" for a datacenter virtual.
//   it is up to the plugin to ensure uniqueness here...
F_NONNULL
unsigned gdnsd_mon_admin(const char* desc);

// do not ref this directly in a plugin!
// use gdnsd_mon_get_sttl_table() below for access!
extern gdnsd_sttl_t* smgr_sttl_consumer_;

#pragma GCC visibility pop

// State-fetching (one table call per resolve invocation, reused
//   for as many index fetches as necc)
F_UNUSED
static const gdnsd_sttl_t* gdnsd_mon_get_sttl_table(void) {
    return gdnsd_prcu_rdr_deref(smgr_sttl_consumer_);
}

// Given two sttl values, combine them according to the following rules:
//   1) result TTL is the lesser of both TTLs
//   2) if either is down, result is down
//   3) if either is forced, result is forced
// This is meant to be used to combine parallel results, e.g. two
//   service checks on the same IP address.
// Note that currently, users of this don't actually care about the forced-bit.
// If they did, we'd probably want a more correct (and expensive) method of
//   combining the state-bits, such that the output forced-bit is only copied if
//   the forcing had an effect (e.g. forced-down + unforced-down = unforced-down)
F_PURE F_UNUSED
static gdnsd_sttl_t gdnsd_sttl_min2(const gdnsd_sttl_t a, const gdnsd_sttl_t b) {
    const gdnsd_sttl_t a_ttl = a & GDNSD_STTL_TTL_MASK;
    const gdnsd_sttl_t b_ttl = b & GDNSD_STTL_TTL_MASK;
    const gdnsd_sttl_t state = (a | b) & (GDNSD_STTL_DOWN | GDNSD_STTL_FORCED);
    return (a_ttl < b_ttl) ? (state | a_ttl) : (state | b_ttl);
}

// As above, but generalized to an array of table indices to support merging
//   several different service_type checks against a single IP for
//   a single resource.
F_NONNULLX(1) F_PURE F_UNUSED
static gdnsd_sttl_t gdnsd_sttl_min(const gdnsd_sttl_t* sttl_tbl, const unsigned* idx_ary, const unsigned idx_ary_len) {
    dmn_assert(sttl_tbl);
    gdnsd_sttl_t rv = GDNSD_STTL_TTL_MAX;
    for(unsigned i = 0; i < idx_ary_len; i++)
        rv = gdnsd_sttl_min2(rv, sttl_tbl[idx_ary[i]]);
    return rv;
}

#endif // GDNSD_MON_H
