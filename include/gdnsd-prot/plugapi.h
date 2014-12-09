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

#ifndef GDNSD_PLUGAPI_PROT_H
#define GDNSD_PLUGAPI_PROT_H

#include <gdnsd/plugapi.h>

#include <gdnsd/compiler.h>
#include <gdnsd/vscf.h>

#include <inttypes.h>
#include <stdbool.h>

struct dyn_result {
    unsigned edns_scope_mask; // inits to zero
                              //   should remain zero for global results
                              //   should be set to cinfo->edns_client_mask if result depends only on cinfo->dns_source
                              //   if result uses cinfo->edns_source, set as appropriate...
    bool     is_cname;        // storage contains a CNAME in dname format, assert count_v[46] == 0
    unsigned count_v4;        // count of IPv4 in v4[], assert !is_cname
    unsigned count_v6;        // count of IPv6 starting at &storage[v6_offset], assert !is_cname
    union {
        uint32_t v4[0];
        uint8_t  storage[0];
    };
};

#pragma GCC visibility push(default)

// Intended for result consumers (dnspacket.c), only valid
//   after all resolver plugins are finished configuring,
//   and is static for the life of the daemon from that
//   point forward (can be cached locally).
// Return value is the offset into dyn_result.storage where
//   IPv6 address data begins
F_PURE
unsigned gdnsd_result_get_v6_offset(void);

// Same rules as above, returns the memory size that
//   should be allocated for dyn_result
F_PURE
unsigned gdnsd_result_get_alloc(void);

// MUST call this before loading plugins below,
//   array can be NULL for just the default
//   MUST only call this once per program
void gdnsd_plugins_set_search_path(vscf_data_t* psearch_array);

F_NONNULL
plugin_t* gdnsd_plugin_find_or_load(const char* pname);

// call _load_config() for all plugins which are loaded but have not
//   yet had that callback called
void gdnsd_plugins_configure_all(const unsigned num_threads);

// action iterators
void gdnsd_plugins_action_pre_run(void);
void gdnsd_plugins_action_iothread_init(const unsigned threadnum);
void gdnsd_plugins_action_exit(void);

#pragma GCC visibility pop

#endif // GDNSD_PLUGINAPI_PROT_H
