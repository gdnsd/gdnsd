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

#ifndef GDNSD_PLUGAPI_H
#define GDNSD_PLUGAPI_H

#include <gdnsd/compiler.h>
#include <gdnsd/vscf.h>
#include <gdnsd/net.h>

#include <inttypes.h>
#include <stdbool.h>

#include <ev.h>

#include "mon.h"

// Called by resolver plugins during configuration load callback
// Indicates the maximum count of each address family that the plugin
//   will add to result structures at runtime.  A plugin *cannot* exceed
//   the limits it sets for itself here at startup, and every resolver
//   plugin that can return addresses *must* call this function!
void gdnsd_dyn_addr_max(unsigned v4, unsigned v6);

/*** Data Types ***/

// Private result structure for dynamic resolution plugins
// Modified via the functions below...
struct dyn_result;
typedef struct dyn_result dyn_result_t;

// NOTE the rules for the result-modifying functions below:
//   A plugin cannot add more addresses of a given family than it indicated
//     during its call to gdnsd_dyn_addr_max().
//   A plugin cannot add both addresses and a CNAME to the same result.
//   A plugin cannot add more than one CNAME to the same result.

// Push an gdnsd_anysin_t (v4 or v6 addr) into dyn_result_t storage.
F_NONNULL
void gdnsd_result_add_anysin(dyn_result_t* result, const gdnsd_anysin_t* sa);

// Push a CNAME into dyn_result_t storage.
F_NONNULL
void gdnsd_result_add_cname(dyn_result_t* result, const uint8_t* dname);

// Wipe a result_t's storage completely, removing all addresses or the CNAME stored within
// (this function is valid at all times, never fails, and resets to the original state)
// (does not affect scope mask!)
F_NONNULL
void gdnsd_result_wipe(dyn_result_t* result);

// Wipe just one address family from a result.  Does not affect the other address family,
//   and has no effect at all if the result contained a CNAME instead.
// (does not affect scope mask!)
F_NONNULL
void gdnsd_result_wipe_v4(dyn_result_t* result);
F_NONNULL
void gdnsd_result_wipe_v6(dyn_result_t* result);

// Resets the edns scope mask to the default value of zero, meaning global (unspecified) scope
F_NONNULL
void gdnsd_result_reset_scope_mask(dyn_result_t* result);

// Set the edns scope mask of the result to the minimum scope (numerically-larger) of
//   the current setting and the new input.  This is correct if more than one independent
//   calculation of scope applies to the result.
F_NONNULL
void gdnsd_result_add_scope_mask(dyn_result_t* result, unsigned scope);

/**** Typedefs for plugin callbacks ****/

typedef unsigned(*gdnsd_apiv_cb_t)(void);
typedef void (*gdnsd_load_config_cb_t)(vscf_data_t* pc, const unsigned num_threads);
typedef int (*gdnsd_map_res_cb_t)(const char* resname, const uint8_t* zone_name);
typedef void (*gdnsd_pre_run_cb_t)(void);
typedef void (*gdnsd_iothread_init_cb_t)(void);
typedef void (*gdnsd_iothread_cleanup_cb_t)(void);
typedef gdnsd_sttl_t (*gdnsd_resolve_cb_t)(unsigned resnum, const client_info_t* cinfo, dyn_result_t* result);

/**** New callbacks for monitoring plugins ****/

typedef void (*gdnsd_add_svctype_cb_t)(const char* name, vscf_data_t* svc_cfg, const unsigned interval, const unsigned timeout);
typedef void (*gdnsd_add_mon_addr_cb_t)(const char* desc, const char* svc_name, const char* cname, const gdnsd_anysin_t* addr, const unsigned idx);
typedef void (*gdnsd_add_mon_cname_cb_t)(const char* desc, const char* svc_name, const char* cname, const unsigned idx);
typedef void (*gdnsd_init_monitors_cb_t)(struct ev_loop* mon_loop);
typedef void (*gdnsd_start_monitors_cb_t)(struct ev_loop* mon_loop);

// This is the data type for a plugin itself, holding function
//  pointers for all of the possibly-documented callbacks
typedef struct {
    const char* name;
    bool used;
    bool config_loaded;
    gdnsd_load_config_cb_t load_config;
    gdnsd_map_res_cb_t map_res;
    gdnsd_pre_run_cb_t pre_run;
    gdnsd_iothread_init_cb_t iothread_init;
    gdnsd_iothread_cleanup_cb_t iothread_cleanup;
    gdnsd_resolve_cb_t resolve;
    gdnsd_add_svctype_cb_t add_svctype;
    gdnsd_add_mon_addr_cb_t add_mon_addr;
    gdnsd_add_mon_cname_cb_t add_mon_cname;
    gdnsd_init_monitors_cb_t init_monitors;
    gdnsd_start_monitors_cb_t start_monitors;
} plugin_t;

// Find a(nother) plugin by name.
F_NONNULL F_PURE F_RETNN
plugin_t* gdnsd_plugin_find(const char* plugin_name);

// convenient macro for logging a config error and returning
//  the error value -1 in a resolver plugin's map_res() callback
//  without a bunch of extra clutter and bracing
#define map_res_err(...) \
    do {\
        log_err(__VA_ARGS__);\
        return -1;\
    } while (0)


/*** Stuff used by the core code, not the plugins themselves ***/

struct dyn_result {
    // edns_scope_mask inits to zero,  should remain zero for global results,
    // and should be set to cinfo->edns_client_mask if result depends only on cinfo->dns_source
    unsigned edns_scope_mask;
    bool     is_cname; // storage contains a CNAME in dname format, assert count_v[46] == 0
    unsigned count_v4; // count of IPv4 in v4[], assert !is_cname
    unsigned count_v6; // count of IPv6 starting at &storage[v6_offset], assert !is_cname
    union {
        uint32_t v4[0];
        uint8_t  storage[0];
    };
};

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

// As above, but returns an rrset allocation for response sizing, as the
// maximum encoded size of all the A and AAAA RRs
F_PURE
size_t gdnsd_result_get_max_response(void);

// call _load_config() for all plugins which are loaded but have not
//   yet had that callback called
void gdnsd_plugins_configure_all(const unsigned num_threads);

// action iterators
void gdnsd_plugins_action_pre_run(void);
void gdnsd_plugins_action_iothread_init(void);
void gdnsd_plugins_action_iothread_cleanup(void);

F_NONNULL
void gdnsd_plugins_action_init_monitors(struct ev_loop* mon_loop);
F_NONNULL
void gdnsd_plugins_action_start_monitors(struct ev_loop* mon_loop);

#endif // GDNSD_PLUGINAPI_H
