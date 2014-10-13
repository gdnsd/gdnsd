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

// for uint8_t
#include <inttypes.h>

// For struct ev_loop
#include <ev.h>

// For vscf_data_t
#include <gdnsd/vscf.h>

// For dmn_anysin_t
#include <gdnsd/net.h>

// For gdnsd_sttl_t
#include <gdnsd/mon.h>

/***
 * Plugin API version, bumped on any change that's not backwards-compat.
 * This is hardcoded as the return value of plugin_foo_get_api_version()
 *   in gdnsd/plugin.h, and also compiled into the gdnsd code.  The two
 *   values are compared at plugin load time to ensure that plugin code
 *   which doesn't match the API of the gdnsd binary is not allowed.
 * (Of course, in many cases the plugin never even makes it that far,
 *   because libgdnsd is missing symbols it wants to link against that
 *   were dropped in the new API.  This is just to protect other cases).
 ***/
#define GDNSD_PLUGIN_API_VERSION 16

// Called by resolver plugins during configuration load callback
// Indicates the maximum count of each address family that the plugin
//   will add to result structures at runtime.  A plugin *cannot* exceed
//   the limits it sets for itself here at startup, and every resolver
//   plugin that can return addresses *must* call this function!
void gdnsd_dyn_addr_max(unsigned v4, unsigned v6);

/*** Data Types ***/

// read-only for plugins
typedef struct {
    dmn_anysin_t dns_source;       // address of last source DNS cache/forwarder
    dmn_anysin_t edns_client;      // edns-client-subnet address portion
    unsigned edns_client_mask; // edns-client-subnet mask portion
} client_info_t;               //  ^(if zero, edns_client is invalid (was not sent))

// Private result structure for dynamic resolution plugins
// Modified via the functions below...
struct dyn_result;
typedef struct dyn_result dyn_result_t;

// NOTE the rules for the result-modifying functions below:
//   A plugin cannot add more addresses of a given family than it indicated
//     during its call to gdnsd_dyn_addr_max().
//   A plugin cannot add both addresses and a CNAME to the same result.
//   A plugin cannot add more than one CNAME to the same result.

// Push an dmn_anysin_t (v4 or v6 addr) into dyn_result_t storage.
F_NONNULL
void gdnsd_result_add_anysin(dyn_result_t* result, const dmn_anysin_t* asin);

// Push a CNAME into dyn_result_t storage.
F_NONNULL
void gdnsd_result_add_cname(dyn_result_t* result, const uint8_t* dname, const uint8_t* origin);

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

typedef unsigned (*gdnsd_apiv_cb_t)(void);
typedef void (*gdnsd_load_config_cb_t)(vscf_data_t* pc, const unsigned num_threads);
typedef int (*gdnsd_map_res_cb_t)(const char* resname, const uint8_t* origin);
typedef void (*gdnsd_pre_run_cb_t)(void);
typedef void (*gdnsd_iothread_init_cb_t)(unsigned threadnum);
typedef gdnsd_sttl_t (*gdnsd_resolve_cb_t)(unsigned resnum, const uint8_t* origin, const client_info_t* cinfo, dyn_result_t* result);
typedef void (*gdnsd_exit_cb_t)(void);

/**** New callbacks for monitoring plugins ****/

typedef void (*gdnsd_add_svctype_cb_t)(const char* name, vscf_data_t* svc_cfg, const unsigned interval, const unsigned timeout);
typedef void (*gdnsd_add_mon_addr_cb_t)(const char* desc, const char* svc_name, const char* cname, const dmn_anysin_t* addr, const unsigned idx);
typedef void (*gdnsd_add_mon_cname_cb_t)(const char* desc, const char* svc_name, const char* cname, const unsigned idx);
typedef void (*gdnsd_init_monitors_cb_t)(struct ev_loop* mon_loop);
typedef void (*gdnsd_start_monitors_cb_t)(struct ev_loop* mon_loop);

// This is the data type for a plugin itself, holding function
//  pointers for all of the possibly-documented callbacks
typedef struct {
    const char* name;
    bool config_loaded;
    gdnsd_load_config_cb_t load_config;
    gdnsd_map_res_cb_t map_res;
    gdnsd_pre_run_cb_t pre_run;
    gdnsd_iothread_init_cb_t iothread_init;
    gdnsd_resolve_cb_t resolve;
    gdnsd_exit_cb_t exit;
    gdnsd_add_svctype_cb_t add_svctype;
    gdnsd_add_mon_addr_cb_t add_mon_addr;
    gdnsd_add_mon_cname_cb_t add_mon_cname;
    gdnsd_init_monitors_cb_t init_monitors;
    gdnsd_start_monitors_cb_t start_monitors;
} plugin_t;

// Find a(nother) plugin by name.  Not valid at load_config() time,
//   use later.
F_NONNULL F_PURE
plugin_t* gdnsd_plugin_find(const char* plugin_name);

// convenient macro for logging a config error and returning
//  the error value -1 in a resolver plugin's map_res() callback
//  without a bunch of extra clutter and bracing
#define map_res_err(...) \
    do {\
        log_err(__VA_ARGS__);\
        return -1;\
    } while(0)

#endif // GDNSD_PLUGINAPI_H
