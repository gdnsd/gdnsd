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

// For anysin_t
#include <gdnsd/net.h>

// For mon_list_t
#include <gdnsd/mon.h>

/***
 * Plugin API version, bumped on any change that's not backwards-compat.
 * This is hardcoded as a the return value of plugin_foo_get_api_version()
 *   in gdnsd/plugin.h, and also compiled into the gdnsd code.  The two
 *   values are compared at plugin load time to ensure that plugin code
 *   which doesn't match the API of the gdnsd binary is not allowed.
 * (Of course, in many cases the plugin never even makes it that far,
 *   because libgdnsd is missing symbols it wants to link against that
 *   were dropped in the new API.  This is just to protect other cases).
 ***/
#define GDNSD_PLUGIN_API_VERSION 11

/*** Data Types ***/

// read-only for plugins
typedef struct {
    anysin_t dns_source;
    anysin_t edns_client;
    unsigned edns_client_mask; // if zero, edns_client is invalid (was not sent), do not parse it.
} client_info_t;

// Result structure for dynamic address resolution plugins
typedef struct {
    uint32_t ttl;             // from zonefile, can modify
    unsigned edns_scope_mask; // inits to zero.
                              // If your plugin ignores (or ignored in this case) all of client_info_t, leave it zero
                              // If your plugin uses client_info_t.dns_source but ignores (or doesn't use for this
                              //    request) .edns_source, you must set edns_scope_mask = client_info_t.edns_client_mask
                              // If your plugin actually uses client_info_t.edns_client, set as appropriate...
    unsigned count_v4;
    unsigned count_v6;
    uint32_t addrs_v4[64];
    uint8_t  addrs_v6[64 * 16];
} dynaddr_result_t;

// Result structure for dynamic cname resolution plugins
typedef struct {
    uint32_t ttl;
    unsigned edns_scope_mask;
    // dname pointer is already set, it points at the storage
    //   you should copy your result to.  Do *not* overwrite
    //   this with a new pointer (the const should make that
    //   fail anyways).
    uint8_t* const dname;
} dyncname_result_t;

// Push an anysin_t onto a dynaddr_result_t.  Handles both families, asserts
//   overall count limits.
F_NONNULL
void gdnsd_dynaddr_add_result_anysin(dynaddr_result_t* result, const anysin_t* asin);

/**** Typedefs for plugin callbacks ****/

typedef unsigned (*gdnsd_apiv_cb_t)(void);
typedef mon_list_t* (*gdnsd_load_config_cb_t)(const vscf_data_t* pc);
typedef int (*gdnsd_map_resource_dyna_cb_t)(const char* resname);
typedef int (*gdnsd_map_resource_dync_cb_t)(const char* resname, const uint8_t* origin);
typedef void (*gdnsd_full_config_cb_t)(unsigned num_threads);
typedef void (*gdnsd_pre_privdrop_cb_t)(void);
typedef void (*gdnsd_post_daemonize_cb_t)(void);
typedef void (*gdnsd_pre_run_cb_t)(struct ev_loop* loop);
typedef void (*gdnsd_iothread_init_cb_t)(unsigned threadnum);
typedef bool (*gdnsd_resolve_dynaddr_cb_t)(unsigned threadnum, unsigned resnum, const client_info_t* cinfo, dynaddr_result_t* result);
typedef void (*gdnsd_resolve_dyncname_cb_t)(unsigned threadnum, unsigned resnum, const uint8_t* origin, const client_info_t* cinfo, dyncname_result_t* result);
typedef void (*gdnsd_exit_cb_t)(void);

/**** New callbacks for monitoring plugins ****/

typedef void (*gdnsd_add_svctype_cb_t)(const char* name, const vscf_data_t* svc_cfg, const unsigned interval, const unsigned timeout);
typedef void (*gdnsd_add_monitor_cb_t)(const char* svc_name, mon_smgr_t* smgr);
typedef void (*gdnsd_init_monitors_cb_t)(struct ev_loop* mon_loop);
typedef void (*gdnsd_start_monitors_cb_t)(struct ev_loop* mon_loop);

// This is the data type for a plugin itself, holding function
//  pointers for all of the possibly documented callbacks
typedef struct {
    const char* name;
    gdnsd_load_config_cb_t load_config;
    gdnsd_full_config_cb_t full_config;
    gdnsd_map_resource_dyna_cb_t map_resource_dyna;
    gdnsd_map_resource_dync_cb_t map_resource_dync;
    gdnsd_post_daemonize_cb_t post_daemonize;
    gdnsd_pre_privdrop_cb_t pre_privdrop;
    gdnsd_pre_run_cb_t pre_run;
    gdnsd_iothread_init_cb_t iothread_init;
    gdnsd_resolve_dynaddr_cb_t resolve_dynaddr;
    gdnsd_resolve_dyncname_cb_t resolve_dyncname;
    gdnsd_exit_cb_t exit;
    gdnsd_add_svctype_cb_t add_svctype;
    gdnsd_add_monitor_cb_t add_monitor;
    gdnsd_init_monitors_cb_t init_monitors;
    gdnsd_start_monitors_cb_t start_monitors;
} plugin_t;

// Find a(nother) plugin by name.  Not valid at load_config() time,
//   use during full_config() ideally, or later if you must.
F_NONNULL F_PURE
const plugin_t* gdnsd_plugin_find(const char* plugin_name);

#endif // GDNSD_PLUGINAPI_H
