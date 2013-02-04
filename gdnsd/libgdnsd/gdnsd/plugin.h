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

#ifdef GDNSD_PLUGIN_H
#error gdnsd/plugin.h must be included *exactly once* from *exactly one* source file per plugin
#endif

#define GDNSD_PLUGIN_H

// Include all of the libgdnsd stuff for convenience
#include <gdnsd/compiler.h>
#include <gdnsd/vscf.h>
#include <gdnsd/dname.h>
#include <gdnsd/net.h>
#include <gdnsd/log.h>
#include <gdnsd/mon.h>
#include <gdnsd/plugapi.h>
#include <gdnsd/misc.h>
#include <gdnsd/paths.h>

#ifndef GDNSD_PLUGIN_NAME
#error You must define GDNSD_PLUGIN_NAME before including <gdnsd/plugin.h>
#endif

/* All of the below is just to declare the API functions the plugin
 * should be implementing, so that the compiler can complain if the
 * prototypes don't match your code.  Also, the get_api_version call
 * is implemented in the header file directly.
 */

#define xSYM_GET_APIV(x)      plugin_ ## x ## _get_api_version
#define xSYM_LOAD_CONFIG(x)   plugin_ ## x ## _load_config
#define xSYM_MAP_RESOURCEA(x) plugin_ ## x ## _map_resource_dyna
#define xSYM_MAP_RESOURCEC(x) plugin_ ## x ## _map_resource_dync
#define xSYM_FULL_CONFIG(x)   plugin_ ## x ## _full_config
#define xSYM_POST_DAEMON(x)   plugin_ ## x ## _post_daemonize
#define xSYM_PRE_PRIVDROP(x)  plugin_ ## x ## _pre_privdrop
#define xSYM_PRE_RUN(x)       plugin_ ## x ## _pre_run
#define xSYM_IOTH_INIT(x)     plugin_ ## x ## _iothread_init
#define xSYM_RESOLVE_DYNA(x)  plugin_ ## x ## _resolve_dynaddr
#define xSYM_RESOLVE_DYNC(x)  plugin_ ## x ## _resolve_dyncname
#define xSYM_EXIT(x)          plugin_ ## x ## _exit
#define xSYM_ADD_SVC(x)       plugin_ ## x ## _add_svctype
#define xSYM_ADD_MON(x)       plugin_ ## x ## _add_monitor
#define xSYM_INIT_MONS(x)     plugin_ ## x ## _init_monitors
#define xSYM_START_MONS(x)    plugin_ ## x ## _start_monitors
#define SYM_GET_APIV(x)       xSYM_GET_APIV(x)
#define SYM_LOAD_CONFIG(x)    xSYM_LOAD_CONFIG(x)
#define SYM_MAP_RESOURCEA(x)  xSYM_MAP_RESOURCEA(x)
#define SYM_MAP_RESOURCEC(x)  xSYM_MAP_RESOURCEC(x)
#define SYM_FULL_CONFIG(x)    xSYM_FULL_CONFIG(x)
#define SYM_POST_DAEMON(x)    xSYM_POST_DAEMON(x)
#define SYM_PRE_PRIVDROP(x)   xSYM_PRE_PRIVDROP(x)
#define SYM_PRE_RUN(x)        xSYM_PRE_RUN(x)
#define SYM_IOTH_INIT(x)      xSYM_IOTH_INIT(x)
#define SYM_RESOLVE_DYNA(x)   xSYM_RESOLVE_DYNA(x)
#define SYM_RESOLVE_DYNC(x)   xSYM_RESOLVE_DYNC(x)
#define SYM_EXIT(x)           xSYM_EXIT(x)
#define SYM_ADD_SVC(x)        xSYM_ADD_SVC(x)
#define SYM_ADD_MON(x)        xSYM_ADD_MON(x)
#define SYM_INIT_MONS(x)      xSYM_INIT_MONS(x)
#define SYM_START_MONS(x)     xSYM_START_MONS(x)

F_CONST
unsigned SYM_GET_APIV(GDNSD_PLUGIN_NAME)(void);
unsigned SYM_GET_APIV(GDNSD_PLUGIN_NAME)(void) { return GDNSD_PLUGIN_API_VERSION; }

mon_list_t* SYM_LOAD_CONFIG(GDNSD_PLUGIN_NAME)(const vscf_data_t* config);
int SYM_MAP_RESOURCEA(GDNSD_PLUGIN_NAME)(const char* resname);
int SYM_MAP_RESOURCEC(GDNSD_PLUGIN_NAME)(const char* resname, const uint8_t* origin);
void SYM_FULL_CONFIG(GDNSD_PLUGIN_NAME)(unsigned num_threads);
void SYM_POST_DAEMON(GDNSD_PLUGIN_NAME)(void);
void SYM_PRE_PRIVDROP(GDNSD_PLUGIN_NAME)(void);
F_NONNULL
void SYM_PRE_RUN(GDNSD_PLUGIN_NAME)(struct ev_loop* loop);
void SYM_IOTH_INIT(GDNSD_PLUGIN_NAME)(unsigned threadnum);
F_NONNULL
bool SYM_RESOLVE_DYNA(GDNSD_PLUGIN_NAME)(unsigned threadnum, unsigned resnum, const client_info_t* cinfo, dynaddr_result_t* result);
F_NONNULL
void SYM_RESOLVE_DYNC(GDNSD_PLUGIN_NAME)(unsigned threadnum, unsigned resnum, const uint8_t* origin, const client_info_t* cinfo, dyncname_result_t* result);
void SYM_EXIT(GDNSD_PLUGIN_NAME)(void);
F_NONNULLX(1)
void SYM_ADD_SVC(GDNSD_PLUGIN_NAME)(const char* name, const vscf_data_t* svc_cfg, const unsigned interval, const unsigned timeout);
F_NONNULL
void SYM_ADD_MON(GDNSD_PLUGIN_NAME)(const char* svc_name, mon_smgr_t* smgr);
F_NONNULL
void SYM_INIT_MONS(GDNSD_PLUGIN_NAME)(struct ev_loop* mon_loop);
F_NONNULL
void SYM_START_MONS(GDNSD_PLUGIN_NAME)(struct ev_loop* mon_loop);

#undef SYM_APIV
#undef SYM_LOAD_CONFIG
#undef SYM_MAP_RESOURCE
#undef SYM_MAP_RESOURCEA
#undef SYM_MAP_RESOURCEC
#undef SYM_FULL_CONFIG
#undef SYM_POST_DAEMON
#undef SYM_PRE_PRIVDROP
#undef SYM_PRE_RUN
#undef SYM_IOTH_INIT
#undef SYM_RESOLVE_DYNA
#undef SYM_RESOLVE_DYNC
#undef SYM_EXIT
#undef SYM_ADD_SVC
#undef SYM_ADD_MON
#undef SYM_INIT_MONS
#undef SYM_START_MONS
#undef xSYM_APIV
#undef xSYM_LOAD_CONFIG
#undef xSYM_MAP_RESOURCE
#undef xSYM_MAP_RESOURCEA
#undef xSYM_MAP_RESOURCEC
#undef xSYM_FULL_CONFIG
#undef xSYM_POST_DAEMON
#undef xSYM_PRE_PRIVDROP
#undef xSYM_PRE_RUN
#undef xSYM_IOTH_INIT
#undef xSYM_RESOLVE_DYNA
#undef xSYM_RESOLVE_DYNC
#undef xSYM_EXIT
#undef xSYM_ADD_SVC
#undef xSYM_ADD_MON
#undef xSYM_INIT_MONS
#undef xSYM_START_MONS
