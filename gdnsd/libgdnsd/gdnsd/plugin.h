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
#include <gdnsd/alloc.h>
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
#define xSYM_MAP_RES(x)       plugin_ ## x ## _map_res
#define xSYM_PRE_RUN(x)       plugin_ ## x ## _pre_run
#define xSYM_IOTH_INIT(x)     plugin_ ## x ## _iothread_init
#define xSYM_RESOLVE(x)       plugin_ ## x ## _resolve
#define xSYM_EXIT(x)          plugin_ ## x ## _exit
#define xSYM_ADD_SVC(x)       plugin_ ## x ## _add_svctype
#define xSYM_ADD_MON_ADDR(x)  plugin_ ## x ## _add_mon_addr
#define xSYM_ADD_MON_CNAME(x) plugin_ ## x ## _add_mon_cname
#define xSYM_INIT_MONS(x)     plugin_ ## x ## _init_monitors
#define xSYM_START_MONS(x)    plugin_ ## x ## _start_monitors
#define SYM_GET_APIV(x)       xSYM_GET_APIV(x)
#define SYM_LOAD_CONFIG(x)    xSYM_LOAD_CONFIG(x)
#define SYM_MAP_RES(x)        xSYM_MAP_RES(x)
#define SYM_PRE_RUN(x)        xSYM_PRE_RUN(x)
#define SYM_IOTH_INIT(x)      xSYM_IOTH_INIT(x)
#define SYM_RESOLVE(x)        xSYM_RESOLVE(x)
#define SYM_EXIT(x)           xSYM_EXIT(x)
#define SYM_ADD_SVC(x)        xSYM_ADD_SVC(x)
#define SYM_ADD_MON_ADDR(x)   xSYM_ADD_MON_ADDR(x)
#define SYM_ADD_MON_CNAME(x)  xSYM_ADD_MON_CNAME(x)
#define SYM_INIT_MONS(x)      xSYM_INIT_MONS(x)
#define SYM_START_MONS(x)     xSYM_START_MONS(x)

F_CONST
unsigned SYM_GET_APIV(GDNSD_PLUGIN_NAME)(void);
unsigned SYM_GET_APIV(GDNSD_PLUGIN_NAME)(void) { return GDNSD_PLUGIN_API_VERSION; }

void SYM_LOAD_CONFIG(GDNSD_PLUGIN_NAME)(vscf_data_t* config, const unsigned num_threads);
int SYM_MAP_RES(GDNSD_PLUGIN_NAME)(const char* resname, const uint8_t* origin);
F_NONNULL
void SYM_PRE_RUN(GDNSD_PLUGIN_NAME)(void);
void SYM_IOTH_INIT(GDNSD_PLUGIN_NAME)(unsigned threadnum);
F_NONNULLX(3,4)
gdnsd_sttl_t SYM_RESOLVE(GDNSD_PLUGIN_NAME)(unsigned resnum, const uint8_t* origin, const client_info_t* cinfo, dyn_result_t* result);
void SYM_EXIT(GDNSD_PLUGIN_NAME)(void);
F_NONNULL
void SYM_ADD_SVC(GDNSD_PLUGIN_NAME)(const char* name, vscf_data_t* svc_cfg, const unsigned interval, const unsigned timeout);
F_NONNULL
void SYM_ADD_MON_ADDR(GDNSD_PLUGIN_NAME)(const char* desc, const char* svc_name, const char* cname, const dmn_anysin_t* addr, const unsigned idx);
void SYM_ADD_MON_CNAME(GDNSD_PLUGIN_NAME)(const char* desc, const char* svc_name, const char* cname, const unsigned idx);
F_NONNULL
void SYM_INIT_MONS(GDNSD_PLUGIN_NAME)(struct ev_loop* mon_loop);
F_NONNULL
void SYM_START_MONS(GDNSD_PLUGIN_NAME)(struct ev_loop* mon_loop);

#undef SYM_APIV
#undef SYM_LOAD_CONFIG
#undef SYM_MAP_RES
#undef SYM_PRE_RUN
#undef SYM_IOTH_INIT
#undef SYM_RESOLVE
#undef SYM_EXIT
#undef SYM_ADD_SVC
#undef SYM_ADD_MON_ADDR
#undef SYM_ADD_MON_CNAME
#undef SYM_INIT_MONS
#undef SYM_START_MONS
#undef xSYM_APIV
#undef xSYM_LOAD_CONFIG
#undef xSYM_MAP_RES
#undef xSYM_PRE_RUN
#undef xSYM_IOTH_INIT
#undef xSYM_RESOLVE
#undef xSYM_EXIT
#undef xSYM_ADD_SVC
#undef xSYM_ADD_MON_ADDR
#undef xSYM_ADD_MON_CNAME
#undef xSYM_INIT_MONS
#undef xSYM_START_MONS
