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

#include "config.h"

#include <gdnsd/alloc.h>
#include <gdnsd/plugapi.h>
#include <gdnsd/plugapi-priv.h>
#include <gdnsd/log.h>
#include <gdnsd/net.h>
#include <gdnsd/misc.h>

#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "cfg-dirs.h"

// The default (minimum) values here amount to 240 bytes of address
//   storage (12*4+12*16), which is less than the minimum allocation
//   of 256 to store a CNAME, therefore there's no savings trying to
//   go any smaller.
static unsigned addrlimit_v4 = 12U;
static unsigned addrlimit_v6 = 12U;
static unsigned v6_offset = 12U * 4U;

unsigned gdnsd_result_get_v6_offset(void) { return v6_offset; }

unsigned gdnsd_result_get_alloc(void) {
    unsigned storage = (addrlimit_v4 * 4U) + (addrlimit_v6 * 16U);
    if(storage < 256U)
        storage = 256U; // true minimum set by CNAME storage
    return sizeof(dyn_result_t) + storage;
}

void gdnsd_dyn_addr_max(unsigned v4, unsigned v6) {
    // Note these limits are somewhat arbitrary (with some thought towards 16K-ish limits), but:
    //   (a) I can't imagine reasonable use-cases hitting them in practice at this time
    //   (b) There may be other implications for very large values that need to be addressed
    //     before lifting these limits (e.g. auto-raising max packet size?)
    if(v4 > 512U)
        log_fatal("gdnsd cannot cope with plugin configurations which add >512 IPv4 addresses to a single result!");
    if(v6 > 512U)
        log_fatal("gdnsd cannot cope with plugin configurations which add >512 IPv6 addresses to a single result!");

    if(v4 > addrlimit_v4) {
        addrlimit_v4 = v4;
        v6_offset = v4 * 4U;
    }
    if(v6 > addrlimit_v6)
        addrlimit_v6 = v6;
}

void gdnsd_result_add_anysin(dyn_result_t* result, const dmn_anysin_t* asin) {
    dmn_assert(result); dmn_assert(asin);

    dmn_assert(!result->is_cname);
    if(asin->sa.sa_family == AF_INET6) {
        dmn_assert(result->count_v6 < addrlimit_v6);
        memcpy(&result->storage[v6_offset + (result->count_v6++ * 16U)], asin->sin6.sin6_addr.s6_addr, 16);
    }
    else {
        dmn_assert(asin->sa.sa_family == AF_INET);
        dmn_assert(result->count_v4 < addrlimit_v4);
        result->v4[result->count_v4++] = asin->sin.sin_addr.s_addr;
    }
}

void gdnsd_result_add_cname(dyn_result_t* result, const uint8_t* dname, const uint8_t* origin) {
    dmn_assert(result); dmn_assert(dname); dmn_assert(origin);
    dmn_assert(dname_status(dname) != DNAME_INVALID);
    dmn_assert(dname_status(origin) == DNAME_VALID);
    dmn_assert(!result->is_cname);
    dmn_assert(!result->count_v4);
    dmn_assert(!result->count_v6);

    result->is_cname = true;
    dname_copy(result->storage, dname);
    if(dname_is_partial(result->storage))
        dname_cat(result->storage, origin);
    dmn_assert(dname_status(result->storage) == DNAME_VALID);
}

void gdnsd_result_wipe(dyn_result_t* result) {
    dmn_assert(result);
    result->is_cname = false;
    result->count_v4 = 0;
    result->count_v6 = 0;
}

void gdnsd_result_wipe_v4(dyn_result_t* result) {
    dmn_assert(result);
    result->count_v4 = 0;
}

void gdnsd_result_wipe_v6(dyn_result_t* result) {
    dmn_assert(result);
    result->count_v6 = 0;
}

void gdnsd_result_add_scope_mask(dyn_result_t* result, unsigned scope) {
    dmn_assert(result);
    if(scope > result->edns_scope_mask)
        result->edns_scope_mask = scope;
}

void gdnsd_result_reset_scope_mask(dyn_result_t* result) {
    dmn_assert(result);
    result->edns_scope_mask = 0;
}

static unsigned num_plugins = 0;
static plugin_t** plugins = NULL;
static const char** psearch = NULL;

void gdnsd_plugins_set_search_path(vscf_data_t* psearch_array) {
    dmn_assert(!psearch); // only called once

    // Create a plugin search path array
    int psearch_count = psearch_array
        ? vscf_array_get_len(psearch_array)
        : 0;

    psearch = xmalloc((psearch_count + 2) * sizeof(const char*));
    for(int i = 0; i < psearch_count; i++) {
        vscf_data_t* psd = vscf_array_get_data(psearch_array, i);
        if(!vscf_is_simple(psd))
            log_fatal("Plugin search paths must be strings");
        psearch[i] = strdup(vscf_simple_get_data(psd));
    }

    psearch[psearch_count++] = GDNSD_DEFPATH_LIB;
    psearch[psearch_count] = NULL;
}

plugin_t* gdnsd_plugin_find(const char* pname) {
    dmn_assert(pname);

    const unsigned nplug = num_plugins;
    for(unsigned i = 0; i < nplug; i++) {
        plugin_t* p = plugins[i];
        if(!strcmp(pname, p->name))
            return p;
    }

    return NULL;
}

F_NONNULL
static plugin_t* plugin_allocate(const char* pname) {
    dmn_assert(pname);
    dmn_assert(!gdnsd_plugin_find(pname));

    const unsigned this_idx = num_plugins++;
    log_debug("Assigning slot #%u to plugin '%s'", this_idx, pname);
    plugins = xrealloc(plugins, num_plugins * sizeof(plugin_t*));
    plugin_t* rv = plugins[this_idx] = xcalloc(1, sizeof(plugin_t));
    rv->name = strdup(pname);
    rv->config_loaded = false;

    return rv;
}

F_NONNULL
static void* plugin_dlopen(const char* pname) {
    dmn_assert(pname); dmn_assert(psearch);

    struct stat plugstat;
    const char* try_path;
    const char** psptr = psearch;
    while((try_path = *psptr++)) {
        char* pp = gdnsd_str_combine_n(4, try_path, "/plugin_", pname, ".so");
        log_debug("Looking for plugin '%s' at pathname '%s'", pname, pp);
        if(0 == stat(pp, &plugstat) && S_ISREG(plugstat.st_mode)) {
            void* phandle = dlopen(pp, RTLD_NOW | RTLD_LOCAL);
            if(!phandle)
                log_fatal("Failed to dlopen() the '%s' plugin from path '%s': %s", pname, pp, dlerror());
            free(pp);
            return phandle;
        }
        free(pp);
    }

    log_fatal("Failed to locate plugin '%s' in the plugin search path", pname);
}

typedef void(*gen_func_ptr)(void);

F_NONNULL
static gen_func_ptr plugin_dlsym(void* handle, const char* pname, const char* sym_suffix) {
    dmn_assert(handle); dmn_assert(pname); dmn_assert(sym_suffix);

    // If you see an aliasing warning here, it's ok to ignore it
    char* symname = gdnsd_str_combine_n(4, "plugin_", pname, "_", sym_suffix);
    gen_func_ptr rval;
    *(void**)(&rval) = dlsym(handle, symname);
    free(symname);
    return rval;
}

static plugin_t* gdnsd_plugin_load(const char* pname) {
    dmn_assert(pname); dmn_assert(psearch);

    plugin_t* plug = plugin_allocate(pname);
    void* pptr = plugin_dlopen(pname);
    const gdnsd_apiv_cb_t apiv = (gdnsd_apiv_cb_t)plugin_dlsym(pptr, pname, "get_api_version");
    if(!apiv)
        log_fatal("Plugin '%s' does not appear to be a valid gdnsd plugin", pname);
    const unsigned this_version = apiv();
    if(this_version != GDNSD_PLUGIN_API_VERSION)
        log_fatal("Plugin '%s' needs to be recompiled (wanted API version %u, got %u)",
            pname, GDNSD_PLUGIN_API_VERSION, this_version);

#   define PSETFUNC(x) plug->x = (gdnsd_ ## x ## _cb_t)plugin_dlsym(pptr, pname, #x);
    PSETFUNC(load_config)
    PSETFUNC(map_res)
    PSETFUNC(pre_run)
    PSETFUNC(iothread_init)
    PSETFUNC(resolve)
    PSETFUNC(exit)
    PSETFUNC(add_svctype)
    PSETFUNC(add_mon_addr)
    PSETFUNC(add_mon_cname)
    PSETFUNC(init_monitors)
    PSETFUNC(start_monitors)
#   undef PSETFUNC

    // leak of dlopen() handle "pptr" here is intentional.  The code has no further
    //   use for it at this point, and we never dlclose() the plugins...
    return plug;
}

plugin_t* gdnsd_plugin_find_or_load(const char* pname) {
    dmn_assert(pname);
    plugin_t* p = gdnsd_plugin_find(pname);
    return p ? p : gdnsd_plugin_load(pname);
}

// The action iterators...

void gdnsd_plugins_configure_all(const unsigned num_threads) {
    for(unsigned i = 0; i < num_plugins; i++) {
        if(plugins[i]->load_config && !plugins[i]->config_loaded) {
            plugins[i]->load_config(NULL, num_threads);
            plugins[i]->config_loaded = true;
        }
    }
}

void gdnsd_plugins_action_init_monitors(struct ev_loop* mon_loop) {
    for(unsigned i = 0; i < num_plugins; i++)
        if(plugins[i]->init_monitors)
            plugins[i]->init_monitors(mon_loop);
}

void gdnsd_plugins_action_start_monitors(struct ev_loop* mon_loop) {
    for(unsigned i = 0; i < num_plugins; i++)
        if(plugins[i]->start_monitors)
            plugins[i]->start_monitors(mon_loop);
}

void gdnsd_plugins_action_pre_run(void) {
    for(unsigned i = 0; i < num_plugins; i++)
        if(plugins[i]->pre_run)
            plugins[i]->pre_run();
}

void gdnsd_plugins_action_iothread_init(const unsigned threadnum) {
    for(unsigned i = 0; i < num_plugins; i++)
        if(plugins[i]->iothread_init)
            plugins[i]->iothread_init(threadnum);
}

void gdnsd_plugins_action_exit(void) {
    for(unsigned i = 0; i < num_plugins; i++)
        if(plugins[i]->exit)
            plugins[i]->exit();
}
