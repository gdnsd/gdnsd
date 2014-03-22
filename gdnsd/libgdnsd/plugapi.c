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

#include "gdnsd/plugapi.h"
#include "gdnsd/plugapi-priv.h"
#include "gdnsd/log.h"
#include "gdnsd/net.h"

#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "cfg-dirs.h"

void gdnsd_dynaddr_add_result_anysin(dynaddr_result_t* result, const anysin_t* asin) {
    dmn_assert(result); dmn_assert(asin);
    if(asin->sa.sa_family == AF_INET6) {
        dmn_assert(result->count_v6 < 64);
        memcpy(&result->addrs_v6[result->count_v6++ * 16], asin->sin6.sin6_addr.s6_addr, 16);
    }
    else {
        dmn_assert(asin->sa.sa_family == AF_INET);
        dmn_assert(result->count_v4 < 64);
        result->addrs_v4[result->count_v4++] = asin->sin.sin_addr.s_addr;
    }
}

static unsigned num_plugins = 0;
static plugin_t** plugins = NULL;
static const char** psearch = NULL;

void gdnsd_plugins_set_search_path(const vscf_data_t* psearch_array) {
    dmn_assert(!psearch); // only called once

    // Create a plugin search path array
    int psearch_count = psearch_array
        ? vscf_array_get_len(psearch_array)
        : 0;

    psearch = malloc((psearch_count + 2) * sizeof(const char*));
    for(int i = 0; i < psearch_count; i++) {
        const vscf_data_t* psd = vscf_array_get_data(psearch_array, i);
        if(!vscf_is_simple(psd))
            log_fatal("Plugin search paths must be strings");
        psearch[i] = strdup(vscf_simple_get_data(psd));
    }

    psearch[psearch_count++] = GDNSD_LIBDIR;
    psearch[psearch_count] = NULL;
}

const plugin_t* gdnsd_plugin_find(const char* pname) {
    dmn_assert(pname);

    const unsigned nplug = num_plugins;
    for(unsigned i = 0; i < nplug; i++) {
        const plugin_t* const p = plugins[i];
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
    plugins = realloc(plugins, num_plugins * sizeof(plugin_t*));
    plugin_t* rv = plugins[this_idx] = calloc(1, sizeof(plugin_t));
    rv->name = strdup(pname);

    return rv;
}

F_NONNULL
static void* plugin_dlopen(const char* pname) {
    dmn_assert(pname); dmn_assert(psearch);

    struct stat plugstat;
    const char* try_path;
    const char** psptr = psearch;
    const unsigned pname_len = strlen(pname);
    while((try_path = *psptr++)) {
        const unsigned try_len = strlen(try_path);
        const unsigned pp_len = try_len + 8 + pname_len + 4;
        char pp[pp_len];
        memcpy(pp, try_path, try_len);
        memcpy(pp + try_len, "/plugin_", 8);
        memcpy(pp + try_len + 8, pname, pname_len);
        memcpy(pp + try_len + 8 + pname_len, ".so\0", 4);
        log_debug("Looking for plugin '%s' at pathname '%s'", pname, pp);
        if(0 == stat(pp, &plugstat) && S_ISREG(plugstat.st_mode)) {
            void* phandle = dlopen(pp, RTLD_NOW | RTLD_LOCAL);
            if(!phandle)
                log_fatal("Failed to dlopen() the '%s' plugin from path '%s': %s", pname, pp, dlerror());
            return phandle;
        }
    }

    log_fatal("Failed to locate plugin '%s' in the plugin search path", pname);
}

typedef void(*gen_func_ptr)(void);

F_NONNULL
static gen_func_ptr plugin_dlsym(void* handle, const char* pname, const char* sym_suffix) {
    dmn_assert(handle); dmn_assert(pname); dmn_assert(sym_suffix);

    // construct the full symbol name plugin_PNAME_SYMSUFFIX\0
    const unsigned pname_len = strlen(pname);
    const unsigned suffix_len = strlen(sym_suffix);
    const unsigned sym_size = 7 + pname_len + 1 + suffix_len + 1;
    char symname[sym_size];
    memcpy(symname, "plugin_", 7);
    memcpy(symname + 7, pname, pname_len);
    memcpy(symname + 7 + pname_len, "_", 1);
    memcpy(symname + 7 + pname_len + 1, sym_suffix, suffix_len);
    memcpy(symname + 7 + pname_len + 1 + suffix_len, "\0", 1);

    // If you see an aliasing warning here, it's ok to ignore it
    gen_func_ptr rval;
    *(void**)(&rval) = dlsym(handle, symname);
    return rval;
}

const plugin_t* gdnsd_plugin_load(const char* pname) {
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
    PSETFUNC(map_resource_dyna)
    PSETFUNC(map_resource_dync)
    PSETFUNC(full_config)
    PSETFUNC(post_daemonize)
    PSETFUNC(pre_privdrop)
    PSETFUNC(pre_run)
    PSETFUNC(iothread_init)
    PSETFUNC(resolve_dynaddr)
    PSETFUNC(resolve_dyncname)
    PSETFUNC(exit)
    PSETFUNC(add_svctype)
    PSETFUNC(add_monitor)
    PSETFUNC(init_monitors)
    PSETFUNC(start_monitors)
#   undef PSETFUNC

    // leak of dlopen() handle "pptr" here is intentional.  The code has no further
    //   use for it at this point, and we never dlclose() the plugins...
    return plug;
}

const plugin_t* gdnsd_plugin_find_or_load(const char* pname) {
    dmn_assert(pname);
    const plugin_t* const p = gdnsd_plugin_find(pname);
    return p ? p : gdnsd_plugin_load(pname);
}

// The action iterators...

void gdnsd_plugins_action_full_config(const unsigned num_threads) {
    for(unsigned i = 0; i < num_plugins; i++)
        if(plugins[i]->full_config)
            plugins[i]->full_config(num_threads);
}

void gdnsd_plugins_action_post_daemonize(void) {
    for(unsigned i = 0; i < num_plugins; i++)
        if(plugins[i]->post_daemonize)
            plugins[i]->post_daemonize();
}

void gdnsd_plugins_action_pre_privdrop(void) {
    for(unsigned i = 0; i < num_plugins; i++)
        if(plugins[i]->pre_privdrop)
            plugins[i]->pre_privdrop();
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

void gdnsd_plugins_action_pre_run(struct ev_loop* loop) {
    for(unsigned i = 0; i < num_plugins; i++)
        if(plugins[i]->pre_run)
            plugins[i]->pre_run(loop);
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

