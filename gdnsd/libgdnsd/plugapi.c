/* Copyright © 2011 Brandon L Black <blblack@gmail.com>
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

#include "gdnsd-plugapi.h"
#include "gdnsd-plugapi-priv.h"
#include "gdnsd-log.h"
#include "gdnsd-net.h"

#include <string.h>
#include <stdlib.h>

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

const plugin_t* gdnsd_plugin_find(const char* plugin_name) {
    dmn_assert(plugin_name);

    const unsigned nplug = num_plugins;
    for(unsigned i = 0; i < nplug; i++) {
        const plugin_t* const p = plugins[i];
        if(!strcmp(plugin_name, p->name))
            return p;
    }

    return NULL;
}

plugin_t* gdnsd_plugin_allocate(const char* plugin_name) {
    dmn_assert(plugin_name);
    dmn_assert(!gdnsd_plugin_find(plugin_name));

    const unsigned this_idx = num_plugins++;
    log_debug("Assigning slot #%u to plugin '%s'", this_idx, plugin_name);
    plugins = realloc(plugins, num_plugins * sizeof(plugin_t*));
    plugin_t* rv = plugins[this_idx] = calloc(1, sizeof(plugin_t));
    rv->name = strdup(plugin_name);

    return rv;
}

// The action iterators...

void gdnsd_plugins_action_full_config(const unsigned num_threads) {
    for(unsigned i = 0; i < num_plugins; i++)
        if(plugins[i]->full_config)
            plugins[i]->full_config(num_threads);
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

