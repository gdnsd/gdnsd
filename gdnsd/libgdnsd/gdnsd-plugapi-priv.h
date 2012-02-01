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

#ifndef _GDNSD_PLUGAPI_PRIV_H
#define _GDNSD_PLUGAPI_PRIV_H

#include "gdnsd-plugapi.h"

// Assumes no plugin of this name already allocated, not thread-safe.
plugin_t* gdnsd_plugin_allocate(const char* plugin_name);

// action iterators
void gdnsd_plugins_action_full_config(const unsigned num_threads);
void gdnsd_plugins_action_pre_privdrop(void);
void gdnsd_plugins_action_init_monitors(struct ev_loop* mon_loop);
void gdnsd_plugins_action_start_monitors(struct ev_loop* mon_loop);
void gdnsd_plugins_action_pre_run(struct ev_loop* loop);
void gdnsd_plugins_action_iothread_init(const unsigned threadnum);
void gdnsd_plugins_action_exit(void);

#endif // _GDNSD_PLUGINAPI_PRIV_H
