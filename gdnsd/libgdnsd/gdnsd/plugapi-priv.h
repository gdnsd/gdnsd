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

#ifndef GDNSD_PLUGAPI_PRIV_H
#define GDNSD_PLUGAPI_PRIV_H

#include "gdnsd/plugapi.h"
#include "gdnsd/vscf.h"

// MUST call this before loading plugins below,
//   array can be NULL for just the default
//   MUST only call this once per program
void gdnsd_plugins_set_search_path(const vscf_data_t* psearch_array);

F_NONNULL
const plugin_t* gdnsd_plugin_load(const char* pname);

F_NONNULL
const plugin_t* gdnsd_plugin_find_or_load(const char* pname);

// action iterators
void gdnsd_plugins_action_full_config(const unsigned num_threads);
void gdnsd_plugins_action_post_daemonize(void);
void gdnsd_plugins_action_pre_privdrop(void);
F_NONNULL
void gdnsd_plugins_action_init_monitors(struct ev_loop* mon_loop);
F_NONNULL
void gdnsd_plugins_action_start_monitors(struct ev_loop* mon_loop);
F_NONNULL
void gdnsd_plugins_action_pre_run(struct ev_loop* loop);
void gdnsd_plugins_action_iothread_init(const unsigned threadnum);
void gdnsd_plugins_action_exit(void);

#endif // GDNSD_PLUGINAPI_PRIV_H
