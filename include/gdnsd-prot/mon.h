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

#ifndef GDNSD_MON_PROT_H
#define GDNSD_MON_PROT_H

#include <gdnsd/compiler.h>
#include <gdnsd/vscf.h>

#include <ev.h>

#pragma GCC visibility push(default)

// conf.c calls these.  the order of execution is important due
//   to chicken-and-egg problems with explicit plugin configuration
//   for monitoring plugins vs the config of resolver plugins which
//   reference service types themselves.
// The ordering goes:
//   1) gdnsd_mon_cfg_stypes_p1() -> configures basic list of services
//        but does not load any plugins
//   2) load and configure all plugins, which will include callbacks
//        to gdnsd_mon_addr() from the plugin, which will in turn
//        reference the service types list from above but not delve
//        into it deeply.
//   3) gdnsd_mon_cfg_stypes_p2() -> fully fleshes out the
//        service types, including autoloading any plugins not
//        loaded and explicitly configured above, and then
//        does post-processing to pass monitoring requests all
//        the way through from resolver->monitoring plugins via
//        callbacks
void gdnsd_mon_cfg_stypes_p1(vscf_data_t* svctypes_cfg);
void gdnsd_mon_cfg_stypes_p2(vscf_data_t* svctypes_cfg);

// conf can call this to pre-check the admin_state syntax
// fails fatally if the admin_state pathname exists
//    but can't be loaded correctly
void gdnsd_mon_check_admin_file(void);

// main.c calls this for adding monio events to the main thread's eventloop
F_NONNULL
void gdnsd_mon_start(struct ev_loop* mon_loop);

// statio.c calls these
unsigned gdnsd_mon_stats_get_max_len(void);
F_NONNULL
unsigned gdnsd_mon_stats_out_csv(char* buf);
F_NONNULL
unsigned gdnsd_mon_stats_out_json(char* buf);
F_NONNULL
unsigned gdnsd_mon_stats_out_html(char* buf);

#pragma GCC visibility pop

#endif // GDNSD_MON_PROT_H
