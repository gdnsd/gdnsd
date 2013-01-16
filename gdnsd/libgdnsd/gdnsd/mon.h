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

#ifndef GDNSD_MON_H
#define GDNSD_MON_H

// For stats_t, etc...
#include <gdnsd/stats.h>
#include <gdnsd/net.h>

/* mon_state == stats, but these define
 * wrappers may make it easier if we
 * have to move to another mechanism
 * later.
 */
#define MON_STATE_UNINIT 0
#define MON_STATE_DOWN   1
#define MON_STATE_DANGER 2
#define MON_STATE_UP     3
typedef stats_t mon_state_t;
typedef stats_uint_t mon_state_uint_t;

F_NONNULL
mon_state_uint_t gdnsd_mon_get_min_state(const mon_state_t* states, const unsigned num_states);

// Your plugin owns all of the storage within or pointed to
//  by mon_list_t, and it must be durable storage
//  at the time _load_config() returns.  You are free to destroy
//  it during later callbacks, keeping in mind that the actual
//  mon_state_t pointed to by mon_info_t.state_ptr must
//  exist during normal operations for the monitoring code to
//  send status updates through.  It can only be de-allocated
//  at plugin _exit() time.
// It is also permissible for pointers inside of mon_list_t to
//  directly reference temporary storage from vscf, (e.g. the
//  "const char*" returned by vscf_simple_get_data()), as the
//  vscf config tree won't be destroyed until the daemon is
//  done processing your mon_list_t.

// If svctype_name is NULL, it will be interpreted as "default".
// Other arguments are required.
// "desc" is just descriptive, used for stats/log output.

typedef struct {
    const char* svctype;
    const char* desc;
    const char* addr;
    mon_state_t* state_ptr;
} mon_info_t;

typedef struct {
    unsigned count;
    mon_info_t* info;
} mon_list_t;

// This is for monitoring plugins rather than resolver plugins.  Most
//   plugins will want to treat it as mostly opaque other than using
//   "desc" for log/debug output, and reading "addr" during
//   the _add_monitor callback (copying it for use in your own data).
typedef struct _service_type_struct service_type_t;
typedef struct {
    anysin_t addr;
    mon_state_t** mon_state_ptrs;
    service_type_t* svc_type;
    const char* desc;
    unsigned num_state_ptrs;
    unsigned up_thresh;
    unsigned ok_thresh;
    unsigned down_thresh;
    unsigned n_failure;
    unsigned n_success;
} mon_smgr_t;

// Plugins call this helper after every raw state check of a monitored
//   address, so that it can manage long-term state.
// latest -> 0 failed, 1 succeeded
F_NONNULL
void gdnsd_mon_state_updater(mon_smgr_t* smgr, const bool latest);

#endif // GDNSD_MON_H
