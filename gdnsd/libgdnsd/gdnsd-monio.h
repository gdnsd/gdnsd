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

#ifndef _GDNSD_LIBMONIO_H
#define _GDNSD_LIBMONIO_H

// For satom_t, etc...
#include <gdnsd-satom.h>
#include <gdnsd-net.h>

/* monio_state == satom, but these define
 * wrappers may make it easier if we
 * have to move to another mechanism
 * later.
 */
#define MONIO_STATE_UNINIT 0
#define MONIO_STATE_DOWN   1
#define MONIO_STATE_DANGER 2
#define MONIO_STATE_UP     3
typedef satom_t monio_state_t;
typedef satom_uint_t monio_state_uint_t;
#define monio_state_get(x) satom_get(x)
#define monio_state_set(x,y) satom_set(x,y)

F_NONNULL
static inline monio_state_uint_t gdnsd_monio_min_state(const monio_state_t* states, const unsigned num_states) {
    dmn_assert(states);
    monio_state_uint_t lowest = MONIO_STATE_UP;
    for(unsigned i = 0; i < num_states; i++) {
       monio_state_uint_t st = monio_state_get(&states[i]);
       if(st < lowest)
           lowest = st;
    }

    return lowest;
}

// Your plugin owns all of the storage within or pointed to
//  by monio_list_t, and it must be durable storage
//  at the time _load_config() returns.  You are free to destroy
//  it during later callbacks, keeping in mind that the actual
//  monio_state_t pointed to by monio_info_t.state_ptr must
//  exist during normal operations for the monitoring code to
//  send status updates through.  It can only be de-allocated
//  at plugin _exit() time.
// It is also permissible for pointers inside of monio_list_t to
//  directly reference temporary storage from vscf, (e.g. the
//  "const char*" returned by vscf_simple_get_data()), as the
//  vscf config tree won't be destroyed until the daemon is
//  done processing your monio_list_t.

// If svctype_name is NULL, it will be interpreted as "default".
// Other arguments are required.
// "desc" is just descriptive, used for stats/log output.

typedef struct {
    const char* svctype;
    const char* desc;
    const char* addr;
    monio_state_t* state_ptr;
} monio_info_t;

typedef struct {
    unsigned count;
    monio_info_t* info;
} monio_list_t;

// This is for monitoring plugins rather than resolver plugins.  Most
//   plugins will want to treat it as mostly opaque other than using
//   "desc" for log/debug output, and reading "addr" during
//   the _add_monitor callback (copying it for use in your own data).
// You could, in theory, not use the provided monio_state_updater()
//   helper though, in which case you'd be on your own for correctly
//   managing "monio_state_ptrs" in a similar fashion.
typedef struct _service_type_struct service_type_t;
typedef struct {
    anysin_t addr;
    monio_state_t** monio_state_ptrs;
    service_type_t* svc_type;
    const char* desc;
    unsigned num_state_ptrs;
    unsigned up_thresh;
    unsigned ok_thresh;
    unsigned down_thresh;
    unsigned n_failure;
    unsigned n_success;
} monio_smgr_t;

// Plugins call this helper after every raw state check of a monitored
//   address, so that it can manage long-term state.
// latest -> 0 failed, 1 succeeded
F_NONNULL
void gdnsd_monio_state_updater(monio_smgr_t* smgr, const bool latest);

#endif // _GDNSD_LIBMONIO_H
