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

#ifndef GDNSD_EXTMON_COMMS_H
#define GDNSD_EXTMON_COMMS_H

#include "config.h"
#include <gdnsd/compiler.h>
#include <gdnsd/log.h>
#include <inttypes.h>

// this is all of the binary data that needs to pass
//   from plugin->helper to describe an extmon command's execution
typedef struct {
    unsigned idx;
    unsigned timeout;
    unsigned interval;
    unsigned num_args;
    // all strings NUL-terminated
    const char** args; // array-of-strings NULL-terminated
    const char* desc;
} extmon_cmd_t;

// these are used for simple protocol messages during
//   initial plugin<->helper setup.  They automatically
//   retry/restart read/write on e.g. EINTR, etc, and they
//   operate in blocking mode.
// The ones with bool retvals return zero on success, and
//   emc_read_command() returns NULL on failure.
F_WUNUSED F_NONNULL
bool emc_write_string(const int fd, const char* str, const unsigned len);
F_WUNUSED F_NONNULL
bool emc_read_exact(const int fd, const char* str);
F_WUNUSED F_NONNULL
bool emc_read_nbytes(const int fd, const unsigned len, uint8_t* out);
F_WUNUSED F_NONNULL
bool emc_write_command(const int fd, const extmon_cmd_t* cmd);
F_WUNUSED
extmon_cmd_t* emc_read_command(const int fd);

// encoding of helper -> daemon monitor results as uint32_t.
// these uin32_t results are the only runtime traffic, and
// they only flow in the helper->plugin direction

F_CONST
static inline uint32_t emc_encode_mon(const unsigned idx, const bool failed) {
    dmn_assert(idx < 0x10000);
    return (idx << 16)
        | (failed
            ? (((unsigned)'F' << 8) | (unsigned)'A')
            : (((unsigned)'O' << 8) | (unsigned)'K')
        );
}

static inline unsigned emc_decode_mon_idx(const uint32_t data) {
    return (data >> 16);
}

static inline bool emc_decode_mon_failed(const uint32_t data) {
    const unsigned failflag = data & 0xFFFF;
    bool rv = true;
    if(failflag == (((unsigned)'O' << 8) | (unsigned)'K')) {
        rv = false;
    }
    else if(failflag != (((unsigned)'F' << 8) | (unsigned)'A')) {
        log_err("plugin_extmon: BUG: Invalid monitoring result %x!", data);
    }
    return rv;
}

#endif // GDNSD_EXTMON_COMMS_H
