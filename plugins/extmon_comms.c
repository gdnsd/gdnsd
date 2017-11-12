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

#include <config.h>
#include "extmon_comms.h"

#include <gdnsd/alloc.h>
#include <gdnsd/compiler.h>
#include <gdnsd/log.h>

#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

bool emc_write_string(const int fd, const char* str, const size_t len) {
    bool rv = false;
    size_t written = 0;
    while(written < len) {
        ssize_t write_rv = write(fd, str + written, len - written);
        if(write_rv < 1) {
            if(!write_rv) {
                log_debug("plugin_extmon: emc_write_string(%s) failed: pipe closed", str);
                rv = true;
                break;
            }
            else if(!ERRNO_WOULDBLOCK && errno != EINTR) {
                log_debug("plugin_extmon: emc_write_string(%s) failed: %s", str, dmn_logf_strerror(errno));
                rv = true;
                break;
            }
        }
        else {
            written += (size_t)write_rv;
        }
    }
    return rv;
}

bool emc_read_nbytes(const int fd, const size_t len, uint8_t* out) {
    bool rv = false;
    size_t seen = 0;
    while(seen < len) {
        ssize_t read_rv = read(fd, out + seen, len - seen);
        if(read_rv < 1) {
            if(!read_rv) {
                log_debug("plugin_extmon: emc_read_nbytes() failed: pipe closed");
                rv = true;
                break;
            }
            else if(!ERRNO_WOULDBLOCK && errno != EINTR) {
                log_debug("plugin_extmon: emc_read_nbytes() failed: %s", dmn_logf_strerror(errno));
                rv = true;
                break;
            }
        }
        else {
            seen += (size_t)read_rv;
        }
    }
    return rv;
}

bool emc_read_exact(const int fd, const char* str) {
    const unsigned len = strlen(str);
    uint8_t buf[len];
    return (emc_read_nbytes(fd, len, buf)
        || !!memcmp(str, buf, len));
}

bool emc_write_command(const int fd, const extmon_cmd_t* cmd) {
    unsigned alloc = 256;
    unsigned len = 0;
    char* buf = xmalloc(alloc);

    // 4 byte prefix "CMD:"
    memcpy(buf, "CMD:", 4);
    len += 4;

    // 2-byte index, 2-byte timeout, 2-byte interval, 2-byte max_proc
    buf[len++] = (char)(cmd->idx >> 8);
    buf[len++] = (char)(cmd->idx & 0xFF);
    buf[len++] = (char)(cmd->timeout >> 8);
    buf[len++] = (char)(cmd->timeout & 0xFF);
    buf[len++] = (char)(cmd->interval >> 8);
    buf[len++] = (char)(cmd->interval & 0xFF);
    buf[len++] = (char)(cmd->max_proc >> 8);
    buf[len++] = (char)(cmd->max_proc & 0xFF);

    // skip 2-byte len for rest of packet at offset 12
    len += 2;

    // arg count + NUL-terminated arguments
    buf[len++] = (char)cmd->num_args;
    for(unsigned i = 0; i < cmd->num_args; i++) {
        const unsigned arg_len = strlen(cmd->args[i]) + 1;
        while((len + arg_len + 16) > alloc) {
            alloc *= 2;
            buf = xrealloc(buf, alloc);
        }
        memcpy(&buf[len], cmd->args[i], arg_len);
        len += arg_len;
    }

    // NUL-terminated description string
    const unsigned desc_len = strlen(cmd->desc) + 1;
    while((len + desc_len + 16) > alloc) {
        alloc *= 2;
        buf = xrealloc(buf, alloc);
    }
    memcpy(&buf[len], cmd->desc, desc_len);
    len += desc_len;

    // now go back and fill in the overall len
    //   of the variable area for desc/args.
    const unsigned var_len = len - 14;
    buf[12] = (char)(var_len >> 8);
    buf[13] = (char)(var_len & 0xFF);

    bool rv = emc_write_string(fd, buf, len);
    free(buf);
    return rv;
}

static bool nul_within_n_bytes(const uint8_t* instr, const unsigned len) {
    bool rv = false;
    for(unsigned j = 0; j < len; j++) {
        if(!instr[j]) {
            rv = true;
            break;
        }
    }
    return rv;
}

extmon_cmd_t* emc_read_command(const int fd) {

    extmon_cmd_t* cmd = NULL;

    {
        uint8_t fixed_part[14];
        if(emc_read_nbytes(fd, 14, fixed_part)
            || strncmp((char*)fixed_part, "CMD:", 4)) {
            log_debug("emc_read_command() failed to read CMD: prefix");
            goto out_error;
        }

        cmd = xmalloc(sizeof(extmon_cmd_t));
        cmd->idx = ((unsigned)fixed_part[4] << 8) + fixed_part[5];
        cmd->timeout = ((unsigned)fixed_part[6] << 8) + fixed_part[7];
        cmd->interval = ((unsigned)fixed_part[8] << 8) + fixed_part[9];
        cmd->max_proc = ((unsigned)fixed_part[10] << 8) + fixed_part[11];
        cmd->args = NULL;
        cmd->num_args = 0;

        // note we add an extra NULL at the end of args here, for execl()
        const unsigned var_len = ((unsigned)fixed_part[12] << 8) + fixed_part[13];
        if(var_len < 4) {
            // 4 bytes would be enough for num_args, a single 1-byte argument
            //   and its NUL termiantor, and a zero-length NUL-terminated desc
            log_debug("emc_read_command() variable section too short (%u)!", var_len);
            goto out_error;
        }

        uint8_t var_part[var_len];
        if(emc_read_nbytes(fd, var_len, var_part)) {
            log_debug("emc_read_command() failed to read %u-byte variable section", var_len);
            goto out_error;
        }

        const unsigned n_args = *var_part;
        if(!n_args) {
            log_debug("emc_read_command() got zero-arg command!");
            goto out_error;
        }

        cmd->args = xmalloc((n_args + 1) * sizeof(char*));
        const uint8_t* current = &var_part[1];
        unsigned len_remain = var_len - 1;
        for(cmd->num_args = 0; cmd->num_args < n_args; cmd->num_args++) {
            const unsigned cmdlen = strnlen((const char*)current, len_remain) + 1;
            cmd->args[cmd->num_args] = xmalloc(cmdlen);
            if(!nul_within_n_bytes(current, len_remain)) {
                log_debug("emc_read_command(): argument runs off end of buffer");
                goto out_error;
            }
            memcpy(cmd->args[cmd->num_args], current, cmdlen);
            current += cmdlen;
            len_remain -= cmdlen;
        }
        cmd->args[cmd->num_args] = NULL;

        if(!nul_within_n_bytes(current, len_remain)) {
            log_debug("emc_read_command(): argument runs off end of buffer");
            goto out_error;
        }
        cmd->desc = strdup((const char*)current);
        current += strlen((const char*)current);
        current++;

        if(current != (var_part + var_len)) {
            log_debug("emc_read_command(): unused len at end of buffer!");
            goto out_error;
        }
    }

    return cmd;

    out_error:
    if(cmd) {
        if(cmd->args) {
            for(unsigned x = 0; x < cmd->num_args; x++)
                free(cmd->args[x]);
            free(cmd->args);
        }
        free(cmd);
    }
    return NULL;
}
