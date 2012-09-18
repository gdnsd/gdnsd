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
#include "gdnsd-compiler.h"
#include "gdnsd-log.h"
#include "extmon_comms.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>

bool emc_write_string(const int fd, const char* str, const unsigned len) {
    bool rv = false;
    unsigned written = 0;
    while(written < len) {
        int writerv = write(fd, str + written, len - written);
        if(writerv < 1) {
            if(!writerv) {
                log_debug("plugin_extmon: emc_write_string(%s) failed: pipe closed", str);
                rv = true;
                break;
            }
            else if(errno != EAGAIN && errno != EINTR) {
                log_debug("plugin_extmon: emc_write_string(%s) failed: %s", str, dmn_strerror(errno));
                rv = true;
                break;
            }
        }
        else {
            written += writerv;
        }
    }
    return rv;
}

bool emc_read_nbytes(const int fd, const unsigned len, char* out) {
    bool rv = false;
    unsigned seen = 0;
    while(seen < len) {
        int readrv = read(fd, out + seen, len - seen);
        if(readrv < 1) {
            if(!readrv) {
                log_debug("plugin_extmon: emc_read_nbytes() failed: pipe closed");
                rv = true;
                break;
            }
            else if(errno != EAGAIN && errno != EINTR) {
                log_debug("plugin_extmon: emc_read_nbytes() failed: %s", dmn_strerror(errno));
                rv = true;
                break;
            }
        }
        else {
            seen += readrv;
        }
    }
    return rv;
}

bool emc_read_exact(const int fd, const char* str) {
    const unsigned len = strlen(str);
    char buf[len];
    return (emc_read_nbytes(fd, len, buf)
        || !!memcmp(str, buf, len));
}

bool emc_write_command(const int fd, const extmon_cmd_t* cmd) {
    unsigned alloc = 256;
    unsigned len = 0;
    char* buf = malloc(alloc);

    // 4 byte prefix "CMD:"
    memcpy(buf, "CMD:", 4);
    len += 4;

    // 2-byte index, 1-byte timeout, 1-byte interval
    *((uint16_t*)&buf[len]) = cmd->idx;
    len += 2;
    buf[len++] = cmd->timeout;
    buf[len++] = cmd->interval;

    // skip 2-byte len for rest of packet at offset 8
    len += 2;

    // arg count + NUL-terminated arguments
    buf[len++] = cmd->num_args;
    for(unsigned i = 0; i < cmd->num_args; i++) {
        const unsigned arg_len = strlen(cmd->args[i]) + 1;
        while((len + arg_len + 16) > alloc) {
            alloc *= 2;
            buf = realloc(buf, alloc);
        }
        memcpy(&buf[len], cmd->args[i], arg_len);
        len += arg_len;
    }

    // NUL-terminated description string
    const unsigned desc_len = strlen(cmd->desc) + 1;
    while((len + desc_len + 16) > alloc) {
        alloc *= 2;
        buf = realloc(buf, alloc);
    }
    memcpy(&buf[len], cmd->desc, desc_len);
    len += desc_len;

    // now go back and fill in the overall len
    //   of the variable area for desc/args.
    *((uint16_t*)&buf[8]) = len - 10;

    bool rv = emc_write_string(fd, buf, len);
    free(buf);
    return rv;
}

static bool nul_within_n_bytes(const char* instr, const unsigned len) {
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
    extmon_cmd_t* cmd = malloc(sizeof(extmon_cmd_t));

    char fixed_part[10];
    if(emc_read_nbytes(fd, 10, fixed_part)
        || strncmp(fixed_part, "CMD:", 4)) {
        log_debug("emc_read_command() failed to read CMD: prefix");
        return NULL;
    }
    uint16_t* idx_ptr = (uint16_t*)(&fixed_part[4]);
    cmd->idx = *idx_ptr;
    cmd->timeout = *((uint8_t*)&fixed_part[6]);
    cmd->interval = *((uint8_t*)&fixed_part[7]);

    // note we add an extra NULL at the end of args here, for execl()
    uint16_t* var_len_ptr = (uint16_t*)&fixed_part[8];
    const unsigned var_len = *var_len_ptr;
    if(var_len < 4) {
        // 4 bytes would be enough for num_args, a single 1-byte argument
        //   and its NUL termiantor, and a zero-length NUL-terminated desc
        log_debug("emc_read_command() variable section too short (%u)!", var_len);
        return NULL;
    }

    char var_part[var_len];
    if(emc_read_nbytes(fd, var_len, var_part)) {
        log_debug("emc_read_command() failed to read %u-byte variable section", var_len);
        return NULL;
    }

    cmd->num_args = *((uint8_t*)var_part);
    if(!cmd->num_args) {
        log_debug("emc_read_command() got zero-arg command!");
        return NULL;
    }

    cmd->args = malloc((cmd->num_args + 1) * sizeof(char*));
    const char* current = &var_part[1];
    unsigned len_remain = var_len - 1;
    for(unsigned i = 0; i < cmd->num_args; i++) {
        if(!nul_within_n_bytes(current, len_remain)) {
            log_debug("emc_read_command(): argument runs off end of buffer");
            return NULL;
        }
        const unsigned cmdlen = strlen(current) + 1;
        cmd->args[i] = malloc(cmdlen);
        memcpy((char*)cmd->args[i], current, cmdlen);
        current += cmdlen;
        len_remain -= cmdlen;
    }
    cmd->args[cmd->num_args] = NULL;

    if(!nul_within_n_bytes(current, len_remain)) {
        log_debug("emc_read_command(): argument runs off end of buffer");
        return NULL;
    }
    cmd->desc = strdup(current);
    current += strlen(current);
    current++;

    if(current != (var_part + var_len)) {
        log_debug("emc_read_command(): unused len at end of buffer!");
        return NULL;
    }

    return cmd;
}

