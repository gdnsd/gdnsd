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

void emc_write_string(const int fd, const char* str, const unsigned len) {
    unsigned written = 0;
    while(written < len) {
        int rv = write(fd, str + written, len - written);
        if(rv < 1) {
            if(!rv)
                log_fatal("plugin_extmon: emc_write_string(%s) failed: pipe closed", str);
            if(errno != EAGAIN && errno != EINTR)
                log_fatal("plugin_extmon: emc_write_string(%s) failed: %s", str, dmn_strerror(errno));
        }
        else {
            written += rv;
        }
    }
}

void emc_read_nbytes(const int fd, const unsigned len, char* out) {
    unsigned seen = 0;
    while(seen < len) {
        int rv = read(fd, out + seen, len - seen);
        if(rv < 1) {
            if(!rv)
                log_fatal("plugin_extmon: emc_read_nbytes() failed: pipe closed");
            if(errno != EAGAIN && errno != EINTR)
                log_fatal("plugin_extmon: emc_read_nbytes() failed: %s", dmn_strerror(errno));
        }
        else {
            seen += rv;
        }
    }
}

void emc_read_exact(const int fd, const char* str) {
    const unsigned len = strlen(str);
    char buf[len];
    emc_read_nbytes(fd, len, buf);
    if(memcmp(str, buf, len))
        log_fatal("plugin_extmon: emc_read_exact() mismatch: wanted '%s', got '%s'", str, buf);
}

void emc_write_command(const int fd, const extmon_cmd_t* cmd) {
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

    emc_write_string(fd, buf, len);
    free(buf);
}

extmon_cmd_t* emc_read_command(const int fd) {
    extmon_cmd_t* cmd = malloc(sizeof(extmon_cmd_t));

    char fixed_part[10];
    emc_read_nbytes(fd, 10, fixed_part);
    if(strncmp(fixed_part, "CMD:", 4))
        log_fatal("plugin_extmon: did not see expected command prefix");
    uint16_t* idx_ptr = (uint16_t*)(&fixed_part[4]);
    cmd->idx = *idx_ptr;
    cmd->timeout = *((uint8_t*)&fixed_part[6]);
    cmd->interval = *((uint8_t*)&fixed_part[7]);

    // note we add an extra NULL at the end of args here, for execl()
    uint16_t* var_len_ptr = (uint16_t*)&fixed_part[8];
    const unsigned var_len = *var_len_ptr;
    char var_part[var_len];
    emc_read_nbytes(fd, var_len, var_part);
    cmd->num_args = *((uint8_t*)var_part);
    cmd->args = malloc((cmd->num_args + 1) * sizeof(char*));
    const char* current = &var_part[1];
    for(unsigned i = 0; i < cmd->num_args; i++) {
        cmd->args[i] = strdup(current);
        current += strlen(current);
        current++;
    }
    cmd->args[cmd->num_args] = NULL;

    cmd->desc = strdup(current);
    current += strlen(current);
    current++;
    dmn_assert((current - var_part) == var_len);

    return cmd;
}

