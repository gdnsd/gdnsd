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

#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <pthread.h>

#include "gdnsd/compiler.h"
#include "gdnsd/net.h"
#include "gdnsd/log.h"
#include "gdnsd/stats.h"
#include "gdnsd/dmn.h"
#include "gdnsd/paths-priv.h"

/* libdmn custom log formatters and the buffer sizes they use:
 *
 * const char* logf_anysin(const anysin_t* asin); // variable...
 * const char* logf_anysin_noport(const anysin_t* asin); // variable...
 * const char* logf_dname(const uint8_t* dname); // 1024
 *
 * Usage example:
 *   anysin_t* saddr = ...;
 *   uint8_t*  dname = ...;
 *   int pthread_errno = ...;
 *   log_err("pthread error: %s during req for name '%s' from %s",
 *      logf_errnum(pthread_errno), logf_dname(dname), logf_anysin(saddr));
 */

static const char* generic_nullstr = "(null)";

const char* gdnsd_logf_ipv6(const uint8_t* ipv6) {
    anysin_t tempsin;
    memset(&tempsin, 0, sizeof(anysin_t));
    tempsin.sin.sin_family = AF_INET6;
    memcpy(tempsin.sin6.sin6_addr.s6_addr, ipv6, 16);
    tempsin.len = sizeof(struct sockaddr_in6);
    return gdnsd_logf_anysin_noport(&tempsin);
}

const char* gdnsd_logf_in6a(const struct in6_addr* in6a) {
    return gdnsd_logf_ipv6(in6a->s6_addr);
}

const char* gdnsd_logf_dname(const uint8_t* dname) {
    if(!dname)
        return generic_nullstr;

    char* dnbuf = dmn_fmtbuf_alloc(1024);
    char* dnptr = dnbuf;

    dname++; // skip initial OAL byte

    unsigned llen;
    while(1) {
        llen = *dname++;

        // Handle terminal cases
        if(llen == 255)
            break;
        if(llen == 0) {
            *dnptr++ = '.';
            break;
        }

        // Inter-label dot, if something has already been written
        if(dnptr != dnbuf)
            *dnptr++ = '.';

        // Label text
        for(uint8_t i = 0; i < llen; i++) {
            unsigned char x = *dname++;
            if(x > 0x20 && x < 0x7F) {
                *dnptr++ = x;
            }
            else {
                *dnptr++ = '\\';
                *dnptr++ = '0' + (x / 100);
                *dnptr++ = '0' + ((x / 10) % 10);
                *dnptr++ = '0' + (x % 10);
            }
        }
    }

    *dnptr = '\0';
    return dnbuf;
}

const char* gdnsd_logf_pathname(const char* inpath) {
    char* space = NULL;

    if(!inpath) {
        space = dmn_fmtbuf_alloc(7);
        memcpy(space, "<NULL>", 7); // includes NUL
    }
    else {
        const unsigned inlen = strlen(inpath);
        const char* rootpath = gdnsd_get_rootdir();
        if(rootpath) {
            const unsigned rootlen = strlen(rootpath);
            const unsigned toalloc = 1 + rootlen + 1 + 1 + inlen + 1;
            char* space_ptr = space = dmn_fmtbuf_alloc(toalloc);
            *space_ptr++ = '[';
            memcpy(space_ptr, rootpath, rootlen); space_ptr += rootlen;
            *space_ptr++ = ']';
            *space_ptr++ = '/';
            memcpy(space_ptr, inpath, inlen + 1); // includes NUL
        }
        else {
            space = dmn_fmtbuf_alloc(inlen + 1);
            memcpy(space, inpath, inlen + 1); // includes NUL
        }
    }

    return space;
}
