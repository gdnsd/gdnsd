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

#include "gdnsd-compiler.h"
#include "gdnsd-net.h"
#include "gdnsd-log.h"
#include "gdnsd-stats.h"
#include "gdnsd-dmn.h"
#include "gdnsd-misc-priv.h"

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

// Note: NI_MAXHOST seems to generally be 1025
const char* gdnsd_logf_anysin(const anysin_t* asin) {
    if(!asin)
        return generic_nullstr;

    char hostbuf[NI_MAXHOST + 1];
    char servbuf[NI_MAXSERV + 1];

    hostbuf[0] = servbuf[0] = 0; // JIC getnameinfo leaves them un-init
    int name_err = getnameinfo(&asin->sa, asin->len, hostbuf, NI_MAXHOST, servbuf, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
    if(name_err)
        return gai_strerror(name_err); // This might be confusing...

    const bool isv6 = (asin->sa.sa_family == AF_INET6);
    const size_t hostbuf_len = strlen(hostbuf);
    const size_t servbuf_len = strlen(servbuf);
    const size_t alloc_len = hostbuf_len + servbuf_len + (isv6 ? 2 : 4);
    char* buf = dmn_fmtbuf_alloc(alloc_len);
    char* bufptr = buf;
    if(isv6)
        *bufptr++ = '[';
    memcpy(bufptr, hostbuf, hostbuf_len);
    bufptr += hostbuf_len;
    if(isv6)
        *bufptr++ = ']';
    *bufptr++ = ':';
    memcpy(bufptr, servbuf, servbuf_len + 1); // include NUL

    return buf;
}

// Note: NI_MAXHOST seems to generally be 1025
const char* gdnsd_logf_anysin_noport(const anysin_t* asin) {
    if(!asin)
        return generic_nullstr;

    char hostbuf[NI_MAXHOST + 1];

    hostbuf[0] = 0; // JIC getnameinfo leaves them un-init
    int name_err = getnameinfo(&asin->sa, asin->len, hostbuf, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
    if(name_err)
        return gai_strerror(name_err); // This might be confusing...

    char* buf = dmn_fmtbuf_alloc(strlen(hostbuf) + 1);
    strcpy(buf, hostbuf);

    return buf;
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

const char* gdnsd_logf_pathname(const char* relpath) {
    const char* rootpath = gdnsd_get_rootdir();
    const unsigned rootlen = strlen(rootpath);
    const unsigned rplen = relpath ? strlen(relpath) : 0;
    const unsigned oal = rootlen + 1 + rplen;
    char* space = dmn_fmtbuf_alloc(oal + 1);
    memcpy(space, rootpath, rootlen);
    space[rootlen] = '/';
    memcpy(space + rootlen + 1, relpath, rplen);
    space[oal] = 0;
    return space;
}
