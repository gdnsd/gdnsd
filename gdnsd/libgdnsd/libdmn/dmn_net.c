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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

#include "dmn.h"

/* network utils */

int dmn_anysin_getaddrinfo(const char* addr_txt, const char* port_txt, dmn_anysin_t* result, bool numeric_only) {
    dmn_assert(addr_txt); dmn_assert(result);

    struct addrinfo* ainfo = NULL;
    const struct addrinfo hints = {
        .ai_flags = numeric_only ? (AI_NUMERICHOST | AI_NUMERICSERV) : 0,
        .ai_family = AF_UNSPEC,
        .ai_socktype = 0,
        .ai_protocol = 0,
        .ai_addrlen = 0,
        .ai_addr = NULL,
        .ai_canonname = NULL,
        .ai_next = NULL
    };

    const int addr_err = getaddrinfo(addr_txt, port_txt, &hints, &ainfo);

    if(!addr_err) {
        // Zero-out the result in case of strange earlier contents,
        //  and also to gaurantee a zero port if port_txt is NULL
        //  (getaddrinfo() itself docs that it may be uninitialized)
        memset(result, 0, sizeof(dmn_anysin_t));
        memcpy(&result->sa, ainfo->ai_addr, ainfo->ai_addrlen);
        result->len = ainfo->ai_addrlen;
    }

    if(ainfo)
        freeaddrinfo(ainfo);

    return addr_err;
}

static const char invalid_addr[] = "!!invalid!!";

int dmn_anysin_fromstr(const char* addr_port_text, const unsigned def_port, dmn_anysin_t* result, bool numeric_only) {
    dmn_assert(addr_port_text); dmn_assert(result);

    char* apcopy = strdup(addr_port_text);

    const char* addr = apcopy;
    char* port = NULL;
    if(addr[0] == '[') {
        char* end_brace = strchr(addr, ']');
        if(end_brace) {
            addr++; // set address start past initial '['
            *end_brace = '\0'; // terminate address part
            if(end_brace[1] == ':' && end_brace[2])
                port = &end_brace[2]; // set port
        }
    }
    else {
        port = strchr(addr, ':'); // set port
        if(port) {
            // If two colons present in addr_port_text without [],
            //   assume IPv6 with no port info
            char* check_v6 = strchr(port + 1, ':');
            if(check_v6) {
                port = NULL;
            }
            // If the user's string was ":12345", that's illegal
            //  by our definition, but some getaddrinfo() implementations
            //  will interpret the zero-length NUL-terminated address
            //  string we would otherwise provide as "::1", don't ask
            //  me why.  So make it *really* invalid to trigger an
            //  an error later in getaddrinfo()
            else if(port == addr) {
                addr = invalid_addr;
            }
            // Else assume IPv4:port
            else {
                *port++ = '\0'; // terminate address part
                if(!*port) port = NULL; // makes default decision easier
            }
        }
    }

    int addr_err = dmn_anysin_getaddrinfo(addr, port, result, numeric_only);

    // set default port
    if(!addr_err && !port && def_port) {
        if(result->sa.sa_family == AF_INET) {
            result->sin.sin_port = htons(def_port);
        }
        else {
            dmn_assert(result->sa.sa_family == AF_INET6);
            result->sin6.sin6_port = htons(def_port);
        }
    }

    free(apcopy);
    return addr_err;
}

bool dmn_anysin_is_anyaddr(const dmn_anysin_t* asin) {
    dmn_assert(asin);
    dmn_assert(asin->sa.sa_family == AF_INET || asin->sa.sa_family == AF_INET6);

    if(asin->sa.sa_family == AF_INET6) {
        if(!memcmp(&asin->sin6.sin6_addr.s6_addr, &in6addr_any, sizeof(struct in6_addr)))
            return true;
    }
    else if(asin->sin.sin_addr.s_addr == INADDR_ANY) {
            return true;
    }

    return false;
}

static const char* generic_nullstr = "(null)";

// Note: NI_MAXHOST seems to generally be 1025
const char* dmn_logf_anysin(const dmn_anysin_t* asin) {
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
const char* dmn_logf_anysin_noport(const dmn_anysin_t* asin) {
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
