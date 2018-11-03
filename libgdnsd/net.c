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
#include <gdnsd/net.h>

#include <gdnsd/log.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <string.h>

/* network utils */

static int tcp_proto = 0;
static int udp_proto = 0;

void gdnsd_init_net(void)
{
    static bool has_run = false;
    if (has_run)
        log_fatal("BUG: gdnsd_init_net() should only be called once!");
    else
        has_run = true;

    struct protoent* pe;

    // cppcheck-suppress getprotobynameCalled (init time, no threads)
    pe = getprotobyname("tcp");
    if (!pe)
        log_fatal("getprotobyname('tcp') failed");
    tcp_proto = pe->p_proto;

    // cppcheck-suppress getprotobynameCalled (init time, no threads)
    pe = getprotobyname("udp");
    if (!pe)
        log_fatal("getprotobyname('udp') failed");
    udp_proto = pe->p_proto;
}

void gdnsd_sun_set_path(struct sockaddr_un* a, const char* path)
{
    memset(a, 0, sizeof(*a));
    a->sun_family = AF_UNIX;
    const unsigned plen = strlen(path) + 1;
    if (plen > sizeof(a->sun_path))
        log_fatal("Implementation bug/limit: desired control socket path %s exceeds sun_path length of %zu", path, sizeof(a->sun_path));
    memcpy(a->sun_path, path, plen);
}

int gdnsd_getproto_udp(void)
{
    return udp_proto;
}

int gdnsd_getproto_tcp(void)
{
    return tcp_proto;
}

int gdnsd_anysin_getaddrinfo(const char* addr_txt, const char* port_txt, gdnsd_anysin_t* result)
{
    struct addrinfo* ainfo = NULL;
    const struct addrinfo hints = {
        .ai_flags = AI_NUMERICHOST | AI_NUMERICSERV,
        .ai_family = AF_UNSPEC,
        .ai_socktype = 0,
        .ai_protocol = 0,
        .ai_addrlen = 0,
        .ai_addr = NULL,
        .ai_canonname = NULL,
        .ai_next = NULL
    };

    const int addr_err = getaddrinfo(addr_txt, port_txt, &hints, &ainfo);

    if (!addr_err) {
        // Zero-out the result in case of strange earlier contents,
        //  and also to gaurantee a zero port if port_txt is NULL
        //  (getaddrinfo() itself docs that it may be uninitialized)
        memset(result, 0, sizeof(*result));
        memcpy(&result->sa, ainfo->ai_addr, ainfo->ai_addrlen);
        result->len = ainfo->ai_addrlen;
    }

    if (ainfo)
        freeaddrinfo(ainfo);

    return addr_err;
}

static const char invalid_addr[] = "!!invalid!!";

int gdnsd_anysin_fromstr(const char* addr_port_text, const unsigned def_port, gdnsd_anysin_t* result)
{
    char* apcopy = strdup(addr_port_text);

    const char* addr = apcopy;
    char* port = NULL;
    if (addr[0] == '[') {
        char* end_brace = strchr(addr, ']');
        if (end_brace) {
            addr++; // set address start past initial '['
            *end_brace = '\0'; // terminate address part
            if (end_brace[1] == ':' && end_brace[2])
                port = &end_brace[2]; // set port
        }
    } else {
        port = strchr(addr, ':'); // set port
        if (port) {
            // If two colons present in addr_port_text without [],
            //   assume IPv6 with no port info
            char* check_v6 = strchr(port + 1, ':');
            if (check_v6) {
                port = NULL;
            } else if (port == addr) {
                // If the user's string was ":12345", that's illegal
                //  by our definition, but some getaddrinfo() implementations
                //  will interpret the zero-length NUL-terminated address
                //  string we would otherwise provide as "::1", don't ask
                //  me why.  So make it *really* invalid to trigger an
                //  an error later in getaddrinfo()
                addr = invalid_addr;
            } else {
                // Else assume IPv4:port
                *port++ = '\0'; // terminate address part
                if (!*port)
                    port = NULL; // makes default decision easier
            }
        }
    }

    int addr_err = gdnsd_anysin_getaddrinfo(addr, port, result);

    // set default port
    if (!addr_err && !port && def_port) {
        if (result->sa.sa_family == AF_INET) {
            result->sin.sin_port = htons(def_port);
        } else {
            gdnsd_assert(result->sa.sa_family == AF_INET6);
            result->sin6.sin6_port = htons(def_port);
        }
    }

    free(apcopy);
    return addr_err;
}

bool gdnsd_anysin_is_anyaddr(const gdnsd_anysin_t* asin)
{
    gdnsd_assert(asin->sa.sa_family == AF_INET || asin->sa.sa_family == AF_INET6);

    if (asin->sa.sa_family == AF_INET6) {
        if (!memcmp(&asin->sin6.sin6_addr.s6_addr, &in6addr_any, sizeof(in6addr_any)))
            return true;
    } else if (asin->sin.sin_addr.s_addr == INADDR_ANY) {
        return true;
    }

    return false;
}

static const char* generic_nullstr = "(null)";

int gdnsd_anysin2str(const gdnsd_anysin_t* asin, char* buf)
{
    int name_err = 0;
    buf[0] = 0;

    char hostbuf[INET6_ADDRSTRLEN];
    char servbuf[6];
    hostbuf[0] = servbuf[0] = 0; // JIC getnameinfo leaves them un-init

    if (asin) {
        name_err = getnameinfo(&asin->sa, asin->len, hostbuf, INET6_ADDRSTRLEN, servbuf, 6, NI_NUMERICHOST | NI_NUMERICSERV);
        if (!name_err) {
            const bool isv6 = (asin->sa.sa_family == AF_INET6);
            const unsigned hostbuf_len = strlen(hostbuf);
            const unsigned servbuf_len = strlen(servbuf);
            gdnsd_assert((hostbuf_len + servbuf_len + (isv6 ? 4 : 2)) <= GDNSD_ANYSIN_MAXSTR);
            char* bufptr = buf;
            if (isv6)
                *bufptr++ = '[';
            memcpy(bufptr, hostbuf, hostbuf_len);
            bufptr += hostbuf_len;
            if (isv6)
                *bufptr++ = ']';
            *bufptr++ = ':';
            memcpy(bufptr, servbuf, servbuf_len + 1); // include NUL
        }
    } else {
        strcpy(buf, generic_nullstr);
    }

    return name_err;
}

const char* gdnsd_logf_anysin(const gdnsd_anysin_t* asin)
{
    char tmpbuf[GDNSD_ANYSIN_MAXSTR];
    int name_err = gdnsd_anysin2str(asin, tmpbuf);
    if (name_err)
        return gai_strerror(name_err); // This might be confusing...

    const unsigned copylen = strlen(tmpbuf) + 1;
    char* buf = gdnsd_fmtbuf_alloc(copylen);
    memcpy(buf, tmpbuf, copylen);

    return buf;
}

int gdnsd_anysin2str_noport(const gdnsd_anysin_t* asin, char* buf)
{
    int name_err = 0;
    buf[0] = 0;

    if (asin)
        name_err = getnameinfo(&asin->sa, asin->len, buf, INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST);
    else
        strcpy(buf, generic_nullstr);

    return name_err;
}

const char* gdnsd_logf_anysin_noport(const gdnsd_anysin_t* asin)
{
    char tmpbuf[INET6_ADDRSTRLEN];
    int name_err = gdnsd_anysin2str_noport(asin, tmpbuf);
    if (name_err)
        return gai_strerror(name_err); // This might be confusing...

    const unsigned copylen = strlen(tmpbuf) + 1;
    char* buf = gdnsd_fmtbuf_alloc(copylen);
    memcpy(buf, tmpbuf, copylen);
    return buf;
}
