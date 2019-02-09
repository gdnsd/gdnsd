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
#include <gdnsd/alloc.h>

#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <string.h>

/* network utils */


/******************************************************************************
 * This block handles the mismatch of get/set sockopt values for
 * TCP_DEFER_ACCEPT on Linux.  The algorithms and constants here are from the
 * kernel, but are pretty stable.
 *****************************************************************************/
#ifdef __linux__

#define LINUX_TCP_RTO_MAX 120
#define LINUX_TCP_TIMEOUT_INIT 1

static uint8_t secs_to_retrans(int seconds)
{
    uint8_t res = 0;
    if (seconds > 0) {
        int timeout = LINUX_TCP_TIMEOUT_INIT;
        int period = timeout;
        res = 1;
        while (seconds > period && res < 255) {
            res++;
            timeout <<= 1;
            if (timeout > LINUX_TCP_RTO_MAX)
                timeout = LINUX_TCP_RTO_MAX;
            period += timeout;
        }
    }
    return res;
}

static int retrans_to_secs(uint8_t retrans)
{
    int period = 0;
    if (retrans > 0) {
        int timeout = LINUX_TCP_TIMEOUT_INIT;
        period = timeout;
        while (--retrans) {
            timeout <<= 1;
            if (timeout > LINUX_TCP_RTO_MAX)
                timeout = LINUX_TCP_RTO_MAX;
            period += timeout;
        }
    }
    return period;
}

static int tcpdefaccept_xlate_secs(int seconds)
{
    return retrans_to_secs(secs_to_retrans(seconds));
}

#endif
/******************************************************************************
 * End block of Linux TCP_DEFER_ACCEPT hackery
 *****************************************************************************/

void gdnsd_sockopt_idem_int_(const int sock, const int level, const int optname, const int wantval, const bool fatal, const bool is_bool, const gdnsd_anysin_t* sa, const char* level_str, const char* optname_str, const char* proto_str)
{
    int current = 0;
    socklen_t s_current = sizeof(current);
    int compare = wantval;
#ifdef __linux__
    // Linux hack: buffers are reported back at 2x configured value
    if (level == SOL_SOCKET && (optname == SO_RCVBUF || optname == SO_SNDBUF))
        compare *= 2;
    // Linux hack: defer accept timeout is translated from seconds to
    // retransmits on set, then back to seconds on get, which rounds it up
    // based on tcp retransmit timing algorithm.
    if (level == SOL_TCP && optname == TCP_DEFER_ACCEPT)
        compare = tcpdefaccept_xlate_secs(compare);
#endif
    if (getsockopt(sock, level, optname, &current, &s_current)) {
        if (fatal)
            log_fatal("getsockopt(%s:%s, %s, %s) failed: %s", proto_str, logf_anysin(sa), level_str, optname_str, logf_errno());
        else
            log_warn("getsockopt(%s:%s, %s, %s) failed: %s", proto_str, logf_anysin(sa), level_str, optname_str, logf_errno());
    } else {
        bool ok;
        if (is_bool)
            ok = (!current == !compare);
        else
            ok = (current == compare);
        if (!ok && setsockopt(sock, level, optname, &wantval, sizeof(wantval))) {
            if (fatal)
                log_fatal("setsockopt(%s:%s, %s, %s, %i) failed: %s", proto_str, logf_anysin(sa), level_str, optname_str, wantval, logf_errno());
            else
                log_warn("setsockopt(%s:%s, %s, %s, %i) failed: %s", proto_str, logf_anysin(sa), level_str, optname_str, wantval, logf_errno());
        }
    }
}

socklen_t gdnsd_sun_set_path(struct sockaddr_un* a, const char* path)
{
    memset(a, 0, sizeof(*a));
    a->sun_family = AF_UNIX;
    const unsigned plen = strlen(path) + 1;
    if (plen > sizeof(a->sun_path))
        log_fatal("Implementation bug/limit: desired control socket path %s exceeds sun_path length of %zu", path, sizeof(a->sun_path));
    memcpy(a->sun_path, path, plen);
    return (offsetof(struct sockaddr_un, sun_path) + plen);
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
        //  and also to guarantee a zero port if port_txt is NULL
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
    char* apcopy = xstrdup(addr_port_text);

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
            result->sin4.sin_port = htons(def_port);
        } else {
            gdnsd_assert(result->sa.sa_family == AF_INET6);
            result->sin6.sin6_port = htons(def_port);
        }
    }

    free(apcopy);
    return addr_err;
}

bool gdnsd_anysin_is_anyaddr(const gdnsd_anysin_t* sa)
{
    gdnsd_assert(sa->sa.sa_family == AF_INET || sa->sa.sa_family == AF_INET6);

    if (sa->sa.sa_family == AF_INET6) {
        if (!memcmp(&sa->sin6.sin6_addr.s6_addr, &in6addr_any, sizeof(in6addr_any)))
            return true;
    } else if (sa->sin4.sin_addr.s_addr == INADDR_ANY) {
        return true;
    }

    return false;
}

static const char generic_nullstr[] = "(null)";

int gdnsd_anysin2str(const gdnsd_anysin_t* sa, char* buf)
{
    int name_err = 0;
    buf[0] = 0;

    char hostbuf[INET6_ADDRSTRLEN + 32];
    char servbuf[6];
    hostbuf[0] = servbuf[0] = 0; // JIC getnameinfo leaves them un-init

    if (sa) {
        name_err = getnameinfo(&sa->sa, sa->len, hostbuf, INET6_ADDRSTRLEN + 32, servbuf, 6, NI_NUMERICHOST | NI_NUMERICSERV);
        if (!name_err) {
            if (sa->sa.sa_family == AF_INET6)
                snprintf(buf, GDNSD_ANYSIN_MAXSTR, "[%s]:%s", hostbuf, servbuf);
            else
                snprintf(buf, GDNSD_ANYSIN_MAXSTR, "%s:%s", hostbuf, servbuf);
        }
    } else {
        memcpy(buf, generic_nullstr, sizeof(generic_nullstr));
    }

    return name_err;
}

const char* gdnsd_logf_anysin(const gdnsd_anysin_t* sa)
{
    char tmpbuf[GDNSD_ANYSIN_MAXSTR];
    int name_err = gdnsd_anysin2str(sa, tmpbuf);
    if (name_err)
        return gai_strerror(name_err); // This might be confusing...

    const unsigned copylen = strlen(tmpbuf) + 1;
    char* buf = gdnsd_fmtbuf_alloc(copylen);
    memcpy(buf, tmpbuf, copylen);

    return buf;
}

int gdnsd_anysin2str_noport(const gdnsd_anysin_t* sa, char* buf)
{
    int name_err = 0;
    buf[0] = 0;

    if (sa)
        name_err = getnameinfo(&sa->sa, sa->len, buf, GDNSD_ANYSIN_MAXSTR, NULL, 0, NI_NUMERICHOST);
    else
        memcpy(buf, generic_nullstr, sizeof(generic_nullstr));

    return name_err;
}

const char* gdnsd_logf_anysin_noport(const gdnsd_anysin_t* sa)
{
    char tmpbuf[GDNSD_ANYSIN_MAXSTR];
    int name_err = gdnsd_anysin2str_noport(sa, tmpbuf);
    if (name_err)
        return gai_strerror(name_err); // This might be confusing...

    const unsigned copylen = strlen(tmpbuf) + 1;
    char* buf = gdnsd_fmtbuf_alloc(copylen);
    memcpy(buf, tmpbuf, copylen);
    return buf;
}
