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

#ifndef GDNSD_NET_H
#define GDNSD_NET_H

#include <gdnsd/compiler.h>

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#define gdnsd_anysin_getaddrinfo gdnsd_anysin_getaddrinfo
#define gdnsd_anysin_fromstr gdnsd_anysin_fromstr

#if EAGAIN == EWOULDBLOCK
#  define ERRNO_WOULDBLOCK (errno == EAGAIN)
#else
#  define ERRNO_WOULDBLOCK (errno == EAGAIN || errno == EWOULDBLOCK)
#endif

#pragma GCC visibility push(default)

// Initialize network stuff (caches getprotoent, test features, etc),
// needed before runtime socket creations, etc.
void gdnsd_init_net(void);

// Plugins should use these to get protocol numbers
F_PURE
int gdnsd_getproto_udp(void);
F_PURE
int gdnsd_getproto_tcp(void);

// Whether SO_REUSEPORT seems to be a runtime-valid sockopt
F_PURE
bool gdnsd_reuseport_ok(void);

/* Socket union type */
// note anonymous union here, which gcc has supported
//  forever, and is now becoming standard in C11
typedef struct {
    union {
        struct sockaddr_in6 sin6;
        struct sockaddr_in  sin;
        struct sockaddr     sa;
    };
    socklen_t len;
} gdnsd_anysin_t;

// This is a maximum for the value of gdnsd_anysin_t.len
#define GDNSD_ANYSIN_MAXLEN sizeof(struct sockaddr_in6)

// max length of ASCII numeric ipv6 addr, with room for trailing NUL
#ifndef INET6_ADDRSTRLEN
#  define INET6_ADDRSTRLEN 46
#endif

// maximum addr:port ASCII representation from gdnsd_anysin2str below
// maximal form is "[...IPv6...]:12345\0"
#define GDNSD_ANYSIN_MAXSTR (1 + ((INET6_ADDRSTRLEN) - 1) + 1 + 1 + 5 + 1)

// transforms addr_txt + port_txt -> result using getaddrinfo(), setting result->len
// input text fields must be numeric, not hostnames or port names.
// if false, hostnames and port names are possible, which may result
//    in the libc doing DNS lookups and such on your behalf.
// caller must allocate result to sizeof(gdnsd_anysin_t)
// port_txt can be NULL, in which case the proto-specific port field will be zero
// retval is retval from getaddrinfo() itself (if non-zero, error occurred and
//   string representation is available from gai_strerror()).
// result is unaffected if an error occurs.
F_NONNULLX(1,3)
int gdnsd_anysin_getaddrinfo(const char* addr_txt, const char* port_txt, gdnsd_anysin_t* result);

// As above, but for parsing the address and port from a single string of the form addr:port,
//   where :port is optional, and addr may be surround by [] (to help with ipv6 [::1]:53 issues).
// Port defaults to unsigned arg "def_port" if not specified in the input string.
F_NONNULLX(1,3)
int gdnsd_anysin_fromstr(const char* addr_port_text, const unsigned def_port, gdnsd_anysin_t* result);

// Check if the sockaddr is the V4 or V6 ANY-address (0.0.0.0, or ::)
F_NONNULL
bool gdnsd_anysin_is_anyaddr(const gdnsd_anysin_t* asin);

// convert "asin" to numeric ASCII of the form "ipv4:port" or "[ipv6]:port"
// NULL input results in the string "(null)"
// note that buf *must* be pre-allocated to at least GDNSD_ANYSIN_MAXSTR bytes!
// return value is from getaddrinfo() (0 for success, otherwise pass to gai_strerror())
F_NONNULLX(2)
int gdnsd_anysin2str(const gdnsd_anysin_t* asin, char* buf);

// convert just the address portion to ASCII in "buf"
// NULL input results in the string "(null)"
// note that buf *must* be pre-allocated to at least INET6_ADDRSTRLEN bytes!
// return value is from getaddrinfo() (0 for success, otherwise pass to gai_strerror())
F_NONNULLX(2)
int gdnsd_anysin2str_noport(const gdnsd_anysin_t* asin, char* buf);

// Log-formatters for gdnsd_anysin_t + gdnsd_log_*(), which use the above...
F_RETNN
const char* gdnsd_logf_anysin(const gdnsd_anysin_t* asin);
F_RETNN
const char* gdnsd_logf_anysin_noport(const gdnsd_anysin_t* asin);

#pragma GCC visibility pop

#define logf_anysin gdnsd_logf_anysin
#define logf_anysin_noport gdnsd_logf_anysin_noport

#endif // GDNSD_NET_H
