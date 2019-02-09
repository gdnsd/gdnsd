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
#include <sys/un.h>
#include <netdb.h>
#include <errno.h>

#define gdnsd_anysin_getaddrinfo gdnsd_anysin_getaddrinfo
#define gdnsd_anysin_fromstr gdnsd_anysin_fromstr

#if EAGAIN == EWOULDBLOCK
#  define ERRNO_WOULDBLOCK (errno == EAGAIN)
#else
#  define ERRNO_WOULDBLOCK (errno == EAGAIN || errno == EWOULDBLOCK)
#endif

F_NONNULL
socklen_t gdnsd_sun_set_path(struct sockaddr_un* a, const char* path);

/* Socket union type */
// note anonymous union here, which gcc has supported
//  forever, and is now becoming standard in C11
typedef struct {
    union {
        struct sockaddr_in6 sin6;
        struct sockaddr_in  sin4;
        struct sockaddr     sa;
    };
    socklen_t len;
} gdnsd_anysin_t;

// read-only for plugins
typedef struct {
    gdnsd_anysin_t dns_source;       // address of last source DNS cache/forwarder
    gdnsd_anysin_t edns_client;      // edns-client-subnet address portion
    unsigned edns_client_mask; // edns-client-subnet mask portion
} client_info_t;               //  ^(if zero, edns_client is invalid (was not sent))

// This is a maximum for the value of gdnsd_anysin_t.len
#define GDNSD_ANYSIN_MAXLEN sizeof(struct sockaddr_in6)

// max length of ASCII numeric ipv6 addr, with room for trailing NUL
#ifndef INET6_ADDRSTRLEN
#  define INET6_ADDRSTRLEN 46
#endif

// maximum addr:port ASCII representation from gdnsd_anysin2str below
// maximal form is "[IPv6%f]:12345\0" where "%f" is a flow label, which we're
// just kinda guessing can fit in 32 bytes or so.
//                           [   IPv6 (incl NUL)    f ]   :   port
#define GDNSD_ANYSIN_MAXSTR (1 + INET6_ADDRSTRLEN + 32 + 1 + 1 + 5)

// transforms addr_txt + port_txt -> result using getaddrinfo(), setting result->len
// input text fields must be numeric, not hostnames or port names.
// if false, hostnames and port names are possible, which may result
//    in the libc doing DNS lookups and such on your behalf.
// caller must allocate result to sizeof(gdnsd_anysin_t)
// port_txt can be NULL, in which case the proto-specific port field will be zero
// retval is retval from getaddrinfo() itself (if non-zero, error occurred and
//   string representation is available from gai_strerror()).
// result is unaffected if an error occurs.
F_NONNULLX(1, 3)
int gdnsd_anysin_getaddrinfo(const char* addr_txt, const char* port_txt, gdnsd_anysin_t* result);

// As above, but for parsing the address and port from a single string of the form addr:port,
//   where :port is optional, and addr may be surround by [] (to help with ipv6 [::1]:53 issues).
// Port defaults to unsigned arg "def_port" if not specified in the input string.
F_NONNULLX(1, 3)
int gdnsd_anysin_fromstr(const char* addr_port_text, const unsigned def_port, gdnsd_anysin_t* result);

// Check if the sockaddr is the V4 or V6 ANY-address (0.0.0.0, or ::)
F_NONNULL F_PURE
bool gdnsd_anysin_is_anyaddr(const gdnsd_anysin_t* sa);

// convert "sa" to numeric ASCII of the form "ipv4:port" or "[ipv6]:port"
// NULL input results in the string "(null)"
// note that buf *must* be pre-allocated to at least GDNSD_ANYSIN_MAXSTR bytes!
// return value is from getaddrinfo() (0 for success, otherwise pass to gai_strerror())
F_NONNULLX(2) F_COLD
int gdnsd_anysin2str(const gdnsd_anysin_t* sa, char* buf);

// convert just the address portion to ASCII in "buf"
// NULL input results in the string "(null)"
// note that buf *must* be pre-allocated to at least GDNSD_ANYSIN_MAXSTR bytes!
// return value is from getaddrinfo() (0 for success, otherwise pass to gai_strerror())
F_NONNULLX(2) F_COLD
int gdnsd_anysin2str_noport(const gdnsd_anysin_t* sa, char* buf);

// Log-formatters for gdnsd_anysin_t + gdnsd_log_*(), which use the above...
F_RETNN F_COLD
const char* gdnsd_logf_anysin(const gdnsd_anysin_t* sa);
F_RETNN F_COLD
const char* gdnsd_logf_anysin_noport(const gdnsd_anysin_t* sa);

#define logf_anysin gdnsd_logf_anysin
#define logf_anysin_noport gdnsd_logf_anysin_noport

// Idempotent (get, then set only if needs to change) setsockopt for basic integers.
// The "bool" variants use an integer type, but only compare get-vs-set as
// booleans (e.g. get returning 16 will still match a desired set value of 1):

#define sockopt_int_fatal(proto, sa, sock, level, optname, wantval) \
    gdnsd_sockopt_idem_int_(sock, level, optname, wantval, true, false, sa, #level, #optname, #proto)

#define sockopt_bool_fatal(proto, sa, sock, level, optname, wantval) \
    gdnsd_sockopt_idem_int_(sock, level, optname, wantval, true, true, sa, #level, #optname, #proto)

#define sockopt_int_warn(proto, sa, sock, level, optname, wantval) \
    gdnsd_sockopt_idem_int_(sock, level, optname, wantval, false, false, sa, #level, #optname, #proto)

#define sockopt_bool_warn(proto, sa, sock, level, optname, wantval) \
    gdnsd_sockopt_idem_int_(sock, level, optname, wantval, false, true, sa, #level, #optname, #proto)

void gdnsd_sockopt_idem_int_(const int sock, const int level, const int optname, const int wantval, const bool fatal, const bool is_bool, const gdnsd_anysin_t* sa, const char* level_str, const char* optname_str, const char* proto_str);

#endif // GDNSD_NET_H
