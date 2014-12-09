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
#include "net.h"

#include <gdnsd/log.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

/* network utils */

static int tcp_proto = 0;
static int udp_proto = 0;
static bool reuseport_ok = false;

void gdnsd_init_net(void) {
    static bool has_run = false;
    if(has_run)
        log_fatal("BUG: gdnsd_init_net() should only be called once!");
    else
        has_run = true;

    struct protoent* pe;

    // cppcheck-suppress nonreentrantFunctionsgetprotobyname (init time, no threads)
    pe = getprotobyname("tcp");
    if(!pe)
        log_fatal("getprotobyname('tcp') failed");
    tcp_proto = pe->p_proto;

    // cppcheck-suppress nonreentrantFunctionsgetprotobyname (init time, no threads)
    pe = getprotobyname("udp");
    if(!pe)
        log_fatal("getprotobyname('udp') failed");
    udp_proto = pe->p_proto;

#ifdef SO_REUSEPORT
    const int sock_rp = socket(PF_INET, SOCK_DGRAM, udp_proto);
    if(sock_rp > -1) {
        const int opt_one = 1;
        if(!setsockopt(sock_rp, SOL_SOCKET, SO_REUSEPORT, &opt_one, sizeof opt_one))
            reuseport_ok = true;
        close(sock_rp);
    }
#endif
}

int gdnsd_getproto_udp(void) { return udp_proto; }
int gdnsd_getproto_tcp(void) { return tcp_proto; }
bool gdnsd_reuseport_ok(void) { return reuseport_ok; }
