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

#include "gdnsd/net.h"
#include "gdnsd/net-priv.h"
#include "gdnsd/log.h"

/* network utils */

static int tcp_proto = 0;
static int udp_proto = 0;
static bool tcp_v6_ok = false;

void gdnsd_init_net(void) {
    struct protoent* pe;

    pe = getprotobyname("tcp");
    if(!pe)
        log_fatal("getprotobyname('tcp') failed");
    tcp_proto = pe->p_proto;

    pe = getprotobyname("udp");
    if(!pe)
        log_fatal("getprotobyname('udp') failed");
    udp_proto = pe->p_proto;

    const int sock = socket(PF_INET6, SOCK_STREAM, tcp_proto);
    if(sock) {
        close(sock);
        tcp_v6_ok = true;
    }
}

int gdnsd_getproto_udp(void) { return udp_proto; }
int gdnsd_getproto_tcp(void) { return tcp_proto; }
bool gdnsd_tcp_v6_ok(void) { return tcp_v6_ok; }
