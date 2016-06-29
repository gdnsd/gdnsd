/* Copyright © 2016 Brandon L Black <blblack@gmail.com>
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

#ifndef GDNSD_SOCKS_H
#define GDNSD_SOCKS_H

#include <gdnsd/dmn.h>
#include <gdnsd/vscf.h>

#include <stdbool.h>
#include <pthread.h>

typedef struct {
    dmn_anysin_t addr;
    unsigned dns_port;
    unsigned udp_recv_width;
    unsigned udp_sndbuf;
    unsigned udp_rcvbuf;
    unsigned udp_threads;
    unsigned tcp_timeout;
    unsigned tcp_clients_per_thread;
    unsigned tcp_threads;
} dns_addr_t;

typedef struct {
    dns_addr_t* ac;
    pthread_t threadid;
    unsigned threadnum;
    int sock;
    bool is_udp;
} dns_thread_t;

typedef struct {
    dns_addr_t*   dns_addrs;
    dns_thread_t* dns_threads;
    unsigned num_dns_addrs;
    unsigned num_dns_threads;
    unsigned max_response;
    unsigned max_edns_response;
} socks_cfg_t;

// this loads the configuration in socks_cfg_t, but does not
//   actually operate on the underlying socket fds
socks_cfg_t* socks_conf_load(const vscf_data_t* cfg_root);

// initializes the actual socket fds and does various setsockopt()
//   sorts of things on them, but does not bind() them.
F_NONNULL
void socks_lsocks_init(socks_cfg_t* socks_cfg);

// bind() the sockets.
void socks_lsocks_bind(const socks_cfg_t* socks_cfg);

#endif // GDNSD_SOCKS_H
