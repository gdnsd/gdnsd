/* Copyright © 2014 Brandon L Black <blblack@gmail.com>
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

#include <gdnsd/net.h>
#include <gdnsd/vscf.h>

#include <stdbool.h>
#include <pthread.h>

typedef struct {
    gdnsd_anysin_t addr;
    unsigned dns_port;
    unsigned udp_sndbuf;
    unsigned udp_rcvbuf;
    unsigned udp_threads;
    unsigned tcp_timeout;
    unsigned tcp_fastopen;
    unsigned tcp_clients_per_thread;
    unsigned tcp_backlog;
    unsigned tcp_threads;
    bool     tcp_proxy;
    bool     tcp_pad;
} dns_addr_t;

typedef struct {
    dns_addr_t* ac;
    pthread_t threadid;
    unsigned threadnum;
    int sock;
    bool is_udp;
} dns_thread_t;

typedef struct {
    dns_addr_t* dns_addrs;
    dns_thread_t* dns_threads;
    unsigned num_dns_addrs;
    unsigned num_dns_threads;
} socks_cfg_t;

F_RETNN
socks_cfg_t* socks_conf_load(const vscf_data_t* cfg_root);

F_NONNULL
void socks_dns_lsocks_init(socks_cfg_t* socks_cfg);

F_NONNULL
void socks_bind_sock(const char* desc, const int sock, const gdnsd_anysin_t* sa);

#endif // GDNSD_SOCKS_H
