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

#include <gdnsd/dmn.h>
#include <gdnsd/vscf.h>

#include <stdbool.h>
#include <pthread.h>

typedef struct {
    dmn_anysin_t addr;
    bool autoscan;
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
    bool bind_success;
} dns_thread_t;

typedef struct {
    dns_addr_t*    dns_addrs;
    dns_thread_t*  dns_threads;
    dmn_anysin_t*  http_addrs;
    unsigned num_dns_addrs;
    unsigned num_dns_threads;
    unsigned num_http_addrs;
    unsigned http_timeout;
    unsigned max_http_clients;
} socks_cfg_t;

// this is to be eliminated eventually, I think
extern socks_cfg_t* scfg;

socks_cfg_t* socks_conf_load(const vscf_data_t* cfg_root);

F_NONNULL
void socks_dns_lsocks_init(socks_cfg_t* socks_cfg);

F_NONNULL
bool socks_helper_bind(const char* desc, const int sock, const dmn_anysin_t* asin, bool no_freebind);

// helper uses this (when told) to bind all sockets (calls above, indirectly in the statio case)
void socks_helper_bind_all(void);

F_NONNULL
bool socks_sock_is_bound_to(const int sock, const dmn_anysin_t* addr);

// daemon uses this to validate work done above
// if soft: false retval means all succeeded, true retval means one or more failed
// if !soft: will log_fatal() if any fail
F_NONNULL
bool socks_daemon_check_all(socks_cfg_t* socks_cfg, bool soft);

#endif // GDNSD_SOCKS_H
