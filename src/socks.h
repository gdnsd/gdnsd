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

#include "cdl.h"

#include <gdnsd/net.h>
#include <gdnsd/vscf.h>

#include <stdbool.h>
#include <pthread.h>

struct dns_addr {
    CDL_ENTRY(struct dns_addr) dns_addrs_entry;
    struct anysin addr;
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
};

struct dns_thread {
    CDL_ENTRY(struct dns_thread) dns_threads_entry;
    struct dns_addr* ac;
    pthread_t threadid;
    int sock;
};

struct ctl_addr {
    CDL_ENTRY(struct ctl_addr) ctl_addrs_entry;
    struct anysin addr;
    bool chal_ok; // add/flush challenge data
    bool ctl_ok;  // reload-zones, replace, stop
};

struct socks_cfg {
    CDL_ROOT(struct dns_addr) dns_addrs;
    CDL_ROOT(struct dns_thread) dns_tcp_threads;
    CDL_ROOT(struct dns_thread) dns_udp_threads;
    CDL_ROOT(struct ctl_addr) ctl_addrs;
    unsigned long fd_estimate;
};

F_RETNN
struct socks_cfg* socks_conf_load(const vscf_data_t* cfg_root);

F_NONNULL
void socks_dns_lsocks_init(const struct socks_cfg* socks_cfg);

F_NONNULL
void socks_bind_sock(const char* desc, const int sock, const struct anysin* sa);

#endif // GDNSD_SOCKS_H
