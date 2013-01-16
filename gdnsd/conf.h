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

#ifndef GDNSD_CONF_H
#define GDNSD_CONF_H

#include "config.h"
#include "ltree.h"

typedef struct {
    anysin_t addr;
    int      udp_sock;
    int      tcp_sock;
    bool     tcp_disabled;
    bool     udp_need_late_bind;
    bool     tcp_need_late_bind;
    unsigned late_bind_secs;
    unsigned tcp_timeout;
    unsigned tcp_clients_per_socket;
    unsigned tcp_threadnum;
    unsigned udp_threadnum;
    unsigned udp_recv_width;
    unsigned udp_sndbuf;
    unsigned udp_rcvbuf;
} dns_addr_t;

typedef struct {
    dns_addr_t* dns_addrs;
    anysin_t*   http_addrs;
    const char* username;
    const uint8_t* chaos;
    bool     include_optional_ns;
    bool     realtime_stats;
    bool     lock_mem;
    bool     disable_text_autosplit;
    bool     edns_client_subnet;
    bool     monitor_force_v6_up;
    bool     zones_rfc1035_strict_startup;
    bool     zones_rfc1035_auto;
    int      priority;
    unsigned chaos_len;
    unsigned zones_default_ttl;
    unsigned log_stats;
    unsigned max_http_clients;
    unsigned http_timeout;
    unsigned num_dns_addrs;
    unsigned num_http_addrs;
    unsigned num_io_threads;
    unsigned max_response;
    unsigned max_cname_depth;
    unsigned max_addtl_rrsets;
    unsigned zones_rfc1035_auto_interval;
    double zones_rfc1035_min_quiesce;
    double zones_rfc1035_quiesce;
} global_config_t;

extern global_config_t gconfig;

F_NONNULL
void conf_load(void);

// retval indicates we need runtime CAP_NET_BIND_DEVICE
bool dns_lsock_init(void);

// utility function, must be AF_INET or AF_INET6 already,
//  used by dnsio_udp
F_NONNULL F_PURE
bool is_any_addr(const anysin_t* asin);

#endif // GDNSD_CONF_H
