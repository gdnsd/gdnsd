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

#include <config.h>
#include "socks.h"

#include "dnsio_udp.h"
#include "dnsio_tcp.h"

#include <gdnsd/alloc.h>
#include <gdnsd/misc.h>
#include <gdnsd/log.h>

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

// The "default defaults" for various address-level things
static const dns_addr_t addr_defs_defaults = {
    .dns_port = 53U,
    .udp_recv_width = 8U,
    .udp_rcvbuf = 0U,
    .udp_sndbuf = 0U,
    .udp_threads = 1U,
    .tcp_clients_per_thread = 128U,
    .tcp_timeout = 5U,
    .tcp_threads = 1U,
};

static const socks_cfg_t socks_cfg_defaults = {
    .dns_addrs = NULL,
    .dns_threads = NULL,
    .num_dns_addrs = 0U,
    .num_dns_threads = 0U,
    .max_response = 16384U,
    .max_edns_response = 1410U,
};

// Generic iterator for catching bad config hash keys in various places below
F_NONNULL
static bool bad_key(const char* key, unsigned klen V_UNUSED, vscf_data_t* d V_UNUSED, const void* which_asvoid) {
    dmn_assert(key); dmn_assert(d); dmn_assert(which_asvoid);
    const char* which = which_asvoid;
    log_fatal("Invalid %s key '%s'", which, key);
}

static void make_addr(const char* lspec_txt, const unsigned def_port, dmn_anysin_t* result) {
    dmn_assert(result);
    const int addr_err = gdnsd_anysin_fromstr(lspec_txt, def_port, result);
    if(addr_err)
        log_fatal("Could not process listen-address spec '%s': %s", lspec_txt, gai_strerror(addr_err));
}

#define CFG_OPT_UINT_ALTSTORE(_opt_set, _gconf_loc, _min, _max, _store) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if(_opt_setting) { \
            unsigned long _val; \
            if(!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_ulong(_opt_setting, &_val)) \
                log_fatal("Config option %s: Value must be a positive integer", #_gconf_loc); \
            if(_val < _min || _val > _max) \
                log_fatal("Config option %s: Value out of range (%lu, %lu)", #_gconf_loc, _min, _max); \
            _store = (unsigned) _val; \
        } \
    } while(0)

#define CFG_OPT_UINT_ALTSTORE_NOMIN(_opt_set, _gconf_loc, _max, _store) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if(_opt_setting) { \
            unsigned long _val; \
            if(!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_ulong(_opt_setting, &_val)) \
                log_fatal("Config option %s: Value must be a positive integer", #_gconf_loc); \
            if(_val > _max) \
                log_fatal("Config option %s: Value out of range (0, %lu)", #_gconf_loc, _max); \
            _store = (unsigned) _val; \
        } \
    } while(0)

F_NONNULL
static void dns_listen_any(socks_cfg_t* socks_cfg, const dns_addr_t* addr_defs) {
    dmn_assert(socks_cfg); dmn_assert(addr_defs);

    socks_cfg->num_dns_addrs = 2;
    socks_cfg->dns_addrs = xcalloc(socks_cfg->num_dns_addrs, sizeof(dns_addr_t));
    dns_addr_t* ac_v4 = &socks_cfg->dns_addrs[0];
    memcpy(ac_v4, addr_defs, sizeof(dns_addr_t));
    make_addr("0.0.0.0", addr_defs->dns_port, &ac_v4->addr);
    dns_addr_t* ac_v6 = &socks_cfg->dns_addrs[1];
    memcpy(ac_v6, addr_defs, sizeof(dns_addr_t));
    make_addr("::", addr_defs->dns_port, &ac_v6->addr);
}

F_NONNULLX(1,3)
static void fill_dns_addrs(socks_cfg_t* socks_cfg, vscf_data_t* listen_opt, const dns_addr_t* addr_defs) {
    dmn_assert(socks_cfg); dmn_assert(addr_defs);

    if(!listen_opt)
        return dns_listen_any(socks_cfg, addr_defs);
    if(vscf_is_simple(listen_opt)) {
        const char* simple_str = vscf_simple_get_data(listen_opt);
        if(!strcmp(simple_str, "any")) {
            return dns_listen_any(socks_cfg, addr_defs);
        }
    }

    if(vscf_is_hash(listen_opt)) {
        socks_cfg->num_dns_addrs = vscf_hash_get_len(listen_opt);
        socks_cfg->dns_addrs = xcalloc(socks_cfg->num_dns_addrs, sizeof(dns_addr_t));
        for(unsigned i = 0; i < socks_cfg->num_dns_addrs; i++) {
            dns_addr_t* addrconf = &socks_cfg->dns_addrs[i];
            memcpy(addrconf, addr_defs, sizeof(dns_addr_t));
            const char* lspec = vscf_hash_get_key_byindex(listen_opt, i, NULL);
            vscf_data_t* addr_opts = vscf_hash_get_data_byindex(listen_opt, i);
            if(!vscf_is_hash(addr_opts))
                log_fatal("DNS listen address '%s': per-address options must be a hash", lspec);

            CFG_OPT_UINT_ALTSTORE(addr_opts, udp_recv_width, 1LU, 64LU, addrconf->udp_recv_width);
            CFG_OPT_UINT_ALTSTORE(addr_opts, udp_rcvbuf, 4096LU, 1048576LU, addrconf->udp_rcvbuf);
            CFG_OPT_UINT_ALTSTORE(addr_opts, udp_sndbuf, 4096LU, 1048576LU, addrconf->udp_sndbuf);
            CFG_OPT_UINT_ALTSTORE_NOMIN(addr_opts, udp_threads, 1024LU, addrconf->udp_threads);

            CFG_OPT_UINT_ALTSTORE(addr_opts, tcp_clients_per_thread, 1LU, 65535LU, addrconf->tcp_clients_per_thread);
            CFG_OPT_UINT_ALTSTORE(addr_opts, tcp_timeout, 3LU, 60LU, addrconf->tcp_timeout);
            CFG_OPT_UINT_ALTSTORE_NOMIN(addr_opts, tcp_threads, 1024LU, addrconf->tcp_threads);

            if(!gdnsd_reuseport_ok()) {
                if(addrconf->udp_threads > 1) {
                    log_warn("DNS listen address '%s': option 'udp_threads' was reduced from the configured value of %u to 1 for lack of SO_REUSEPORT support", lspec, addrconf->udp_threads);
                    addrconf->udp_threads = 1;
                }
                if(addrconf->tcp_threads > 1) {
                    log_warn("DNS listen address '%s': option 'tcp_threads' was reduced from the configured value of %u to 1 for lack of SO_REUSEPORT support", lspec, addrconf->tcp_threads);
                    addrconf->tcp_threads = 1;
                }
            }

            make_addr(lspec, addrconf->dns_port, &addrconf->addr);
            vscf_hash_iterate_const(addr_opts, true, bad_key, "per-address listen option");
        }
    }
    else {
        socks_cfg->num_dns_addrs = vscf_array_get_len(listen_opt);
        socks_cfg->dns_addrs = xcalloc(socks_cfg->num_dns_addrs, sizeof(dns_addr_t));
        for(unsigned i = 0; i < socks_cfg->num_dns_addrs; i++) {
            dns_addr_t* addrconf = &socks_cfg->dns_addrs[i];
            memcpy(addrconf, addr_defs, sizeof(dns_addr_t));
            vscf_data_t* lspec = vscf_array_get_data(listen_opt, i);
            if(!vscf_is_simple(lspec))
                log_fatal("Config option 'listen': all listen specs must be strings");
            make_addr(vscf_simple_get_data(lspec), addr_defs->dns_port, &addrconf->addr);
        }
    }
}

F_NONNULLX(1,3)
static void process_listen(socks_cfg_t* socks_cfg, vscf_data_t* listen_opt, const dns_addr_t* addr_defs) {
    dmn_assert(socks_cfg); dmn_assert(addr_defs);

    // this fills in socks_cfg->dns_addrs raw data
    fill_dns_addrs(socks_cfg, listen_opt, addr_defs);

    if(!socks_cfg->num_dns_addrs)
        dmn_log_fatal("DNS listen addresses explicitly configured as an empty set - cannot continue without at least one address!");

    // use dns_addrs to populate dns_threads....

    socks_cfg->num_dns_threads = 0;
    for(unsigned i = 0; i < socks_cfg->num_dns_addrs; i++)
        socks_cfg->num_dns_threads += (socks_cfg->dns_addrs[i].udp_threads + socks_cfg->dns_addrs[i].tcp_threads);

    if(!socks_cfg->num_dns_threads)
        dmn_log_fatal("All listen addresses configured for zero UDP and zero TCP threads - cannot continue without at least one listener!");

    socks_cfg->dns_threads = xcalloc(socks_cfg->num_dns_threads, sizeof(dns_thread_t));

    unsigned tnum = 0;
    for(unsigned i = 0; i < socks_cfg->num_dns_addrs; i++) {
        dns_addr_t* a = &socks_cfg->dns_addrs[i];
        for(unsigned j = 0; j < a->udp_threads; j++) {
            dns_thread_t* t = &socks_cfg->dns_threads[tnum];
            t->ac = a;
            t->is_udp = true;
            t->threadnum = tnum++;
        }
        for(unsigned j = 0; j < a->tcp_threads; j++) {
            dns_thread_t* t = &socks_cfg->dns_threads[tnum];
            t->ac = a;
            t->is_udp = false;
            t->threadnum = tnum++;
        }
        if(!(a->udp_threads + a->tcp_threads))
            dmn_log_warn("DNS listen address %s explicitly configured with no UDP or TCP threads - nothing is actually listening on this address!",
                dmn_logf_anysin(&a->addr));
        else
            dmn_log_info("DNS listener threads (%u UDP + %u TCP) configured for %s",
                a->udp_threads, a->tcp_threads, dmn_logf_anysin(&a->addr));
    }

    dmn_assert(tnum == socks_cfg->num_dns_threads);
}

socks_cfg_t* socks_conf_load(const vscf_data_t* cfg_root) {
    dmn_assert(!cfg_root || vscf_is_hash(cfg_root));

    socks_cfg_t* socks_cfg = xmalloc(sizeof(*socks_cfg));
    memcpy(socks_cfg, &socks_cfg_defaults, sizeof(*socks_cfg));

    vscf_data_t* listen_opt = NULL;

    // These are initially populated with static defaults, then updated
    //   with global options to become the defaults for per-address-level
    //   settings within process_listen()
    dns_addr_t addr_defs;
    memcpy(&addr_defs, &addr_defs_defaults, sizeof(addr_defs));

    vscf_data_t* options = cfg_root ? vscf_hash_get_data_byconstkey(cfg_root, "options", true) : NULL;
    if(options) {
        CFG_OPT_UINT_ALTSTORE(options, dns_port, 1LU, 65535LU, addr_defs.dns_port);
        CFG_OPT_UINT_ALTSTORE(options, udp_recv_width, 1LU, 64LU, addr_defs.udp_recv_width);
        CFG_OPT_UINT_ALTSTORE(options, udp_rcvbuf, 4096LU, 1048576LU, addr_defs.udp_rcvbuf);
        CFG_OPT_UINT_ALTSTORE(options, udp_sndbuf, 4096LU, 1048576LU, addr_defs.udp_sndbuf);
        CFG_OPT_UINT_ALTSTORE_NOMIN(options, udp_threads, 1024LU, addr_defs.udp_threads);
        CFG_OPT_UINT_ALTSTORE(options, tcp_timeout, 3LU, 60LU, addr_defs.tcp_timeout);
        CFG_OPT_UINT_ALTSTORE(options, tcp_clients_per_thread, 1LU, 65535LU, addr_defs.tcp_clients_per_thread);
        CFG_OPT_UINT_ALTSTORE_NOMIN(options, tcp_threads, 1024LU, addr_defs.tcp_threads);

        CFG_OPT_UINT_ALTSTORE(options, max_response, 4096LU, 64000LU, socks_cfg->max_response);
        CFG_OPT_UINT_ALTSTORE(options, max_edns_response, 512LU, 64000LU, socks_cfg->max_edns_response);
        if(socks_cfg->max_edns_response > socks_cfg->max_response) {
            log_warn("The global option 'max_edns_response' was reduced from %u to the max_response size of %u", socks_cfg->max_edns_response, socks_cfg->max_response);
            socks_cfg->max_edns_response = socks_cfg->max_response;
        }

        if(!gdnsd_reuseport_ok()) {
            if(addr_defs.udp_threads > 1) {
                log_warn("The global option 'udp_threads' was reduced from the configured value of %u to 1 for lack of SO_REUSEPORT support", addr_defs.udp_threads);
                addr_defs.udp_threads = 1;
            }
            if(addr_defs.tcp_threads > 1) {
                log_warn("The global option 'tcp_threads' was reduced from the configured value of %u to 1 for lack of SO_REUSEPORT support", addr_defs.tcp_threads);
                addr_defs.tcp_threads = 1;
            }
        }

        listen_opt = vscf_hash_get_data_byconstkey(options, "listen", true);
    }

    process_listen(socks_cfg, listen_opt, &addr_defs);

    return socks_cfg;
}

void socks_lsocks_init(socks_cfg_t* socks_cfg) {
    dmn_assert(socks_cfg);
    for(unsigned i = 0; i < socks_cfg->num_dns_threads; i++) {
        dns_thread_t* t = &socks_cfg->dns_threads[i];
        if(t->is_udp)
            udp_sock_setup(t, socks_cfg->max_edns_response);
        else
            t->sock = tcp_listen_pre_setup(&t->ac->addr, t->ac->tcp_timeout);
    }
}

static void socks_helper_bind(const char* desc, const int sock, const dmn_anysin_t* asin) {
    dmn_assert(desc); dmn_assert(asin);

    if(!bind(sock, &asin->sa, asin->len))
        return;

    // save errno so it's not clobbered by a failed setsockopt() later
    int bind_errno = errno;

#if defined IP_FREEBIND || (defined IP_BINDANY && defined IPV6_BINDANY) || defined SO_BINDANY
    // first bind() attempt failed...  in the case of non-ANY addresses, where
    // the OS has support for freebind/bindany, try to use that (and warn)
    // before falling through to various failure modes if due to EADDRNOTAVAIL
    if(errno == EADDRNOTAVAIL && !dmn_anysin_is_anyaddr(asin)) {
# if defined IP_FREEBIND
        // Linux
        const int bindlev = IPPROTO_IP;
        const int bindopt = IP_FREEBIND;
        const char* bindtxt = "IP_FREEBIND";
# elif defined IP_BINDANY && defined IPV6_BINDANY
        // FreeBSD, untested
        const bool isv6 = asin->sa.sa_family == AF_INET6 ? true : false;
        const int bindlev = isv6 ? IPPROTO_IPV6 : IPPROTO_IP;
        const int bindopt = isv6 ? IPV6_BINDANY : IP_BINDANY;
        const char* bindtxt = isv6 ? "IPV6_BINDANY" : "IP_BINDANY";
# elif defined SO_BINDANY
        // OpenBSD equiv?
        const int bindlev = SOL_SOCKET;
        const int bindopt = SO_BINDANY;
        const char* bindtxt = "SO_BINDANY";
# endif
        const int opt_one = 1;
        if(setsockopt(sock, bindlev, bindopt, &opt_one, sizeof opt_one) == -1) {
            log_warn("Failed to set %s on %s socket %s: %s",
                bindtxt, desc, dmn_logf_anysin(asin), dmn_logf_errno());
        }
        else {
            if(!bind(sock, &asin->sa, asin->len)) {
                log_warn("%s socket %s bound via %s, address may not yet exist",
                    desc, dmn_logf_anysin(asin), bindtxt);
                return;
            }
            bind_errno = errno;
        }
    }
#endif // some freebind mechanism is avail

    log_fatal("Failed to bind %s socket %s: %s",
        desc, dmn_logf_anysin(asin), dmn_logf_strerror(bind_errno));
}

// bind all sockets (udp/tcp dns)
void socks_lsocks_bind(const socks_cfg_t* socks_cfg) {
    for(unsigned i = 0; i < socks_cfg->num_dns_threads; i++) {
        const dns_thread_t* t = &socks_cfg->dns_threads[i];
        socks_helper_bind(t->is_udp ? "UDP DNS" : "TCP DNS",
            t->sock, &t->ac->addr);
    }
}
