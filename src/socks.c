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
#include <ifaddrs.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

// The "default defaults" for various address-level things
static const dns_addr_t addr_defs_defaults = {
    .dns_port = 53U,
    .udp_rcvbuf = 0U,
    .udp_sndbuf = 0U,
    .udp_threads = 2U,
    .tcp_timeout = 37U,
    .tcp_fastopen = 256U,
    .tcp_clients_per_thread = 256U,
    .tcp_backlog = 0U,
    .tcp_threads = 2U,
    .tcp_proxy = false,
    .tcp_pad = false,
};

static const socks_cfg_t socks_cfg_defaults = {
    .dns_addrs = NULL,
    .dns_threads = NULL,
    .num_dns_addrs = 0U,
    .num_dns_threads = 0U,
};

// Generic iterator for catching bad config hash keys in various places below
F_NONNULL
static bool bad_key(const char* key, unsigned klen V_UNUSED, vscf_data_t* d V_UNUSED, const void* which_asvoid)
{
    const char* which = which_asvoid;
    log_fatal("Invalid %s key '%s'", which, key);
}

static void make_addr(const char* lspec_txt, const unsigned def_port, gdnsd_anysin_t* result)
{
    gdnsd_assert(result);
    const int addr_err = gdnsd_anysin_fromstr(lspec_txt, def_port, result);
    if (addr_err)
        log_fatal("Could not process listen-address spec '%s': %s", lspec_txt, gai_strerror(addr_err));
}

#define CFG_OPT_UINT_ALTSTORE(_opt_set, _gconf_loc, _min, _max, _store) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if (_opt_setting) { \
            unsigned long _val; \
            if (!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_ulong(_opt_setting, &_val)) \
                log_fatal("Config option %s: Value must be a positive integer", #_gconf_loc); \
            if (_val < _min || _val > _max) \
                log_fatal("Config option %s: Value out of range (%lu, %lu)", #_gconf_loc, _min, _max); \
            _store = (unsigned) _val; \
        } \
    } while (0)

#define CFG_OPT_UINT_ALTSTORE_NOMIN(_opt_set, _gconf_loc, _max, _store) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if (_opt_setting) { \
            unsigned long _val; \
            if (!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_ulong(_opt_setting, &_val)) \
                log_fatal("Config option %s: Value must be a positive integer", #_gconf_loc); \
            if (_val > _max) \
                log_fatal("Config option %s: Value out of range (0, %lu)", #_gconf_loc, _max); \
            _store = (unsigned) _val; \
        } \
    } while (0)

#define CFG_OPT_BOOL_ALTSTORE(_opt_set, _gconf_loc, _store) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if (_opt_setting) { \
        bool _val; \
            if (!vscf_is_simple(_opt_setting) \
            || !vscf_simple_get_as_bool(_opt_setting, &_val)) \
                log_fatal("Config option %s: Value must be 'true' or 'false'", #_gconf_loc); \
        _store = _val; \
        } \
    } while (0)

#define CFG_OPT_REMOVED(_opt_set, _gconf_loc) \
    do { \
        vscf_data_t* _opt_setting = vscf_hash_get_data_byconstkey(_opt_set, #_gconf_loc, true); \
        if (_opt_setting) \
            log_warn("Config option %s is no longer supported, and will become a syntax error in a future major version upgrade", #_gconf_loc); \
    } while (0)

F_NONNULL
static void dns_listen_any(socks_cfg_t* socks_cfg, const dns_addr_t* addr_defs)
{
    socks_cfg->num_dns_addrs = 2;
    socks_cfg->dns_addrs = xcalloc_n(socks_cfg->num_dns_addrs, sizeof(*socks_cfg->dns_addrs));
    dns_addr_t* ac_v4 = &socks_cfg->dns_addrs[0];
    memcpy(ac_v4, addr_defs, sizeof(*ac_v4));
    make_addr("0.0.0.0", addr_defs->dns_port, &ac_v4->addr);
    dns_addr_t* ac_v6 = &socks_cfg->dns_addrs[1];
    memcpy(ac_v6, addr_defs, sizeof(*ac_v6));
    make_addr("::", addr_defs->dns_port, &ac_v6->addr);
}

F_NONNULLX(1, 3)
static void fill_dns_addrs(socks_cfg_t* socks_cfg, vscf_data_t* listen_opt, const dns_addr_t* addr_defs)
{
    if (!listen_opt) {
        dns_listen_any(socks_cfg, addr_defs);
        return;
    }

    if (vscf_is_simple(listen_opt)) {
        const char* simple_str = vscf_simple_get_data(listen_opt);
        if (!strcmp(simple_str, "any")) {
            dns_listen_any(socks_cfg, addr_defs);
            return;
        }
    }

    if (vscf_is_hash(listen_opt)) {
        socks_cfg->num_dns_addrs = vscf_hash_get_len(listen_opt);
        socks_cfg->dns_addrs = xcalloc_n(socks_cfg->num_dns_addrs, sizeof(*socks_cfg->dns_addrs));
        for (unsigned i = 0; i < socks_cfg->num_dns_addrs; i++) {
            dns_addr_t* addrconf = &socks_cfg->dns_addrs[i];
            memcpy(addrconf, addr_defs, sizeof(*addrconf));
            const char* lspec = vscf_hash_get_key_byindex(listen_opt, i, NULL);
            vscf_data_t* addr_opts = vscf_hash_get_data_byindex(listen_opt, i);
            if (!vscf_is_hash(addr_opts))
                log_fatal("DNS listen address '%s': per-address options must be a hash", lspec);

            CFG_OPT_REMOVED(addr_opts, udp_recv_width);
            CFG_OPT_BOOL_ALTSTORE(addr_opts, tcp_proxy, addrconf->tcp_proxy);
            CFG_OPT_UINT_ALTSTORE(addr_opts, tcp_timeout, 5LU, 1800LU, addrconf->tcp_timeout);
            CFG_OPT_UINT_ALTSTORE_NOMIN(addr_opts, tcp_fastopen, 1048576LU, addrconf->tcp_fastopen);
            CFG_OPT_UINT_ALTSTORE(addr_opts, tcp_clients_per_thread, 16LU, 65535LU, addrconf->tcp_clients_per_thread);
            CFG_OPT_UINT_ALTSTORE_NOMIN(addr_opts, tcp_backlog, 65535LU, addrconf->tcp_backlog);
            CFG_OPT_UINT_ALTSTORE(addr_opts, tcp_threads, 1LU, 1024LU, addrconf->tcp_threads);
            if (addrconf->tcp_proxy) {
                addrconf->udp_threads = 0U;
                addrconf->tcp_pad = true;
            } else {
                CFG_OPT_UINT_ALTSTORE(addr_opts, udp_rcvbuf, 4096LU, 1048576LU, addrconf->udp_rcvbuf);
                CFG_OPT_UINT_ALTSTORE(addr_opts, udp_sndbuf, 4096LU, 1048576LU, addrconf->udp_sndbuf);
                CFG_OPT_UINT_ALTSTORE(addr_opts, udp_threads, 1LU, 1024LU, addrconf->udp_threads);
            }
            CFG_OPT_BOOL_ALTSTORE(addr_opts, tcp_pad, addrconf->tcp_pad);

            make_addr(lspec, addrconf->dns_port, &addrconf->addr);
            if (addrconf->tcp_proxy) {
                unsigned lport;
                if (addrconf->addr.sa.sa_family == AF_INET) {
                    lport = addrconf->addr.sin4.sin_port;
                } else {
                    gdnsd_assert(addrconf->addr.sa.sa_family == AF_INET6);
                    lport = addrconf->addr.sin6.sin6_port;
                }
                if (lport == 53U)
                    log_fatal("Cannot configure tcp_proxy mode on port 53");
            }
            vscf_hash_iterate_const(addr_opts, true, bad_key, addrconf->tcp_proxy
                                    ? "per-address listen option with tcp_proxy"
                                    : "per-address listen option");
        }
    } else {
        socks_cfg->num_dns_addrs = vscf_array_get_len(listen_opt);
        socks_cfg->dns_addrs = xcalloc_n(socks_cfg->num_dns_addrs, sizeof(*socks_cfg->dns_addrs));
        for (unsigned i = 0; i < socks_cfg->num_dns_addrs; i++) {
            dns_addr_t* addrconf = &socks_cfg->dns_addrs[i];
            memcpy(addrconf, addr_defs, sizeof(*addrconf));
            vscf_data_t* lspec = vscf_array_get_data(listen_opt, i);
            if (!vscf_is_simple(lspec))
                log_fatal("Config option 'listen': all listen specs must be strings");
            make_addr(vscf_simple_get_data(lspec), addr_defs->dns_port, &addrconf->addr);
        }
    }
}

F_NONNULLX(1, 3)
static void process_listen(socks_cfg_t* socks_cfg, vscf_data_t* listen_opt, const dns_addr_t* addr_defs)
{
    // this fills in socks_cfg->dns_addrs raw data
    fill_dns_addrs(socks_cfg, listen_opt, addr_defs);

    if (!socks_cfg->num_dns_addrs)
        log_fatal("DNS listen addresses explicitly configured as an empty set - cannot continue without at least one address!");

    // use dns_addrs to populate dns_threads....

    socks_cfg->num_dns_threads = 0;
    for (unsigned i = 0; i < socks_cfg->num_dns_addrs; i++)
        socks_cfg->num_dns_threads += (socks_cfg->dns_addrs[i].udp_threads + socks_cfg->dns_addrs[i].tcp_threads);

    // Because we require thread counts to be non-zero
    gdnsd_assert(socks_cfg->num_dns_threads);

    socks_cfg->dns_threads = xcalloc_n(socks_cfg->num_dns_threads, sizeof(*socks_cfg->dns_threads));

    unsigned tnum = 0;
    for (unsigned i = 0; i < socks_cfg->num_dns_addrs; i++) {
        dns_addr_t* a = &socks_cfg->dns_addrs[i];

        for (unsigned j = 0; j < a->udp_threads; j++) {
            dns_thread_t* t = &socks_cfg->dns_threads[tnum];
            t->ac = a;
            t->is_udp = true;
            t->threadnum = tnum++;
            t->sock = -1;
        }

        for (unsigned j = 0; j < a->tcp_threads; j++) {
            dns_thread_t* t = &socks_cfg->dns_threads[tnum];
            t->ac = a;
            t->is_udp = false;
            t->threadnum = tnum++;
            t->sock = -1;
        }

        if (a->tcp_proxy) {
            gdnsd_assert(!a->udp_threads);
            log_info("DNS listener threads (%u TCP PROXY) configured for %s",
                     a->tcp_threads, logf_anysin(&a->addr));
        } else {
            log_info("DNS listener threads (%u UDP + %u TCP) configured for %s",
                     a->udp_threads, a->tcp_threads, logf_anysin(&a->addr));
        }
    }

    gdnsd_assert(tnum == socks_cfg->num_dns_threads);
}

socks_cfg_t* socks_conf_load(const vscf_data_t* cfg_root)
{
    gdnsd_assert(!cfg_root || vscf_is_hash(cfg_root));

    socks_cfg_t* socks_cfg = xmalloc(sizeof(*socks_cfg));
    memcpy(socks_cfg, &socks_cfg_defaults, sizeof(*socks_cfg));

    vscf_data_t* listen_opt = NULL;

    dns_addr_t addr_defs;
    memcpy(&addr_defs, &addr_defs_defaults, sizeof(addr_defs));

    vscf_data_t* options = cfg_root ? vscf_hash_get_data_byconstkey(cfg_root, "options", true) : NULL;
    if (options) {
        CFG_OPT_REMOVED(options, udp_recv_width);
        CFG_OPT_UINT_ALTSTORE(options, dns_port, 1LU, 65535LU, addr_defs.dns_port);
        CFG_OPT_UINT_ALTSTORE(options, udp_rcvbuf, 4096LU, 1048576LU, addr_defs.udp_rcvbuf);
        CFG_OPT_UINT_ALTSTORE(options, udp_sndbuf, 4096LU, 1048576LU, addr_defs.udp_sndbuf);
        CFG_OPT_UINT_ALTSTORE(options, udp_threads, 1LU, 1024LU, addr_defs.udp_threads);
        CFG_OPT_UINT_ALTSTORE(options, tcp_timeout, 5LU, 1800LU, addr_defs.tcp_timeout);
        CFG_OPT_UINT_ALTSTORE_NOMIN(options, tcp_fastopen, 1048576LU, addr_defs.tcp_fastopen);
        CFG_OPT_UINT_ALTSTORE(options, tcp_clients_per_thread, 16LU, 65535LU, addr_defs.tcp_clients_per_thread);
        CFG_OPT_UINT_ALTSTORE_NOMIN(options, tcp_backlog, 65535LU, addr_defs.tcp_backlog);
        CFG_OPT_UINT_ALTSTORE(options, tcp_threads, 1LU, 1024LU, addr_defs.tcp_threads);

        listen_opt = vscf_hash_get_data_byconstkey(options, "listen", true);
    }

    process_listen(socks_cfg, listen_opt, &addr_defs);

    return socks_cfg;
}

void socks_bind_sock(const char* desc, const int sock, const gdnsd_anysin_t* sa)
{
    int bind_errno = 0;

    // Immediate, simple success
    if (!bind(sock, &sa->sa, sa->len))
        return;
    bind_errno = errno;

#if defined IP_FREEBIND || (defined IP_BINDANY && defined IPV6_BINDANY) || defined SO_BINDANY
    // first bind() attempt failed.  in the case of non-ANY addresses, where
    // the OS has support for freebind/bindany, try it before failing hard
    if (errno == EADDRNOTAVAIL && !gdnsd_anysin_is_anyaddr(sa)) {
        const int opt_one = 1;

# if defined IP_FREEBIND
        // Linux
        const int bindlev = IPPROTO_IP;
        const int bindopt = IP_FREEBIND;
        const char* bindtxt = "IP_FREEBIND";
# elif defined IP_BINDANY && defined IPV6_BINDANY
        // FreeBSD, untested
        const bool isv6 = sa->sa.sa_family == AF_INET6 ? true : false;
        const int bindlev = isv6 ? IPPROTO_IPV6 : IPPROTO_IP;
        const int bindopt = isv6 ? IPV6_BINDANY : IP_BINDANY;
        const char* bindtxt = isv6 ? "IPV6_BINDANY" : "IP_BINDANY";
# elif defined SO_BINDANY
        // OpenBSD equiv?
        const int bindlev = SOL_SOCKET;
        const int bindopt = SO_BINDANY;
        const char* bindtxt = "SO_BINDANY";
# endif

        if (setsockopt(sock, bindlev, bindopt, &opt_one, sizeof(opt_one)) == -1) {
            // Don't even re-attempt the bind if we can't set the option, just
            // warn about the setsockopt() and fail out at the bottom with the
            // original errno from bind():
            log_warn("Failed to set %s on %s socket %s: %s", bindtxt, desc, logf_anysin(sa), logf_errno());
        } else {
            if (!bind(sock, &sa->sa, sa->len)) {
                // Success, after setting IP_FREEBIND or similar
                log_warn("%s socket %s bound via %s, address may not (yet!) exist on the host", desc, logf_anysin(sa), bindtxt);
                return;
            }
            // Second attempt failed, update bind_errno and fail out below
            bind_errno = errno;
        }
    }
#endif

    // If initial bind attempt failed, and the above freebind stuff either
    // failed or isn't available, fail hard:
    log_fatal("bind() failed for %s socket %s: %s", desc, logf_anysin(sa), logf_strerror(bind_errno));
}

void socks_dns_lsocks_init(socks_cfg_t* socks_cfg)
{
    for (unsigned i = 0; i < socks_cfg->num_dns_threads; i++) {
        dns_thread_t* t = &socks_cfg->dns_threads[i];
        if (t->is_udp)
            udp_sock_setup(t);
        else
            tcp_dns_listen_setup(t);
    }
}
