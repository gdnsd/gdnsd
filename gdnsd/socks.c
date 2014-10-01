#include "socks.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "conf.h"
#include <gdnsd/log.h>
#include "statio.h"

bool socks_helper_bind(const char* desc, const int sock, const dmn_anysin_t* asin, bool no_freebind V_UNUSED) {
    dmn_assert(desc); dmn_assert(asin);

    if(!bind(sock, &asin->sa, asin->len))
        return false;

    // first bind() attempt failed...
    if(errno == EADDRNOTAVAIL) {
        // in the case of non-ANY addresses not from scanning, where the OS has
        //   support for freebind/bindany, try to use that (and warn) before
        //   falling through to various failure modes
#if defined IP_FREEBIND || (defined IP_BINDANY && defined IPV6_BINDANY) || defined SO_BINDANY
        if(!no_freebind && !dmn_anysin_is_anyaddr(asin)) {
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
                log_warn("Failed to set %s on %s socket %s: %s", bindtxt, desc, dmn_logf_anysin(asin), dmn_logf_errno());
            }
            else {
                if(!bind(sock, &asin->sa, asin->len)) {
                    log_warn("%s socket %s bound via %s, address may not (yet!) exist on the host", desc, dmn_logf_anysin(asin), bindtxt);
                    return false;
                }
            }
        }
#endif
    }

    return true;
}

// helper process: bind all sockets (udp/tcp dns + statio)
void socks_helper_bind_all(void) {
    for(unsigned i = 0; i < gconfig.num_dns_threads; i++) {
        dns_thread_t* t = &gconfig.dns_threads[i];
        if(!t->bind_success)
            if(!socks_helper_bind(t->is_udp ? "UDP DNS" : "TCP DNS", t->sock, &t->ac->addr, t->ac->autoscan))
                t->bind_success = true;
    }
    statio_bind_socks();
}

bool socks_sock_is_bound_to(int sock, dmn_anysin_t* addr) {
    bool rv = false;

    dmn_anysin_t bound_to = { .len = DMN_ANYSIN_MAXLEN };
    if(getsockname(sock, &bound_to.sa, &bound_to.len))
        log_fatal("getsockname() failed: %s", dmn_logf_errno());
    if(addr->sa.sa_family == bound_to.sa.sa_family) {
        if(addr->sa.sa_family == AF_INET) {
            if(addr->sin.sin_addr.s_addr == bound_to.sin.sin_addr.s_addr
                && addr->sin.sin_port == bound_to.sin.sin_port)
                    rv = true;
        }
        else {
            dmn_assert(addr->sa.sa_family == AF_INET6);
            if(!memcmp(&addr->sin6.sin6_addr.s6_addr, &bound_to.sin6.sin6_addr.s6_addr, 16)
                && addr->sin6.sin6_port == bound_to.sin6.sin6_port)
                    rv = true;
        }
    }

    return rv;
}

bool socks_daemon_check_all(bool soft) {
    bool rv = false;
    for(unsigned i = 0; i < gconfig.num_dns_threads; i++) {
        dns_thread_t* t = &gconfig.dns_threads[i];
        const char* ptxt = t->is_udp ? "UDP" : "TCP";
        if(!t->bind_success) {
            if(!socks_sock_is_bound_to(t->sock, &t->ac->addr)) {
                if(!t->ac->autoscan && !soft)
                    log_fatal("Failed to bind() %s DNS socket to %s", ptxt, dmn_logf_anysin(&t->ac->addr));
                rv = true;
            }
            else {
                t->bind_success = true;
            }
        }
    }
    rv |= statio_check_socks(soft);
    return rv;
}
