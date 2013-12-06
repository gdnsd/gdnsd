#include "dnsio.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "conf.h"
#include "gdnsd/log.h"

bool dnsio_bind(dns_thread_t* t) {
    dmn_assert(t); dmn_assert(t->ac);
    dmn_assert(t->sock > -1);

    const anysin_t* asin = &t->ac->addr;

    if(!bind(t->sock, &asin->sa, asin->len))
        return false;

    // first bind() attempt failed...

    const char* ptxt = t->is_udp ? "UDP" : "TCP";
    const bool isv6 = asin->sa.sa_family == AF_INET6 ? true : false;
    int bind_err = errno;

    if(bind_err == EADDRNOTAVAIL) {
        // in the case of non-ANY addresses not from scanning, where the OS has
        //   support for nonlocal bind, try to use that (and warn) before
        //   falling through to late bind or various failure modes

#if defined IP_FREEBIND || (defined IP_BINDANY && defined IPV6_BINDANY) || defined SO_BINDANY
        if(!t->ac->autoscan && !gdnsd_anysin_is_anyaddr(asin)) {
# if defined IP_FREEBIND
            // Linux
            const int bindlev = IPPROTO_IP;
            const int bindopt = IP_FREEBIND;
            const char* bindtxt = "IP_FREEBIND";
# elif defined IP_BINDANY && defined IPV6_BINDANY
            // FreeBSD, untested
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
            if(setsockopt(t->sock, bindlev, bindopt, &opt_one, sizeof opt_one) == -1) {
                log_warn("Failed to set %s on %s socket %s: %s", bindtxt, ptxt, logf_anysin(asin), logf_errno());
            }
            else {
                if(!bind(t->sock, &asin->sa, asin->len)) {
                    log_warn("%s socket %s bound via %s, address may not (yet!) exist on the host", ptxt, logf_anysin(asin), bindtxt);
                    return false;
                }
                bind_err = errno;
            }
        }
#endif

        // Handle bind() error from either attempt, if no success so far
        if(t->ac->autoscan) {
            log_warn("Could not bind %s socket %s (%s), configured by automatic interface scanning.  Will ignore this listen address.", ptxt, logf_anysin(asin), logf_errnum(bind_err));
            t->autoscan_bind_failed = true;
            return false;
        }
        else if(t->ac->late_bind_secs) {
            t->need_late_bind = true;
            log_info("%s DNS socket %s not yet available, will attempt late bind every %u seconds", ptxt, logf_anysin(asin), t->ac->late_bind_secs);
            return ntohs(isv6 ? asin->sin6.sin6_port : asin->sin.sin_port) < 1024 ? true : false;
        }
    }

    log_fatal("Failed to bind() %s socket to %s: %s", ptxt, logf_anysin(asin), logf_errnum(bind_err));
}
