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

#include "dnsio_udp.h"

#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <sys/time.h>
#include <time.h>

#include "conf.h"
#include "dnswire.h"
#include "dnspacket.h"
#include "socks.h"
#include <gdnsd/log.h>
#include <gdnsd/misc.h>
#include <gdnsd/prcu-priv.h>

#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif

#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

// RCU perf magic value:
// This is the longest time for which we'll delay writers
//   in rcu_synchronize() (e.g. geoip/zonefile data reloaders
//   waiting to reclaim dead data) in the worst case.  The
//   current value is ~47ms and is unlikely to fall into strange
//   multiplicative patterns of coincidence.
#define PRCU_DELAY_US 47317

static bool has_mmsg(void);

static void udp_sock_opts_v4(const int sock V_UNUSED, const bool any_addr) {
    const int opt_one V_UNUSED = 1;
    // If all variants we know of don't exist, we simply assume the IP
    //  stack will *not* set the DF bit on UDP packets.  We may need
    //  more variants here for other operating systems.
#if defined IP_MTU_DISCOVER && defined IP_PMTUDISC_DONT
    const int mtu_type = IP_PMTUDISC_DONT;
    if(setsockopt(sock, SOL_IP, IP_MTU_DISCOVER, &mtu_type, sizeof (mtu_type)) == -1)
        log_fatal("Failed to disable Path MTU Discovery for UDP socket: %s", dmn_logf_errno());
#endif
#if defined IP_DONTFRAG
    const int opt_zero = 0;
    if(setsockopt(sock, SOL_IP, IP_DONTFRAG, &opt_zero, sizeof (opt_zero)) == -1)
        log_fatal("Failed to disable DF bit for UDP socket: %s", dmn_logf_errno());
#endif

    if(any_addr) {
#if HAVE_DECL_IP_PKTINFO
        if(setsockopt(sock, SOL_IP, IP_PKTINFO, &opt_one, sizeof opt_one) == -1)
            log_fatal("Failed to set IP_PKTINFO on UDP socket: %s", dmn_logf_errno());
#elif HAVE_DECL_IP_RECVDSTADDR && HAVE_DECL_IP_SENDSRCADDR
        // we don't use SENDSRCADDR directly, but it seems most smart implementors
        //  define it as an alias to RECVDSTADDR.  Importantly: MacOS, which does
        //  not implement the sending part of this magic, does not declare SENDSRCADDR
#  if IP_RECVDSTADDR != IP_SENDSRCADDR
#    error Your platform violates some gdnsd assumptions (IP_RECVDSTADDR != IP_SENDSRCADDR)
#  endif
        if(setsockopt(sock, SOL_IP, IP_RECVDSTADDR, &opt_one, sizeof opt_one) == -1)
            log_fatal("Failed to set IP_RECVDSTADDR on UDP socket: %s", dmn_logf_errno());
#else
        log_fatal("IPv4 any-address '0.0.0.0' not supported for DNS listening on your platform (no IP_PKTINFO or IP_RECVDSTADDR+IP_SENDSRCADDR)");
#endif
    }

    // This is just a latency hack, it's not necessary for correct operation
#if defined IP_TOS && defined IPTOS_LOWDELAY
    const int opt_tos = IPTOS_LOWDELAY;
    if(setsockopt(sock, SOL_IP, IP_TOS, &opt_tos, sizeof opt_tos) == -1)
        log_warn("Failed to set IPTOS_LOWDELAY on UDP socket: %s", dmn_logf_errno());
#endif

}

/* Here, we assume that if neither IPV6_USE_MIN_MTU or IPV6_MTU is
 *  available that the kernel will fragment for us by default.  This
 *  may or may not be a safe assumption on all OS's.
 * To test: set up an environment where one link in the client<->server
 *  path has a smaller MTU than the server interface MTU, and the
 *  server's interface MTU is >1280. Send an IPv6 query that results in
 *  a response greater than the path MTU, but smaller than the server's
 *  interface MTU.
 *  If the response does not reach the client, this platform is broken,
 *  and we need to find a platform-specific way to make it fragment to
 *  1280 or disable IPv6 completely for this platform.
 */

static void udp_sock_opts_v6(const int sock) {
    const int opt_one = 1;

#if defined IPV6_USE_MIN_MTU
    if(setsockopt(sock, SOL_IPV6, IPV6_USE_MIN_MTU, &opt_one, sizeof opt_one) == -1)
        log_fatal("Failed to set IPV6_USE_MIN_MTU on UDP socket: %s", dmn_logf_errno());
#elif defined IPV6_MTU
#    ifndef IPV6_MIN_MTU
#      define IPV6_MIN_MTU 1280
#    endif
    const int min_mtu = IPV6_MIN_MTU;
    if(setsockopt(sock, SOL_IPV6, IPV6_MTU, &min_mtu, sizeof min_mtu) == -1)
        log_fatal("Failed to set IPV6_MTU on UDP socket: %s", dmn_logf_errno());
#endif

    if(setsockopt(sock, SOL_IPV6, IPV6_V6ONLY, &opt_one, sizeof opt_one) == -1)
        log_fatal("Failed to set IPV6_V6ONLY on UDP socket: %s", dmn_logf_errno());

#if defined IPV6_MTU_DISCOVER && defined IPV6_PMTUDISC_DONT
    const int mtu_type = IPV6_PMTUDISC_DONT;
    if(setsockopt(sock, SOL_IPV6, IPV6_MTU_DISCOVER, &mtu_type, sizeof (mtu_type)) == -1)
        log_fatal("Failed to disable Path MTU Discovery for UDP socket: %s", dmn_logf_errno());
#endif
#if defined IPV6_DONTFRAG
    const int opt_zero = 0;
    if(setsockopt(sock, SOL_IPV6, IPV6_DONTFRAG, &opt_zero, sizeof (opt_zero)) == -1)
        log_fatal("Failed to disable DF bit for UDP socket: %s", dmn_logf_errno());
#endif

#if defined IPV6_RECVPKTINFO
    if(setsockopt(sock, SOL_IPV6, IPV6_RECVPKTINFO, &opt_one, sizeof opt_one) == -1)
        log_fatal("Failed to set IPV6_RECVPKTINFO on UDP socket: %s", dmn_logf_errno());
#elif defined IPV6_PKTINFO
    if(setsockopt(sock, SOL_IPV6, IPV6_PKTINFO, &opt_one, sizeof opt_one) == -1)
        log_fatal("Failed to set IPV6_PKTINFO on UDP socket: %s", dmn_logf_errno());
#else
#   error IPV6_RECVPKTINFO or IPV6_PKTINFO required; this host lacks both
#endif

#if defined IPV6_TCLASS && defined IPTOS_LOWDELAY
    const int opt_tos = IPTOS_LOWDELAY;
    if(setsockopt(sock, SOL_IPV6, IPV6_TCLASS, &opt_tos, sizeof opt_tos) == -1)
        log_fatal("Failed to set IPTOS_LOWDELAY on UDP socket: %s", dmn_logf_errno());
#endif
}

F_NONNULL
static void negotiate_udp_buffer(int sock, int which, const int pktsize, const unsigned width, const dmn_anysin_t* asin) {
        dmn_assert(sock > -1);
        dmn_assert(which == SO_SNDBUF || which == SO_RCVBUF);
        dmn_assert(pktsize >= 512);
        dmn_assert(width > 0);
        dmn_assert(asin);

        // Our default desired buffer.  This is based on enough room for
        //   recv_width * 8 packets.  recv_width is counted as "4" if less than 4
        //   (including the non-sendmmsg() case).
        const int desired_buf = pktsize * 8 * ((width < 4) ? 4 : width);

        // Bare minimum buffer we'll accept: the greater of 16K or pktsize
        const int min_buf = (pktsize < 16384) ? 16384 : pktsize;

        // For log messages below
        const char* which_str = (which == SO_SNDBUF) ? "SO_SNDBUF" : "SO_RCVBUF";

        // Negotiate with the kernel: if it reports <desired, try to set desired,
        //   cutting in half on failure so long as we stay above the min, and then
        //   eventually trying the exact minimum.  If we can't set the min, fail fatally.
        int opt_size;
        socklen_t size_size = sizeof(opt_size);
        if(getsockopt(sock, SOL_SOCKET, which, &opt_size, &size_size) == -1)
            log_fatal("Failed to get %s on UDP socket: %s", which_str, dmn_logf_errno());
        if(opt_size < desired_buf) {
            opt_size = desired_buf;
            while(setsockopt(sock, SOL_SOCKET, which, &opt_size, sizeof(opt_size)) == -1) {
                if(opt_size > (min_buf << 1))
                    opt_size >>= 1;
                else if(opt_size > min_buf)
                    opt_size = min_buf;
                else
                    log_fatal("Failed to set %s to %u for UDP socket %s: %s.  You may need to reduce the max_edns_response and/or udp_recv_width, or specify workable buffer sizes explicitly in the config", which_str, opt_size, dmn_logf_anysin(asin), dmn_logf_errno());
            }
        }

        // If we had to endure some reductions above, complain about it
        if(opt_size < desired_buf)
            log_info("UDP socket %s: %s: wanted %i, got %i", dmn_logf_anysin(asin), which_str, desired_buf, opt_size);
}

void udp_sock_setup(dns_thread_t* t) {
    dmn_assert(t);

    dns_addr_t* addrconf = t->ac;
    dmn_assert(addrconf);

    const dmn_anysin_t* asin = &addrconf->addr;

    // mod udp_recv_width down to 1 when unsupported, makes other logic simpler
    // XXX fix this so addrconf can be const?????
    if((!has_mmsg() || RUNNING_ON_VALGRIND) && addrconf->udp_recv_width > 1)
        addrconf->udp_recv_width = 1;

    const bool isv6 = asin->sa.sa_family == AF_INET6 ? true : false;
    dmn_assert(isv6 || asin->sa.sa_family == AF_INET);

    const int sock = socket(isv6 ? PF_INET6 : PF_INET, SOCK_DGRAM, gdnsd_getproto_udp());
    if(sock == -1) log_fatal("Failed to create IPv%c UDP socket: %s", isv6 ? '6' : '4', dmn_logf_errno());
    if(fcntl(sock, F_SETFD, FD_CLOEXEC))
        log_fatal("Failed to set FD_CLOEXEC on UDP socket: %s", dmn_logf_errno());

    const int opt_one = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt_one, sizeof opt_one) == -1)
        log_fatal("Failed to set SO_REUSEADDR on UDP socket: %s", dmn_logf_errno());

#ifdef SO_REUSEPORT
    if(gdnsd_reuseport_ok())
        if(setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt_one, sizeof opt_one) == -1)
            log_fatal("Failed to set SO_REUSEPORT on UDP socket: %s", dmn_logf_errno());
#endif

    if(addrconf->udp_rcvbuf) {
        int opt_size = addrconf->udp_rcvbuf;
        if(setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &opt_size, sizeof(opt_size)) == -1)
            log_fatal("Failed to set SO_RCVBUF to %u for UDP socket %s: %s", opt_size,
                dmn_logf_anysin(asin), dmn_logf_errno());
    }
    else {
        negotiate_udp_buffer(sock, SO_RCVBUF, DNS_RECV_SIZE, addrconf->udp_recv_width, asin);
    }

    if(addrconf->udp_sndbuf) {
        int opt_size = addrconf->udp_sndbuf;
        if(setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &opt_size, sizeof(opt_size)) == -1)
            log_fatal("Failed to set SO_SNDBUF to %u for UDP socket %s: %s", opt_size,
                dmn_logf_anysin(asin), dmn_logf_errno());
    }
    else {
        negotiate_udp_buffer(sock, SO_SNDBUF, gconfig.max_edns_response, addrconf->udp_recv_width, asin);
    }

    if(isv6)
        udp_sock_opts_v6(sock);
    else
        udp_sock_opts_v4(sock, dmn_anysin_is_anyaddr(asin));

    t->sock = sock;
}

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

// A reasonable guess for v4/v6 dstaddr pktinfo + cmsg header?
#define CMSG_BUFSIZE 256

F_HOT F_NORETURN F_NONNULL
static void mainloop(const int fd, void* dnsp_ctx, dnspacket_stats_t* stats, const bool use_cmsg) {
    dmn_assert(stats);

    const int cmsg_size = use_cmsg ? CMSG_BUFSIZE : 1;
    long pgsz = sysconf(_SC_PAGESIZE);
    if(pgsz < 1024) // if sysconf() error or ridiculous value, use 1K
        pgsz = 1024;
    const unsigned max_rounded = ((gconfig.max_response + pgsz - 1) / pgsz) * pgsz;

    dmn_anysin_t asin;
    void* buf = gdnsd_xpmalign(pgsz, max_rounded);
    struct iovec iov = {
        .iov_base = buf,
        .iov_len  = 0
    };
    struct msghdr msg_hdr;
    char cmsg_buf[cmsg_size];
    memset(cmsg_buf, 0, sizeof(cmsg_buf));
    memset(&msg_hdr, 0, sizeof(struct msghdr));
    msg_hdr.msg_name       = &asin.sa;
    msg_hdr.msg_iov        = &iov;
    msg_hdr.msg_iovlen     = 1;
    msg_hdr.msg_control    = use_cmsg ? cmsg_buf : NULL;

#ifdef HAVE_QSBR
    const struct timeval tmout_short = { .tv_sec = 0, .tv_usec = PRCU_DELAY_US };
    const struct timeval tmout_inf   = { .tv_sec = 0, .tv_usec = 0 };
    if(unlikely(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tmout_short, sizeof(tmout_short))))
        log_fatal("Failed to set SO_RCVTIMEO on UDP socket: %s", dmn_logf_errno());
    bool is_online = true;
#endif

    int buf_in_len;
    while(1) {
        iov.iov_len = DNS_RECV_SIZE;
        msg_hdr.msg_controllen = cmsg_size;
        msg_hdr.msg_namelen    = DMN_ANYSIN_MAXLEN;
        msg_hdr.msg_flags      = 0;

#ifdef HAVE_QSBR
        if(is_online) {
            gdnsd_prcu_rdr_quiesce();
            buf_in_len = recvmsg(fd, &msg_hdr, 0);
            if(buf_in_len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                gdnsd_prcu_rdr_offline();
                is_online = false;
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tmout_inf, sizeof(tmout_inf));
                continue;
            }
        }
        else {
            buf_in_len = recvmsg(fd, &msg_hdr, 0);
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tmout_short, sizeof(tmout_short));
            is_online = true;
            gdnsd_prcu_rdr_online();
        }
#else
        buf_in_len = recvmsg(fd, &msg_hdr, 0);
#endif

        if(unlikely((asin.sa.sa_family == AF_INET && !asin.sin.sin_port)
            || (asin.sa.sa_family == AF_INET6 && !asin.sin6.sin6_port)
            || buf_in_len < 0)) {
                if(buf_in_len < 0)
                    log_err("UDP recvmsg() error: %s", dmn_logf_errno());
                stats_own_inc(&stats->udp.recvfail);
        }
        else {
            asin.len = msg_hdr.msg_namelen;
            iov.iov_len = process_dns_query(dnsp_ctx, stats, &asin, buf, buf_in_len);
            if(likely(iov.iov_len)) {
                const int sent = sendmsg(fd, &msg_hdr, 0);
                if(unlikely(sent < 0)) {
                    stats_own_inc(&stats->udp.sendfail);
                    log_err("UDP sendmsg() of %zu bytes failed with retval %i for client %s: %s", iov.iov_len, sent, dmn_logf_anysin(&asin), dmn_logf_errno());
                }
            }
        }
    }
}

#ifdef USE_SENDMMSG

// check for linux 3.0+ for sendmmsg() (implies recvmmsg w/ MSG_WAITFORONE)
static bool has_mmsg(void) {
    bool rv = gdnsd_linux_min_version(3, 0, 0);
    if(rv) {
        /* this causes no harm and exits immediately */
        sendmmsg(-1, 0, 0, 0);
        rv = (errno != ENOSYS);
    }
    return rv;
}

F_HOT F_NORETURN F_NONNULL
static void mainloop_mmsg(const unsigned width, const int fd, void* dnsp_ctx, dnspacket_stats_t* stats, const bool use_cmsg) {
    dmn_assert(stats);

    const int cmsg_size = use_cmsg ? CMSG_BUFSIZE : 1;

    // gconfig.max_response, rounded up to the next nearest multiple of the page size
    long pgsz = sysconf(_SC_PAGESIZE);
    if(pgsz < 1024) // if sysconf() error or ridiculous value, use 1K
        pgsz = 1024;
    const unsigned max_rounded = ((gconfig.max_response + pgsz - 1) / pgsz) * pgsz;

    uint8_t* buf[width];
    struct iovec iov[width][1];
    struct mmsghdr dgrams[width];
    char cmsg_buf[width][cmsg_size];
    dmn_anysin_t asin[width];

    /* Set up packet buffers */
    memset(cmsg_buf, 0, sizeof(cmsg_buf));
    for(unsigned i = 0; i < width; i++)
        iov[i][0].iov_base = buf[i] = gdnsd_xpmalign(pgsz, max_rounded);

#ifdef HAVE_QSBR
    const struct timeval tmout_short = { .tv_sec = 0, .tv_usec = PRCU_DELAY_US };
    const struct timeval tmout_inf   = { .tv_sec = 0, .tv_usec = 0 };
    if(unlikely(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tmout_short, sizeof(tmout_short))))
        log_fatal("Failed to set SO_RCVTIMEO on UDP socket: %s", dmn_logf_errno());
    bool is_online = true;
#endif

    int pkts;

    while(1) {
        /* Set up msg_hdr stuff: moving initialization inside of the loop was
             necessitated by the memmove() below */
        for (unsigned i = 0; i < width; i++) {
            iov[i][0].iov_len = DNS_RECV_SIZE;
            dgrams[i].msg_hdr.msg_iov        = iov[i];
            dgrams[i].msg_hdr.msg_iovlen     = 1;
            dgrams[i].msg_hdr.msg_name       = &asin[i].sa;
            dgrams[i].msg_hdr.msg_namelen    = DMN_ANYSIN_MAXLEN;
            dgrams[i].msg_hdr.msg_control    = use_cmsg ? cmsg_buf[i] : NULL;
            dgrams[i].msg_hdr.msg_controllen = cmsg_size;
            dgrams[i].msg_hdr.msg_flags      = 0;
        }

#ifdef HAVE_QSBR
        if(is_online) {
            gdnsd_prcu_rdr_quiesce();
            pkts = recvmmsg(fd, dgrams, width, MSG_WAITFORONE, NULL);
            if(pkts < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                gdnsd_prcu_rdr_offline();
                is_online = false;
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tmout_inf, sizeof(tmout_inf));
                continue;
            }
        }
        else {
            pkts = recvmmsg(fd, dgrams, width, MSG_WAITFORONE, NULL);
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tmout_short, sizeof(tmout_short));
            is_online = true;
            gdnsd_prcu_rdr_online();
        }
#else
        pkts = recvmmsg(fd, dgrams, width, MSG_WAITFORONE, NULL);
#endif

        dmn_assert(pkts != 0);
        dmn_assert(pkts <= (int)width);
        if(likely(pkts > 0)) {
            for(int i = 0; i < pkts; i++) {
                if(unlikely((asin[i].sa.sa_family == AF_INET && !asin[i].sin.sin_port)
                    || (asin[i].sa.sa_family == AF_INET6 && !asin[i].sin6.sin6_port))) {
                        stats_own_inc(&stats->udp.recvfail);
                        iov[i][0].iov_len = 0; // skip send, still need memmove below
                }
                else {
                    asin[i].len = dgrams[i].msg_hdr.msg_namelen;
                    iov[i][0].iov_len = process_dns_query(dnsp_ctx, stats, &asin[i], buf[i], dgrams[i].msg_len);
                }
            }

            /* This block adjusts the array of mmsg entries to account for skips where
             *   process_query() decided we don't owe the sender a response packet.
             */
            /* This could be far simpler if sendmmsg() had an interface for skipping packets,
             *   e.g. a msg_flags flag that indicates the sendmmsg() internal loop should take
             *   no action for this entry, but still count it in the total number of successes
             */
            {
                int i = 0;
                while(i < pkts) {
                    if(unlikely(!dgrams[i].msg_hdr.msg_iov[0].iov_len)) {
                        const int next = i + 1;
                        if(next < pkts) {
                            memmove(&dgrams[i], &dgrams[next], sizeof(struct mmsghdr) * (pkts - next));
                        }
                        pkts--;
                    }
                    else {
                        i++;
                    }
                }
            }

            int mmsg_rv = sendmmsg(fd, dgrams, pkts, 0);
            if(unlikely(mmsg_rv < 0)) {
                stats_own_inc(&stats->udp.sendfail);
                int sockerr = 0;
                socklen_t sock_len = sizeof(sockerr);
                (void)getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &sock_len);
                log_err("UDP sendmmsg() failed: %s", dmn_logf_strerror(sockerr));
            }
        }
        else {
            stats_own_inc(&stats->udp.recvfail);
            log_err("UDP recvmmsg() error: %s", dmn_logf_errno());
        }
    }
}

#else // USE_SENDMMSG

static bool has_mmsg(void) { return false; }

#endif // USE_SENDMMSG

// We need to use cmsg stuff in the case of any IPv6 address (at minimum,
//  to copy the flow label correctly, if not the interface + source addr),
//  as well as the IPv4 any-address (for correct source address).
F_NONNULL F_PURE
static bool needs_cmsg(const dmn_anysin_t* asin) {
    dmn_assert(asin);
    dmn_assert(asin->sa.sa_family == AF_INET6 || asin->sa.sa_family == AF_INET);
    return (asin->sa.sa_family == AF_INET6 || dmn_anysin_is_anyaddr(asin))
        ? true
        : false;
}

F_NORETURN
void* dnsio_udp_start(void* thread_asvoid) {
    dmn_assert(thread_asvoid);

    gdnsd_thread_setname("gdnsd-io-udp");

    const dns_thread_t* t = thread_asvoid;
    dmn_assert(t->is_udp);

    const dns_addr_t* addrconf = t->ac;

    dnspacket_stats_t* stats = dnspacket_stats_init(t->threadnum, true);
    void* dnsp_ctx = dnspacket_ctx_init(true);

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    if(!t->bind_success) {
        dmn_assert(t->ac->autoscan); // other cases would fail fatally earlier
        log_warn("Could not bind UDP DNS socket %s, configured by automatic interface scanning.  Will ignore this listen address.", dmn_logf_anysin(&t->ac->addr));
        //  we come here to  spawn the thread and do the dnspacket_context_setup() properly and
        //  then exit the iothread.  The rest of the code will see this as a thread that
        //  simply never gets requests.  This way we don't have to adjust stats arrays for
        //  the missing thread, etc.
        pthread_exit(NULL);
    }

    const bool need_cmsg = needs_cmsg(&addrconf->addr);

    gdnsd_prcu_rdr_thread_start();

#ifdef USE_SENDMMSG
    if(addrconf->udp_recv_width > 1) {
        log_debug("sendmmsg() with a width of %u enabled for UDP socket %s",
            addrconf->udp_recv_width, dmn_logf_anysin(&addrconf->addr));
        mainloop_mmsg(addrconf->udp_recv_width, t->sock, dnsp_ctx, stats, need_cmsg);
    }
    else
#endif
    {
        mainloop(t->sock, dnsp_ctx, stats, need_cmsg);
    }
}
