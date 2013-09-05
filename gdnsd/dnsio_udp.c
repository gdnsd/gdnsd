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
#include <fcntl.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <sys/mman.h>

#include "conf.h"
#include "dnswire.h"
#include "dnspacket.h"
#include "gdnsd/log.h"
#include "gdnsd/prcu-priv.h"

#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif

#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

static bool has_mmsg(void);

static void udp_sock_opts_v4(const int sock V_UNUSED, const bool any_addr) {
    const int opt_one V_UNUSED = 1;
    // If all variants we know of don't exist, we simply assume the IP
    //  stack will *not* set the DF bit on UDP packets.  We may need
    //  more variants here for other operating systems.
#if defined IP_MTU_DISCOVER && defined IP_PMTUDISC_DONT
    const int mtu_type = IP_PMTUDISC_DONT;
    if(setsockopt(sock, SOL_IP, IP_MTU_DISCOVER, &mtu_type, sizeof (mtu_type)) == -1)
        log_fatal("Failed to disable Path MTU Discovery for UDP socket: %s", logf_errno());
#elif defined IP_DONTFRAG
    const int opt_zero = 0;
    if(setsockopt(sock, SOL_IP, IP_DONTFRAG, &opt_zero, sizeof (opt_zero)) == -1)
        log_fatal("Failed to disable DF bit for UDP socket: %s", logf_errno());
#endif

    // This is just a latency hack, it's not necessary for correct operation
#if defined IP_TOS && defined IPTOS_LOWDELAY
    const int opt_tos = IPTOS_LOWDELAY;
    if(setsockopt(sock, SOL_IP, IP_TOS, &opt_tos, sizeof opt_tos) == -1)
        log_warn("Failed to set IPTOS_LOWDELAY on UDP socket: %s", logf_errno());
#endif

    if(any_addr) {
#if HAVE_DECL_IP_PKTINFO
        if(setsockopt(sock, SOL_IP, IP_PKTINFO, &opt_one, sizeof opt_one) == -1)
            log_fatal("Failed to set IP_PKTINFO on UDP socket: %s", logf_errno());
#elif HAVE_DECL_IP_RECVDSTADDR && HAVE_DECL_IP_SENDSRCADDR
        // we don't use SENDSRCADDR directly, but it seems most smart implementors
        //  define it as an alias to RECVDSTADDR.  Importantly: MacOS, which does
        //  not implement the sending part of this magic, does not declare SENDSRCADDR
#  if IP_RECVDSTADDR != IP_SENDSRCADDR
#    error Your platform violates some gdnsd assumptions (IP_RECVDSTADDR != IP_SENDSRCADDR)
#  endif
        if(setsockopt(sock, SOL_IP, IP_RECVDSTADDR, &opt_one, sizeof opt_one) == -1)
            log_fatal("Failed to set IP_RECVDSTADDR on UDP socket: %s", logf_errno());
#else
        log_fatal("IPv4 any-address '0.0.0.0' not supported for DNS listening on your platform (no IP_PKTINFO or IP_RECVDSTADDR+IP_SENDSRCADDR)");
#endif
    }
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
        log_fatal("Failed to set IPV6_USE_MIN_MTU on UDP socket: %s", logf_errno());
#elif defined IPV6_MTU
#    ifndef IPV6_MIN_MTU
#      define IPV6_MIN_MTU 1280
#    endif
    const int min_mtu = IPV6_MIN_MTU;
    if(setsockopt(sock, SOL_IPV6, IPV6_MTU, &min_mtu, sizeof min_mtu) == -1)
        log_fatal("Failed to set IPV6_MTU on UDP socket: %s", logf_errno());
#endif

    if(setsockopt(sock, SOL_IPV6, IPV6_V6ONLY, &opt_one, sizeof opt_one) == -1)
        log_fatal("Failed to set IPV6_V6ONLY on UDP socket: %s", logf_errno());

#if defined IPV6_TCLASS && defined IPTOS_LOWDELAY
    const int opt_tos = IPTOS_LOWDELAY;
    if(setsockopt(sock, SOL_IPV6, IPV6_TCLASS, &opt_tos, sizeof opt_tos) == -1)
        log_fatal("Failed to set IPTOS_LOWDELAY on UDP socket: %s", logf_errno());
#endif

// this hack is just for MacOS prior to Lion, which finally
//   implements better IPv6 support, but only with a special #define in config.h...
#ifndef IPV6_RECVPKTINFO
# define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

    if(setsockopt(sock, SOL_IPV6, IPV6_RECVPKTINFO, &opt_one, sizeof opt_one) == -1)
        log_fatal("Failed to set IPV6_RECVPKTINFO on UDP socket: %s", logf_errno());
}

bool udp_sock_setup(dns_addr_t *addrconf) {
    dmn_assert(addrconf);

    const anysin_t* asin = &addrconf->addr;

    // mod udp_recv_width down to 1 when unsupported, makes other logic simpler
    if((!has_mmsg() || RUNNING_ON_VALGRIND) && addrconf->udp_recv_width > 1)
        addrconf->udp_recv_width = 1;

    const bool isv6 = asin->sa.sa_family == AF_INET6 ? true : false;
    dmn_assert(isv6 || asin->sa.sa_family == AF_INET);

    const int sock = socket(isv6 ? PF_INET6 : PF_INET, SOCK_DGRAM, gdnsd_getproto_udp());
    if(sock == -1) log_fatal("Failed to create IPv%c UDP socket: %s", isv6 ? '6' : '4', logf_errno());

    const int opt_one = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt_one, sizeof opt_one) == -1)
        log_fatal("Failed to set SO_REUSEADDR on UDP socket: %s", logf_errno());

    int opt_size;
    socklen_t size_size = sizeof(opt_size);

    if(addrconf->udp_rcvbuf) {
        opt_size = addrconf->udp_rcvbuf;
        if(setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &opt_size, sizeof(opt_size)) == -1)
            log_fatal("Failed to set SO_RCVBUF to %u for UDP socket %s: %s", opt_size,
                logf_anysin(asin), logf_errno());
    }
    else {
        // Enforce a basic minimum SO_RCVBUF of (8 * DNS_RECV_SIZE) (10K), multiplied
        //   by udp_recv_width when recvmmsg() is actually in use.

        if(getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &opt_size, &size_size) == -1)
            log_fatal("Failed to get SO_RCVBUF on UDP socket: %s", logf_errno());

        int min_rcv = DNS_RECV_SIZE * 8 * addrconf->udp_recv_width;

        if(opt_size < min_rcv) {
            opt_size = min_rcv;
            if(setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &opt_size, sizeof(opt_size)) == -1)
                log_fatal("Failed to set SO_RCVBUF to %u for UDP socket %s: %s", opt_size,
                    logf_anysin(asin), logf_errno());
        }
    }

    if(addrconf->udp_sndbuf) {
        opt_size = addrconf->udp_sndbuf;
        if(setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &opt_size, sizeof(opt_size)) == -1)
            log_fatal("Failed to set SO_SNDBUF to %u for UDP socket %s: %s", opt_size,
                logf_anysin(asin), logf_errno());
    }
    else {
        // Try to enforce a basic minimum SO_SNDBUF in the range of 16K -> 256K depending
        //   on max_response and mmsg config/detect.
        // The minimum (no mmsg, min max_response) would be 16K, and the defaults
        //   would be 64K for non-mmsg and 128K for mmsg cases.
        if(getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &opt_size, &size_size) == -1)
            log_fatal("Failed to get SO_SNDBUF on UDP socket: %s", logf_errno());

        int desired_sndbuf;
        if(addrconf->udp_recv_width > 4)
            desired_sndbuf = gconfig.max_response * addrconf->udp_recv_width;
        else
            desired_sndbuf = gconfig.max_response * 4;

        if(desired_sndbuf > 262144)
            desired_sndbuf = 262144;

        // However, if that doesn't work, we'll negotiate down to a minimum
        //   of gconfig.max_response.  Any smaller would cause send failures,
        //   although the user may be able to configure around that by manually
        //   specifying a smaller gconfig.max_response.
        if(opt_size < desired_sndbuf) {
            opt_size = desired_sndbuf;
            while(setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &opt_size, sizeof(opt_size)) == -1) {
                if(opt_size > (int)(gconfig.max_response << 1))
                    opt_size >>= 1;
                else if(opt_size > (int)gconfig.max_response)
                    opt_size = (int)gconfig.max_response;
                else
                    log_fatal("Failed to set SO_SNDBUF to %u for UDP socket %s: %s.  You may need to reduce the max_response option on this machine to a size it is capable of allocating for UDP buffers", opt_size, logf_anysin(asin), logf_errno());
            }
        }
    }

    if(isv6)
        udp_sock_opts_v6(sock);
    else
        udp_sock_opts_v4(sock, gdnsd_anysin_is_anyaddr(asin));

    addrconf->udp_sock = sock;

    if(bind(sock, &asin->sa, asin->len)) {
        if(errno == EADDRNOTAVAIL) {
            if(addrconf->autoscan) {
                log_warn("Could not bind UDP socket %s (%s), configured by automatic interface scanning.  Will ignore this listen address.", logf_anysin(asin), logf_errno());
                addrconf->udp_autoscan_bind_failed = true;
                return false;
            }
            else if(addrconf->late_bind_secs) {
                addrconf->udp_need_late_bind = true;
                log_info("UDP DNS socket %s not yet available, will attempt late bind every %u seconds", logf_anysin(asin), addrconf->late_bind_secs);
                return ntohs(isv6 ? asin->sin6.sin6_port : asin->sin.sin_port) < 1024 ? true : false;
            }
        }
        log_fatal("Failed to bind() UDP socket to %s: %s", logf_anysin(asin), logf_errno());
    }

    return false;
}

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

// A reasonable guess for v4/v6 dstaddr pktinfo + cmsg header?
#define CMSG_BUFSIZE 256

F_NORETURN F_NONNULL
static void mainloop(const int fd, dnspacket_context_t* pctx, const bool use_cmsg) {
    dmn_assert(pctx);

    const int cmsg_size = use_cmsg ? CMSG_BUFSIZE : 1;

    anysin_t asin;
    struct iovec iov = {
        .iov_base = mmap(NULL, gconfig.max_response, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0),
        .iov_len  = 0
    };
    struct msghdr msg_hdr;
    char cmsg_buf[cmsg_size];

    memset(&msg_hdr, 0, sizeof(struct msghdr));
    msg_hdr.msg_name       = &asin.sa;
    msg_hdr.msg_iov        = &iov;
    msg_hdr.msg_iovlen     = 1;
    msg_hdr.msg_control    = use_cmsg ? cmsg_buf : NULL;

    while(1) {
        iov.iov_len = DNS_RECV_SIZE;
        msg_hdr.msg_controllen = cmsg_size;
        msg_hdr.msg_namelen    = ANYSIN_MAXLEN;
        msg_hdr.msg_flags      = 0;
        gdnsd_prcu_rdr_offline();
        const int buf_in_len = recvmsg(fd, &msg_hdr, 0);
        gdnsd_prcu_rdr_online();
        if(likely(buf_in_len >= 0)) {
            asin.len = msg_hdr.msg_namelen;
            iov.iov_len = process_dns_query(pctx, &asin, (void*)iov.iov_base, buf_in_len);
            if(likely(iov.iov_len)) {
                const int sent = sendmsg(fd, &msg_hdr, 0);
                if(unlikely(sent < 0)) {
                    stats_own_inc(&pctx->stats->udp.sendfail);
                    log_err("UDP sendmsg() of %li bytes failed with retval %i for client %s: %s", (long)iov.iov_len, sent, logf_anysin(&asin), logf_errno());
                }
            }
        }
        else {
            stats_own_inc(&pctx->stats->udp.recvfail);
            log_err("UDP recvmsg() error: %s", logf_errno());
        }
    }
}

#ifdef USE_SENDMMSG

// check for linux 3.0+ for sendmmsg() (implies recvmmsg w/ MSG_WAITFORONE)
static bool has_mmsg(void) {
    bool rv = false;
    rv = gdnsd_linux_min_version(3, 0, 0);
    if(rv) {
        /* this causes no harm and exits immediately */
        sendmmsg(-1, 0, 0, 0);
        rv = (errno != ENOSYS);
    }
    return rv;
}

F_NORETURN F_NONNULL
static void mainloop_mmsg(const unsigned width, const int fd, dnspacket_context_t* pctx, const bool use_cmsg) {
    dmn_assert(pctx);

    const int cmsg_size = use_cmsg ? CMSG_BUFSIZE : 1;

    // gconfig.max_response, rounded up to the next nearest multiple of the page size
    const long pgsz = sysconf(_SC_PAGESIZE);
    const unsigned max_rounded = gconfig.max_response - (gconfig.max_response % pgsz) + pgsz;

    uint8_t* buf[width];
    struct iovec iov[width][1];
    struct mmsghdr dgrams[width];
    char cmsg_buf[width][cmsg_size];
    anysin_t asin[width];

    /* Set up packet buffers */
    uint8_t* pbuf = mmap(NULL, max_rounded * width, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    for (unsigned i = 0; i < width; i++)
        iov[i][0].iov_base = buf[i] = pbuf + (i * max_rounded);

    while(1) {
        /* Set up msg_hdr stuff: moving initialization inside of the loop was
             necessitated by the memmove() below */
        for (unsigned i = 0; i < width; i++) {
            iov[i][0].iov_len = DNS_RECV_SIZE;
            dgrams[i].msg_hdr.msg_iov        = iov[i];
            dgrams[i].msg_hdr.msg_iovlen     = 1;
            dgrams[i].msg_hdr.msg_name       = &asin[i].sa;
            dgrams[i].msg_hdr.msg_namelen    = ANYSIN_MAXLEN;
            dgrams[i].msg_hdr.msg_control    = use_cmsg ? cmsg_buf[i] : NULL;
            dgrams[i].msg_hdr.msg_controllen = cmsg_size;
            dgrams[i].msg_hdr.msg_flags      = 0;
        }

        gdnsd_prcu_rdr_offline();
        int pkts = recvmmsg(fd, dgrams, width, MSG_WAITFORONE, NULL);
        gdnsd_prcu_rdr_online();
        dmn_assert(pkts <= (int)width);
        if(likely(pkts > 0)) {
            for(int i = 0; i < pkts; i++) {
                asin[i].len = dgrams[i].msg_hdr.msg_namelen;
                iov[i][0].iov_len = process_dns_query(pctx, &asin[i], buf[i], dgrams[i].msg_len);
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

            struct mmsghdr* dgptr = dgrams;
            while(pkts) {
                int sent = sendmmsg(fd, dgptr, pkts, 0);
                dmn_assert(sent != 0);
                dmn_assert(sent <= pkts);
                if(unlikely(sent < pkts)) {
                    int sockerr = 0;
                    socklen_t sock_len = sizeof(sockerr);
                    (void)getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &sock_len);
                    stats_own_inc(&pctx->stats->udp.sendfail);
                    if(sent < 0) sent = 0;
                    log_err("UDP sendmmsg() of %li bytes to client %s failed: %s", dgptr[sent].msg_hdr.msg_iov[0].iov_len, logf_anysin(dgptr[sent].msg_hdr.msg_name), logf_errnum(sockerr));
                    dgptr += sent; // skip past the successes
                    dgptr++; // skip the failed one too
                    pkts--; // drop one count for the failed message
                }
                pkts -= sent; // drop the count of all successes
            }
        }
        else {
            stats_own_inc(&pctx->stats->udp.recvfail);
            log_err("UDP recvmmsg() error: %s", logf_errno());
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
static bool needs_cmsg(const anysin_t* asin) {
    dmn_assert(asin);
    dmn_assert(asin->sa.sa_family == AF_INET6 || asin->sa.sa_family == AF_INET);
    return (asin->sa.sa_family == AF_INET6 || gdnsd_anysin_is_anyaddr(asin))
        ? true
        : false;
}

static void thread_clean(void* unused_arg V_UNUSED) {
    gdnsd_prcu_rdr_thread_end();
}

F_NORETURN
void* dnsio_udp_start(void* addrconf_asvoid) {
    dmn_assert(addrconf_asvoid);

    const dns_addr_t* addrconf = (const dns_addr_t*) addrconf_asvoid;

    dnspacket_context_t* pctx = dnspacket_context_new(addrconf->udp_threadnum, true);

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    if(addrconf->udp_need_late_bind) {
        const anysin_t* asin = &addrconf->addr;
        while(bind(addrconf->udp_sock, &asin->sa, asin->len)) {
            if(errno != EADDRNOTAVAIL) {
                log_err("Failed late bind() of UDP socket to %s: %s.  This listener thread is now shutting down.  Late bind attempts for this socket will no longer be attempted!", logf_anysin(asin), logf_errno());
                pthread_exit(NULL);
            }
            sleep(addrconf->late_bind_secs);
        }
        log_info("Late bind() of UDP socket to %s succeeded, serving requests now", logf_anysin(asin));
    }
    else if(addrconf->udp_autoscan_bind_failed) {
        // already logged this condition back when bind() failed, but it's simpler
        //  to spawn the thread and do the dnspacket_context_new() here properly and
        //  then exit the iothread.  The rest of the code will see this as a thread that
        //  simply never gets requests.
        pthread_exit(NULL);
    }

    const bool need_cmsg = needs_cmsg(&addrconf->addr);

    gdnsd_prcu_rdr_thread_start();
    pthread_cleanup_push(thread_clean, NULL);

#ifdef USE_SENDMMSG
    if(addrconf->udp_recv_width > 1) {
        log_debug("sendmmsg() with a width of %u enabled for UDP socket %s",
            addrconf->udp_recv_width, logf_anysin(&addrconf->addr));
        mainloop_mmsg(addrconf->udp_recv_width, addrconf->udp_sock, pctx, need_cmsg);
    }
    else
#endif
    {
        mainloop(addrconf->udp_sock, pctx, need_cmsg);
    }

    pthread_cleanup_pop(1);
}
