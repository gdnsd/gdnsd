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

#include <config.h>
#include "dnsio_udp.h"

#include "conf.h"
#include "dnswire.h"
#include "dnspacket.h"
#include "socks.h"

#include <gdnsd/log.h>
#include <gdnsd/misc.h>

#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <poll.h>

#include <urcu-qsbr.h>

#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif

#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

// "Fast" SO_RCVTIMEO for recvmsg(), in microseconds:
// In the fast path with fairly constant network input, this is the maximum
// time we'll block in recvmsg().  This timeout value has three critical
// effects:
// 1) It sets an upper bound on the time a UDP thread could delay an RCU
//    writer's grace period in synchronize_rcu() (for e.g. geoip or zone data
//    reloads waiting to free old data) in the worst case scenario.  In the
//    common case of faster traffic, the delay will approximate the packet
//    arrival timing, and in the case of truly-long idle periods the delay is
//    usually zero.
// 2) It sets a similar worst-corner-case upper bound on the time that a UDP
//    thread could delay reacting to a request to stop for shutdown.
// 3) If no packets arrive for this long, the thread will switch to a slower
//    and more-efficient idle path that waits indefinitely in ppoll() for new
//    traffic or a shutdown signal.  This path is more efficient for long idle
//    periods, but costs a few extra syscalls (2x pthread_sigmask + 1x ppoll)
//    every time we use it.
// Note the current value is a prime number of us, and also a prime number of
// ms at lower resolution.  This is to help avoid getting into ugly timing
// patterns.  The current value is ~257ms.
#define FAST_RCVTIMEO_US 257123

// This is the width of our recvmmsg + sendmmsg operations.  It used to be
// configurable, but really a fixed value is probably better, as it makes
// allocations easier to deal with and loops easier to unroll, etc.  At the end
// of the day, once you've gotten past burst absorption and a bit over an order
// of magnitude throughput improvement in the worst case, you've gotten about
// all the pragmatic benefit you can out of this without risking latencies, as
// the packet processing between send+recv is serialized.
// In situations where a larger value seems desirable, it's probably better to
// just drop packets from the buffer (or add more udp threads, or upgrade
// hardware, or improve kernel socket efficiency).
#define MMSG_WIDTH 16U

// This flag is set true early in dnsio_udp_init() only in the case that the
// runtime check passes (in addition to the configure-time check that handles
// the USE_MMSG define).
#ifdef USE_MMSG
static bool use_mmsg = false;
#endif

// These are initialized once at process start by dnsio_udp_init():
static sigset_t sigmask_all;     // blocks all sigs
static sigset_t sigmask_notusr2; // blocks all sigs except USR2

// Used to check the sender of USR2 as the main pid, to ignore erroneous
// signals sent by outsiders:
static pid_t mainpid = 0;

static __thread volatile sig_atomic_t thread_shutdown = 0;
static void sighand_stop(int s V_UNUSED, siginfo_t* info, void* ucontext V_UNUSED)
{
    if (!info || info->si_pid == mainpid)
        thread_shutdown = 1;
}

void dnsio_udp_init(const pid_t main_pid)
{
#ifdef USE_MMSG
    errno = 0;
    sendmmsg(-1, 0, 0, 0);
    if (errno != ENOSYS) {
        errno = 0;
        recvmmsg(-1, 0, 0, 0, 0);
        use_mmsg = (errno != ENOSYS);
        if (use_mmsg)
            log_debug("using sendmmsg()/recvmmsg() interfaces for UDP");
    }
    errno = 0;
#endif
    gdnsd_assert(main_pid);
    mainpid = main_pid;
    struct sigaction sa;
    sa.sa_sigaction = sighand_stop;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGUSR2, &sa, 0))
        log_fatal("Cannot install SIGUSR2 handler for dnsio_udp threads!");

    // Pre-fill a couple of commonly-used static signal masks
    sigfillset(&sigmask_all);
    sigfillset(&sigmask_notusr2);
    sigdelset(&sigmask_notusr2, SIGUSR2);
}

static void udp_sock_opts_v4(const gdnsd_anysin_t* sa, const int sock V_UNUSED)
{
#if defined IP_MTU_DISCOVER && defined IP_PMTUDISC_DONT
#  if defined IP_PMTUDISC_OMIT
    if (sockopt_int_warn(UDP, sa, sock, SOL_IP, IP_MTU_DISCOVER, IP_PMTUDISC_OMIT))
#  endif
        sockopt_int_fatal(UDP, sa, sock, SOL_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT);
#elif defined IP_DONTFRAG
    sockopt_bool_fatal(UDP, sa, sock, SOL_IP, IP_DONTFRAG, 0);
#else
#   error IPv4 not supported: cannot disable DF/PMTUDISC
#endif

    if (gdnsd_anysin_is_anyaddr(sa)) {
#if defined IP_PKTINFO
        sockopt_bool_fatal(UDP, sa, sock, SOL_IP, IP_PKTINFO, 1);
#elif defined IP_RECVDSTADDR
        sockopt_bool_fatal(UDP, sa, sock, SOL_IP, IP_RECVDSTADDR, 1);
#else
        log_fatal("IPv4 any-address '0.0.0.0' not supported for DNS listening on your platform (no IP_PKTINFO or IP_RECVDSTADDR)");
#endif
    }

    // This is just a latency hack, it's not necessary for correct operation
#if defined IP_TOS && defined IPTOS_LOWDELAY
    sockopt_int_warn(UDP, sa, sock, SOL_IP, IP_TOS, IPTOS_LOWDELAY);
#endif
}

#ifndef IPV6_MIN_MTU
#define IPV6_MIN_MTU 1280
#endif

static void udp_sock_opts_v6(const gdnsd_anysin_t* sa, const int sock)
{
    sockopt_bool_fatal(UDP, sa, sock, SOL_IPV6, IPV6_V6ONLY, 1);

#if defined IPV6_USE_MIN_MTU
    sockopt_bool_fatal(UDP, sa, sock, SOL_IPV6, IPV6_USE_MIN_MTU, 1);
#elif defined IPV6_MTU
    // This sockopt doesn't have matching get+set; get needs a live
    // connection and reports the connection's path MTU, so we have to just
    // set it here blindly...
    const int min_mtu = IPV6_MIN_MTU;
    if (setsockopt(sock, SOL_IPV6, IPV6_MTU, &min_mtu, sizeof(min_mtu)) == -1)
        log_fatal("Failed to set IPV6_MTU on TCP socket: %s", logf_errno());
#else
#   error IPv6 not ok: cannot set MTU to 1280
#endif

#if defined IPV6_MTU_DISCOVER && defined IPV6_PMTUDISC_DONT
#  if defined IPV6_PMTUDISC_OMIT
    if (sockopt_int_warn(UDP, sa, sock, SOL_IPV6, IPV6_MTU_DISCOVER, IPV6_PMTUDISC_OMIT))
#  endif
        sockopt_int_fatal(UDP, sa, sock, SOL_IPV6, IPV6_MTU_DISCOVER, IPV6_PMTUDISC_DONT);
#elif defined IPV6_DONTFRAG
    // There have been reports in https://github.com/gdnsd/gdnsd/issues/115 of
    // the IPV6_DONTFRAG setsockopt failing within the context of some
    // OpenVZ+Debian environments.
    // RFC 3542 says "By default, this socket option is disabled", so what
    // we're doing here is just reinforcing the default as a sanity-check
    // against bad defaults.
    // Therefore, we'll merely warn rather than fatal on this, in hopes it
    // clears up whatever's wrong with these OpenVZ environments.
    sockopt_int_warn(UDP, sa, sock, SOL_IPV6, IPV6_DONTFRAG, 0);
#endif

#if defined IPV6_RECVPKTINFO
    sockopt_bool_fatal(UDP, sa, sock, SOL_IPV6, IPV6_RECVPKTINFO, 1);
#elif defined IPV6_PKTINFO
    sockopt_bool_fatal(UDP, sa, sock, SOL_IPV6, IPV6_PKTINFO, 1);
#else
#   error IPv6 not supported: cannot set IPV6_RECVPKTINFO or IPV6_PKTINFO
#endif

#if defined IPV6_TCLASS && defined IPTOS_LOWDELAY
    sockopt_int_warn(UDP, sa, sock, SOL_IPV6, IPV6_TCLASS, IPTOS_LOWDELAY);
#endif
}

void udp_sock_setup(dns_thread_t* t)
{
    const dns_addr_t* addrconf = t->ac;
    gdnsd_assert(addrconf);

    const gdnsd_anysin_t* sa = &addrconf->addr;

    const bool isv6 = sa->sa.sa_family == AF_INET6 ? true : false;
    gdnsd_assert(isv6 || sa->sa.sa_family == AF_INET);

    bool need_bind = false;
    if (t->sock == -1) { // not acquired via replace
        t->sock = socket(sa->sa.sa_family, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
        if (t->sock == -1)
            log_fatal("Failed to create IPv%c UDP socket: %s", isv6 ? '6' : '4', logf_errno());
        need_bind = true;
    }

    sockopt_bool_fatal(UDP, sa, t->sock, SOL_SOCKET, SO_REUSEADDR, 1);
    // We need SO_REUSEPORT for functional reasons
    sockopt_bool_fatal(UDP, sa, t->sock, SOL_SOCKET, SO_REUSEPORT, 1);
#ifdef SO_REUSEPORT_LB
    // If BSD's SO_REUSEPORT_LB is available, try to upgrade to that for better
    // balancing, but merely warn on failure because it's new and there could
    // be a compiletime vs runtime diff.
    sockopt_bool_warn(UDP, sa, t->sock, SOL_SOCKET, SO_REUSEPORT_LB, 1);
#endif

    if (addrconf->udp_rcvbuf)
        sockopt_int_fatal(UDP, sa, t->sock, SOL_SOCKET, SO_RCVBUF, (int)addrconf->udp_rcvbuf);
    if (addrconf->udp_sndbuf)
        sockopt_int_fatal(UDP, sa, t->sock, SOL_SOCKET, SO_SNDBUF, (int)addrconf->udp_sndbuf);

    if (isv6)
        udp_sock_opts_v6(sa, t->sock);
    else
        udp_sock_opts_v4(sa, t->sock);

    if (need_bind)
        socks_bind_sock("UDP DNS", t->sock, sa);
}

static unsigned get_pgsz(void)
{
    long pgsz = sysconf(_SC_PAGESIZE);
    // if sysconf() error or ridiculous value, use 4K
    if (pgsz < 1024 || pgsz > (1 << 20))
        pgsz = 4096;
    return (unsigned)pgsz;
}

// This is a precise definition of the cmsg buffer space needed for IPv6, which
// is assumed to be larger than that needed for IPv4 (we use the same buffer
// size for both cases for simplicity).  There could be portability issues
// lurking here that will need to be addressed, but this works for Linux and I
// think it works for the *BSDs as well.
#define CMSG_BUFSIZE CMSG_SPACE(sizeof(struct in6_pktinfo))

// Clear the ipi6_ifindex value of an IPV6_PKTINFO unless the address is
// link-local.  Leaving it set to its original value in other cases can cause
// mis-routing of responses (e.g. receiving a request packet through a real
// interface, with a global unicast destination address which is configured
// only on the local loopback interface, as is common behind certain kinds of
// loadbalancer/router setups).
F_NONNULL
static void ipv6_pktinfo_ifindex_fixup(struct msghdr* msg_hdr)
{
    gdnsd_assert(((struct sockaddr*)msg_hdr->msg_name)->sa_family == AF_INET6);
    struct cmsghdr* cmsg = (struct cmsghdr*)CMSG_FIRSTHDR(msg_hdr);
    while (cmsg) {
        if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == IPV6_PKTINFO)) {
            struct in6_pktinfo* pi = (void*)CMSG_DATA(cmsg);
            if (!IN6_IS_ADDR_LINKLOCAL(&pi->ipi6_addr))
                pi->ipi6_ifindex = 0;
            break;
        }
        cmsg = (struct cmsghdr*)CMSG_NXTHDR(msg_hdr, cmsg);
    }
}

// Once traffic has become "idle", the mainloop invokes this function, which is
// intended to reliably block as long as it can, until either the terminal
// signal or fresh network traffic arrives.  We have to be careful about signal
// handler races which could cause indefinite ignorance of shutdown here!
static void slow_idle_poll(const int fd)
{
    // Block all signals
    if (pthread_sigmask(SIG_SETMASK, &sigmask_all, NULL))
        log_fatal("pthread_sigmask() failed");

    // check thread_shutdown one more time here to catch any USR2 that landed
    // since the last mainloop check but before the sigmask above.
    if (likely(!thread_shutdown)) {
        // ppoll once for fd input + SIGUSR2, for up to infinite time
        struct pollfd ppfd = {
            .fd = fd,
            .events = (POLLIN | POLLERR | POLLHUP),
            .revents = 0 // we don't care what results land here
        };
        errno = 0;
        const int pprv = ppoll(&ppfd, 1, NULL, &sigmask_notusr2);
        if (pprv < 0 && errno != EINTR)
            log_neterr("UDP ppoll() error: %s", logf_errno());
    }

    // Restore the unblocked-USR2 setup for the fast path
    if (pthread_sigmask(SIG_SETMASK, &sigmask_notusr2, NULL))
        log_fatal("pthread_sigmask() failed");
}

F_HOT F_NONNULL
static void process_msg(const int fd, dnsp_ctx_t* pctx, dnspacket_stats_t* stats, struct msghdr* msg_hdr, const size_t buf_in_len)
{
    gdnsd_anysin_t* sa = msg_hdr->msg_name;
    if (unlikely(
                (sa->sa.sa_family == AF_INET && !sa->sin4.sin_port)
                || (sa->sa.sa_family == AF_INET6 && !sa->sin6.sin6_port)
            )) {
        stats_own_inc(&stats->dropped);
        return;
    }

    if (sa->sa.sa_family == AF_INET6)
        ipv6_pktinfo_ifindex_fixup(msg_hdr);

    sa->len = msg_hdr->msg_namelen;
    struct iovec* iov = msg_hdr->msg_iov;
    iov->iov_len = process_dns_query(pctx, sa, iov->iov_base, NULL, buf_in_len);
    if (iov->iov_len) {
        ssize_t sent;
        do {
            sent = sendmsg(fd, msg_hdr, MSG_DONTWAIT);
        } while (unlikely(sent < 0 && errno == EINTR));
        if (unlikely(sent < 0)) {
            stats_own_inc(&stats->udp.sendfail);
            log_neterr("UDP sendmsg() of %zu bytes to %s failed: %s",
                       iov->iov_len, logf_anysin(sa), logf_errno());
        }
    }
}

F_HOT F_NONNULL
static void mainloop(const int fd, dnsp_ctx_t* pctx, dnspacket_stats_t* stats, const bool use_cmsg)
{
    const unsigned pgsz = get_pgsz();
    const unsigned max_rounded = ((MAX_RESPONSE_BUF + pgsz - 1) / pgsz) * pgsz;

    gdnsd_anysin_t sa;
    void* buf = gdnsd_xpmalign(pgsz, max_rounded);
    struct iovec iov = {
        .iov_base = buf,
        .iov_len  = 0
    };
    struct msghdr msg_hdr;
    union {
        struct cmsghdr chdr;
        char cbuf[CMSG_BUFSIZE];
    } cmsg_buf;
    memset(&msg_hdr, 0, sizeof(msg_hdr));
    msg_hdr.msg_name       = &sa.sa;
    msg_hdr.msg_iov        = &iov;
    msg_hdr.msg_iovlen     = 1;
    msg_hdr.msg_control    = use_cmsg ? cmsg_buf.cbuf : NULL;

    const struct timeval tmout_short = { .tv_sec = 0, .tv_usec = FAST_RCVTIMEO_US };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tmout_short, sizeof(tmout_short)))
        log_fatal("Failed to set SO_RCVTIMEO on UDP socket: %s", logf_errno());

    while (likely(!thread_shutdown)) {
        iov.iov_len = DNS_RECV_SIZE;
        msg_hdr.msg_namelen    = GDNSD_ANYSIN_MAXLEN;
        msg_hdr.msg_flags      = 0;
        if (use_cmsg) {
            msg_hdr.msg_controllen = CMSG_BUFSIZE;
            memset(cmsg_buf.cbuf, 0, sizeof(cmsg_buf));
        }

        rcu_quiescent_state();
        const ssize_t recvmsg_rv = recvmsg(fd, &msg_hdr, 0);
        if (unlikely(recvmsg_rv < 0)) {
            if (ERRNO_WOULDBLOCK) {
                rcu_thread_offline();
                slow_idle_poll(fd);
                rcu_thread_online();
            } else if (errno != EINTR) {
                log_neterr("UDP recvmsg() error: %s", logf_errno());
                stats_own_inc(&stats->udp.recvfail);
            }
            continue;
        }
        process_msg(fd, pctx, stats, &msg_hdr, (size_t)recvmsg_rv);
    }

    free(buf);
}

#ifdef USE_MMSG

F_HOT F_NONNULL
static void process_mmsgs(const int fd, dnsp_ctx_t* pctx, dnspacket_stats_t* stats, struct mmsghdr* dgrams, const unsigned pkts)
{
    // For each input packet, first check for source port zero (in which case
    // we instantly drop it at this layer), then process it through
    // process_dns_query to generate a response (which may return a length of
    // zero to indicate a need to drop the response as well).  The resulting
    // response size (or zero for drop) is stored to the iov_len.
    for (unsigned i = 0; i < pkts; i++) {
        gdnsd_anysin_t* asp = dgrams[i].msg_hdr.msg_name;
        struct iovec* iop = &dgrams[i].msg_hdr.msg_iov[0];
        if (unlikely((asp->sa.sa_family == AF_INET && !asp->sin4.sin_port)
                     || (asp->sa.sa_family == AF_INET6 && !asp->sin6.sin6_port))) {
            // immediately fail with no log output for packets with source port zero
            stats_own_inc(&stats->dropped);
            iop->iov_len = 0; // skip send, same as if process_dns_query() rejected it
        } else {
            if (asp->sa.sa_family == AF_INET6)
                ipv6_pktinfo_ifindex_fixup(&dgrams[i].msg_hdr);
            asp->len = dgrams[i].msg_hdr.msg_namelen;
            iop->iov_len = process_dns_query(pctx, asp, iop->iov_base, NULL, dgrams[i].msg_len);
        }
    }

    // We have an array of datagrams to potentially send.  There are "pkts"
    // entries, but any with iov_len == 0 should not be sent, and sendmmsg can
    // only send contiguous chunks of the array.  Therefore, some magic here
    // has to skip past blocks of zeros while sending blocks of non-zeros:
    unsigned pkts_done = 0;
    while (pkts_done < pkts) {
        // In one for-loop here, we'll skip any leading zeros and count the
        // next set of non-zeros as to_send:
        unsigned to_send = 0;
        for (unsigned i = pkts_done; i < pkts; i++) {
            if (dgrams[i].msg_hdr.msg_iov[0].iov_len)
                to_send++; // part of the first run of non-zeros
            else if (!to_send)
                pkts_done++; // leading-zeros case
            else
                break; // first zero after a non-zero run
        }

        // If there's a run to send:
        if (to_send) {
            // attempt to send next run of non-zeros, retrying on EINTR:
            struct mmsghdr* first = &dgrams[pkts_done];
            ssize_t mmsg_rv;
            do {
                mmsg_rv = sendmmsg(fd, first, to_send, MSG_DONTWAIT);
                // sendmmsg returns [1 - to_send] or -1, never zero:
                gdnsd_assert(mmsg_rv != 0);
                gdnsd_assert(mmsg_rv <= (int)to_send);
            } while (unlikely(mmsg_rv < 0 && errno == EINTR));

            // Handle non-EINTR errors as a failure of the first packet only
            // and then fake an mmsg_rv of 1 to skip over it:
            if (unlikely(mmsg_rv < 0)) {
                stats_own_inc(&stats->udp.sendfail);
                log_neterr("UDP sendmmsg() of %zu bytes to %s failed: %s",
                           first->msg_hdr.msg_iov[0].iov_len,
                           logf_anysin((const gdnsd_anysin_t*)first->msg_hdr.msg_name),
                           logf_errno());
                mmsg_rv = 1;
            }

            // Account for progress and loop as necessary
            pkts_done += (unsigned)mmsg_rv;
        } else {
            // if to_send was zero, logically we should be done with all
            // packets and the outer while() will terminate at the top:
            gdnsd_assert(pkts_done == pkts);
        }
    }
}

F_HOT F_NONNULL
static void mainloop_mmsg(const int fd, dnsp_ctx_t* pctx, dnspacket_stats_t* stats, const bool use_cmsg)
{
    // MAX_RESPONSE_BUF, rounded up to the next nearest multiple of the page size
    const unsigned pgsz = get_pgsz();
    const unsigned max_rounded = ((MAX_RESPONSE_BUF + pgsz - 1) / pgsz) * pgsz;

    uint8_t* bufs = gdnsd_xpmalign_n(pgsz, MMSG_WIDTH, max_rounded);

    struct mmsghdr dgrams[MMSG_WIDTH];
    struct {
        struct iovec iov[1];
        gdnsd_anysin_t sa;
        union {
            struct cmsghdr chdr;
            char cbuf[CMSG_BUFSIZE];
        } cmsg_buf;
    } msgdata[MMSG_WIDTH];

    // Set up mmsg buffers and sub-structures
    for (unsigned i = 0; i < MMSG_WIDTH; i++) {
        memset(&dgrams[i].msg_hdr, 0, sizeof(dgrams[i].msg_hdr));
        msgdata[i].iov[0].iov_base       = &bufs[i * max_rounded];
        dgrams[i].msg_hdr.msg_iov        = msgdata[i].iov;
        dgrams[i].msg_hdr.msg_iovlen     = 1;
        dgrams[i].msg_hdr.msg_name       = &msgdata[i].sa.sa;
        dgrams[i].msg_hdr.msg_control    = use_cmsg ? msgdata[i].cmsg_buf.cbuf : NULL;
    }

    const struct timeval tmout_short = { .tv_sec = 0, .tv_usec = FAST_RCVTIMEO_US };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tmout_short, sizeof(tmout_short)))
        log_fatal("Failed to set SO_RCVTIMEO on UDP socket: %s", logf_errno());

    while (likely(!thread_shutdown)) {
        // Re-set values changed by previous syscalls
        for (unsigned i = 0; i < MMSG_WIDTH; i++) {
            dgrams[i].msg_hdr.msg_iov[0].iov_len = DNS_RECV_SIZE;
            dgrams[i].msg_hdr.msg_namelen        = GDNSD_ANYSIN_MAXLEN;
            dgrams[i].msg_hdr.msg_flags          = 0;
            if (use_cmsg) {
                dgrams[i].msg_hdr.msg_controllen = CMSG_BUFSIZE;
                memset(msgdata[i].cmsg_buf.cbuf, 0, sizeof(msgdata[i].cmsg_buf));
            }
        }

        rcu_quiescent_state();
        const ssize_t mmsg_rv = recvmmsg(fd, dgrams, MMSG_WIDTH, MSG_WAITFORONE, NULL);
        if (unlikely(mmsg_rv < 0)) {
            if (ERRNO_WOULDBLOCK) {
                rcu_thread_offline();
                slow_idle_poll(fd);
                rcu_thread_online();
            } else if (errno != EINTR) {
                stats_own_inc(&stats->udp.recvfail);
                log_neterr("UDP recvmmsg() error: %s", logf_errno());
            }
            continue;
        }
        gdnsd_assert(mmsg_rv <= MMSG_WIDTH); // never returns more than we ask
        gdnsd_assert(mmsg_rv > 0); // never returns zero
        process_mmsgs(fd, pctx, stats, dgrams, (unsigned)mmsg_rv);
    }

    free(bufs);
}

#endif // USE_MMSG

F_NONNULL F_PURE
static bool is_ipv6(const gdnsd_anysin_t* sa)
{
    gdnsd_assert(sa->sa.sa_family == AF_INET6 || sa->sa.sa_family == AF_INET);
    return (sa->sa.sa_family == AF_INET6);
}

void* dnsio_udp_start(void* thread_asvoid)
{
    gdnsd_thread_setname("gdnsd-io-udp");

    const dns_thread_t* t = thread_asvoid;
    gdnsd_assert(t->is_udp);

    const dns_addr_t* addrconf = t->ac;

    dnspacket_stats_t* stats;
    dnsp_ctx_t* pctx = dnspacket_ctx_init_udp(&stats, is_ipv6(&addrconf->addr));

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    // main thread blocks all sigs when spawning both tcp and udp io threads.
    // for dnsio_udp, unblock SIGUSR2, which we use to stop cleanly
    if (pthread_sigmask(SIG_SETMASK, &sigmask_notusr2, NULL))
        log_fatal("pthread_sigmask() failed");

    rcu_register_thread();

    const bool use_cmsg = addrconf->addr.sa.sa_family == AF_INET6
                          ? true
                          : gdnsd_anysin_is_anyaddr(&addrconf->addr);

#ifdef USE_MMSG
    if (use_mmsg)
        mainloop_mmsg(t->sock, pctx, stats, use_cmsg);
    else
#endif
        mainloop(t->sock, pctx, stats, use_cmsg);

    rcu_unregister_thread();
    dnspacket_ctx_cleanup(pctx);
    return NULL;
}
