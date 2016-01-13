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
#include "statio.h"

#include "conf.h"
#include "socks.h"
#include "dnsio_udp.h"
#include "dnsio_tcp.h"
#include "dnspacket.h"

#include <gdnsd-prot/mon.h>
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/paths.h>

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <sys/uio.h>
#include <pthread.h>

// Macro to add an offset to a void* portably...
#define ADDVOID(_vstar,_offs) ((void*)(((char*)(_vstar)) + _offs))

typedef struct {
    stats_uint_t udp_recvfail;       // 1
    stats_uint_t udp_sendfail;       // 2
    stats_uint_t udp_tc;             // 3
    stats_uint_t udp_edns_big;       // 4
    stats_uint_t udp_edns_tc;        // 5
    stats_uint_t tcp_recvfail;       // 6
    stats_uint_t tcp_sendfail;       // 7
    stats_uint_t dns_noerror;        // 8
    stats_uint_t dns_refused;        // 9
    stats_uint_t dns_nxdomain;       // 10
    stats_uint_t dns_notimp;         // 11
    stats_uint_t dns_badvers;        // 12
    stats_uint_t dns_formerr;        // 13
    stats_uint_t dns_dropped;        // 14
    stats_uint_t dns_v6;             // 15
    stats_uint_t dns_edns;           // 16
    stats_uint_t dns_edns_clientsub; // 17
    stats_uint_t udp_reqs;           // 18
    stats_uint_t tcp_reqs;           // 19
} statio_t;

// Various fixed sprintf strings for stats output formats

static const char log_dns[] =
    "noerror:%" PRIuPTR " refused:%" PRIuPTR " nxdomain:%" PRIuPTR " notimp:%" PRIuPTR " badvers:%" PRIuPTR " formerr:%" PRIuPTR " dropped:%" PRIuPTR " v6:%" PRIuPTR " edns:%" PRIuPTR " edns_clientsub:%" PRIuPTR;
static const char log_udp[] =
    "udp_reqs:%" PRIuPTR " udp_recvfail:%" PRIuPTR " udp_sendfail:%" PRIuPTR " udp_tc:%" PRIuPTR " udp_edns_big:%" PRIuPTR " udp_edns_tc:%" PRIuPTR;
static const char log_tcp[] =
    "tcp_reqs:%" PRIuPTR " tcp_recvfail:%" PRIuPTR " tcp_sendfail:%" PRIuPTR;

static const char json_fixed[] =
    "{\r\n"
    "\t\"uptime\": %" PRIu64 ",\r\n"
    "\t\"stats\": {\r\n"
    "\t\t\"noerror\": %" PRIuPTR ",\r\n"
    "\t\t\"refused\": %" PRIuPTR ",\r\n"
    "\t\t\"nxdomain\": %" PRIuPTR ",\r\n"
    "\t\t\"notimp\": %" PRIuPTR ",\r\n"
    "\t\t\"badvers\": %" PRIuPTR ",\r\n"
    "\t\t\"formerr\": %" PRIuPTR ",\r\n"
    "\t\t\"dropped\": %" PRIuPTR ",\r\n"
    "\t\t\"v6\": %" PRIuPTR ",\r\n"
    "\t\t\"edns\": %" PRIuPTR ",\r\n"
    "\t\t\"edns_clientsub\": %" PRIuPTR "\r\n"
    "\t},\r\n"
    "\t\"udp\": {\r\n"
    "\t\t\"reqs\": %" PRIuPTR ",\r\n"
    "\t\t\"recvfail\": %" PRIuPTR ",\r\n"
    "\t\t\"sendfail\": %" PRIuPTR ",\r\n"
    "\t\t\"tc\": %" PRIuPTR ",\r\n"
    "\t\t\"edns_big\": %" PRIuPTR ",\r\n"
    "\t\t\"edns_tc\": %" PRIuPTR "\r\n"
    "\t},\r\n"
    "\t\"tcp\": {\r\n"
    "\t\t\"reqs\": %" PRIuPTR ",\r\n"
    "\t\t\"recvfail\": %" PRIuPTR ",\r\n"
    "\t\t\"sendfail\": %" PRIuPTR "\r\n"
    "\t}";

static const char json_footer[] = "}\r\n";

// basic data about gathering/serving output
static unsigned num_dns_threads = 0;
static time_t start_time = 0;
static time_t pop_statio_time = 0;

// i/o handling
static ev_timer* log_watcher = NULL;
static ev_timer* file_interval_watcher = NULL;
static const char* file_path = NULL;

// This is memset to zero and re-accumulated for every output
static statio_t statio;

// This is the shared thread/loop -local output buffer
static char* json_buffer = NULL;
static unsigned json_buffer_alloc = 0;
static unsigned json_len = 0;

static void accumulate_statio(unsigned threadnum) {
    dnspacket_stats_t* this_stats = dnspacket_stats[threadnum];
    dmn_assert(this_stats);

    const stats_uint_t l_noerror   = stats_get(&this_stats->noerror);
    const stats_uint_t l_refused   = stats_get(&this_stats->refused);
    const stats_uint_t l_nxdomain  = stats_get(&this_stats->nxdomain);
    const stats_uint_t l_notimp    = stats_get(&this_stats->notimp);
    const stats_uint_t l_badvers   = stats_get(&this_stats->badvers);
    const stats_uint_t l_formerr   = stats_get(&this_stats->formerr);
    const stats_uint_t l_dropped   = stats_get(&this_stats->dropped);
    statio.dns_noerror  += l_noerror;
    statio.dns_refused  += l_refused;
    statio.dns_nxdomain += l_nxdomain;
    statio.dns_notimp   += l_notimp;
    statio.dns_badvers  += l_badvers;
    statio.dns_formerr  += l_formerr;
    statio.dns_dropped  += l_dropped;

    const stats_uint_t this_reqs = l_noerror + l_refused + l_nxdomain
        + l_notimp + l_badvers + l_formerr + l_dropped;

    if(this_stats->is_udp) {
        statio.udp_reqs     += this_reqs;
        statio.udp_recvfail += stats_get(&this_stats->udp.recvfail);
        statio.udp_sendfail += stats_get(&this_stats->udp.sendfail);
        statio.udp_tc       += stats_get(&this_stats->udp.tc);
        statio.udp_edns_big += stats_get(&this_stats->udp.edns_big);
        statio.udp_edns_tc  += stats_get(&this_stats->udp.edns_tc);
    }
    else {
        statio.tcp_reqs     += this_reqs;
        statio.tcp_recvfail += stats_get(&this_stats->tcp.recvfail);
        statio.tcp_sendfail += stats_get(&this_stats->tcp.sendfail);
    }

    statio.dns_v6             += stats_get(&this_stats->v6);
    statio.dns_edns           += stats_get(&this_stats->edns);
    statio.dns_edns_clientsub += stats_get(&this_stats->edns_clientsub);
}

static uint64_t get_uptime_u64(void) {
    dmn_assert(pop_statio_time >= start_time);
    return (uint64_t)pop_statio_time - (uint64_t)start_time;
}

static void populate_stats(void) {
    const time_t now = time(NULL);
    if(gcfg->realtime_stats || now > pop_statio_time) {
        memset(&statio, 0, sizeof(statio));
        for(unsigned i = 0; i < num_dns_threads; i++)
            accumulate_statio(i);
        pop_statio_time = now;

        // fill json output buffer
        dmn_assert(json_buffer);
        int snp_rv = snprintf(json_buffer, json_buffer_alloc, json_fixed, get_uptime_u64(), statio.dns_noerror, statio.dns_refused, statio.dns_nxdomain, statio.dns_notimp, statio.dns_badvers, statio.dns_formerr, statio.dns_dropped, statio.dns_v6, statio.dns_edns, statio.dns_edns_clientsub, statio.udp_reqs, statio.udp_recvfail, statio.udp_sendfail, statio.udp_tc, statio.udp_edns_big, statio.udp_edns_tc, statio.tcp_reqs, statio.tcp_recvfail, statio.tcp_sendfail);
        dmn_assert(snp_rv > 0);
        json_len = (unsigned)snp_rv;
        json_len += gdnsd_mon_stats_out_json(ADDVOID(json_buffer, json_len));
        memcpy(ADDVOID(json_buffer, json_len), json_footer, sizeof(json_footer) - 1U);
        json_len += (sizeof(json_footer) - 1U);
    }
    dmn_assert(pop_statio_time >= start_time);
}

static void statio_log_stats(void) {
    populate_stats();
    log_info(log_dns, statio.dns_noerror, statio.dns_refused, statio.dns_nxdomain, statio.dns_notimp, statio.dns_badvers, statio.dns_formerr, statio.dns_dropped, statio.dns_v6, statio.dns_edns, statio.dns_edns_clientsub);
    log_info(log_udp, statio.udp_reqs, statio.udp_recvfail, statio.udp_sendfail, statio.udp_tc, statio.udp_edns_big, statio.udp_edns_tc);
    log_info(log_tcp, statio.tcp_reqs, statio.tcp_recvfail, statio.tcp_sendfail);
}

F_NONNULL
static void log_watcher_cb(struct ev_loop* loop V_UNUSED, ev_timer* t V_UNUSED, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(t); dmn_assert(revents == EV_TIMER);
    statio_log_stats();
}

F_NONNULL
static void file_interval_watcher_cb(struct ev_loop* loop V_UNUSED, ev_timer* t V_UNUSED, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(t); dmn_assert(revents == EV_TIMER);

    populate_stats();

    // construct a temporary file in the same directory...
    dmn_assert(file_path);
    const unsigned fp_len = strlen(file_path);
    char tmpfn[fp_len + 7 + 1];
    memcpy(tmpfn, file_path, fp_len);
    memcpy(tmpfn + fp_len, ".XXXXXX", 7);
    tmpfn[fp_len + 7] = '\0';
    int tmpfd = mkstemp(tmpfn);
    if(tmpfd < 0) {
        dmn_log_err("mkstemp() for stats output failed: %s", dmn_logf_errno());
        return;
    }

    // write the temp file and rename into place
    ssize_t write_rv = write(tmpfd, json_buffer, json_len);
    if(write_rv != json_len) {
        dmn_log_err("write(,,%u) for stats output failed with retval %zi: %s", json_len, write_rv, dmn_logf_errno());
        close(tmpfd);
        return;
    }
    if(close(tmpfd)) {
        dmn_log_err("close() for stats output failed: %s", dmn_logf_errno());
        close(tmpfd);
        return;
    }
    if(rename(tmpfn, file_path))
        dmn_log_err("rename() for stats output failed: %s", dmn_logf_errno());
    close(tmpfd);
}

const char* statio_get_json(unsigned* len) {
    dmn_assert(len);
    populate_stats();
    *len = json_len;
    return json_buffer;
}

// stop further periodic log output and do final log output
void statio_final_stats(struct ev_loop* statio_loop) {
    dmn_assert(statio_loop);
    if(log_watcher)
        ev_timer_stop(statio_loop, log_watcher);
    statio_log_stats();
}

unsigned statio_start(struct ev_loop* statio_loop, const unsigned n_dns_threads) {
    dmn_assert(statio_loop);

    start_time = time(NULL);

    // how many dns threads we gather stats from
    num_dns_threads = n_dns_threads;

    // stats counters are 32-bit on 32-bit machines, and 64 on 64
    const unsigned stat_len = sizeof(stats_uint_t) == 8 ? 20 : 10;

    json_buffer_alloc =
        (sizeof(json_fixed) - 1)              // json fixed format string
        + (20 - strlen(PRIu64))               // uptime output
        + (19 * (stat_len - strlen(PRIuPTR))) // 19 stats, up to 20 bytes long each
        + gdnsd_mon_stats_get_max_len()       // whatever mon.c tells us...
        + (sizeof(json_footer) - 1);          // json_footer fixed string

    // double it, because it's not that big and this gives us a lot of headroom for
    //   having made any stupid mistakes in the max len calcuations :P
    json_buffer_alloc <<= 1U;
    json_buffer = xmalloc(json_buffer_alloc);

    // now set up the normal stuff, like libev event watchers
    if(gcfg->log_stats) {
        log_watcher = xmalloc(sizeof(*log_watcher));
        ev_timer_init(log_watcher, log_watcher_cb, gcfg->log_stats, gcfg->log_stats);
        ev_set_priority(log_watcher, -2);
        ev_timer_start(statio_loop, log_watcher);
    }

    if(gcfg->stats_file_interval) {
        file_path = gdnsd_resolve_path_run(gcfg->stats_file_path, NULL);
        file_interval_watcher = xmalloc(sizeof(*file_interval_watcher));
        ev_timer_init(file_interval_watcher, file_interval_watcher_cb, gcfg->stats_file_interval, gcfg->stats_file_interval);
        ev_set_priority(file_interval_watcher, -2);
        ev_timer_start(statio_loop, file_interval_watcher);
    }

    return json_buffer_alloc;
}
