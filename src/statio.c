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
#include "statio.h"

#include "conf.h"
#include "socks.h"
#include "dnsio_udp.h"
#include "dnsio_tcp.h"
#include "dnspacket.h"

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <sys/uio.h>
#include <pthread.h>

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
    "\t}\r\n"
    "}\r\n";

static time_t start_time;
static unsigned num_dns_threads;

// This is memset to zero and re-accumulated for every output
static statio_t statio;

static size_t json_buffer_max = 0;

static void accumulate_statio(unsigned threadnum)
{
    dnspacket_stats_t* this_stats = dnspacket_stats[threadnum];
    gdnsd_assert(this_stats);

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

    if (this_stats->is_udp) {
        statio.udp_reqs     += this_reqs;
        statio.udp_recvfail += stats_get(&this_stats->udp.recvfail);
        statio.udp_sendfail += stats_get(&this_stats->udp.sendfail);
        statio.udp_tc       += stats_get(&this_stats->udp.tc);
        statio.udp_edns_big += stats_get(&this_stats->udp.edns_big);
        statio.udp_edns_tc  += stats_get(&this_stats->udp.edns_tc);
    } else {
        statio.tcp_reqs     += this_reqs;
        statio.tcp_recvfail += stats_get(&this_stats->tcp.recvfail);
        statio.tcp_sendfail += stats_get(&this_stats->tcp.sendfail);
    }

    statio.dns_v6             += stats_get(&this_stats->v6);
    statio.dns_edns           += stats_get(&this_stats->edns);
    statio.dns_edns_clientsub += stats_get(&this_stats->edns_clientsub);
}

char* statio_get_json(time_t nowish, size_t* len)
{
    char* buf = xmalloc(json_buffer_max);
    memset(&statio, 0, sizeof(statio));
    uint64_t uptime64 = (uint64_t)nowish - (uint64_t)start_time;
    for (unsigned i = 0; i < num_dns_threads; i++)
        accumulate_statio(i);
    // fill json output buffer
    int snp_rv = snprintf(buf, json_buffer_max, json_fixed, uptime64, statio.dns_noerror, statio.dns_refused, statio.dns_nxdomain, statio.dns_notimp, statio.dns_badvers, statio.dns_formerr, statio.dns_dropped, statio.dns_v6, statio.dns_edns, statio.dns_edns_clientsub, statio.udp_reqs, statio.udp_recvfail, statio.udp_sendfail, statio.udp_tc, statio.udp_edns_big, statio.udp_edns_tc, statio.tcp_reqs, statio.tcp_recvfail, statio.tcp_sendfail);
    gdnsd_assert(snp_rv > 0);
    size_t json_len = (size_t)snp_rv;
    *len = json_len;
    return buf;
}

void statio_init(unsigned arg_num_dns_threads)
{
    num_dns_threads = arg_num_dns_threads;
    start_time = time(NULL);

    // stats counters are 32-bit on 32-bit machines, and 64 on 64
    const unsigned stat_len = sizeof(stats_uint_t) == 8 ? 20 : 10;
    json_buffer_max =
        (sizeof(json_fixed) - 1)               // json_fixed format string
        + (20 - strlen(PRIu64))                // uint64_t uptime
        + (19 * (stat_len - strlen(PRIuPTR))); // 19 stats, 10 or 20 bytes long each

    // double it, because it's not that big and this gives us a lot of headroom for
    //   having made any stupid mistakes in the max len calcuations :P
    json_buffer_max <<= 1U;
}
