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

typedef enum {
    UDP_RECVFAIL         = 0,
    UDP_SENDFAIL         = 1,
    UDP_TC               = 2,
    UDP_EDNS_BIG         = 3,
    UDP_EDNS_TC          = 4,
    TCP_RECVFAIL         = 5,
    TCP_SENDFAIL         = 6,
    TCP_CONNS            = 7,
    TCP_CLOSE_C          = 8,
    TCP_CLOSE_S_OK       = 9,
    TCP_CLOSE_S_ERR      = 10,
    TCP_CLOSE_S_KILL     = 11,
    DNS_NOERROR          = 12,
    DNS_REFUSED          = 13,
    DNS_NXDOMAIN         = 14,
    DNS_NOTIMP           = 15,
    DNS_BADVERS          = 16,
    DNS_FORMERR          = 17,
    DNS_DROPPED          = 18,
    DNS_V6               = 19,
    DNS_EDNS             = 20,
    DNS_EDNS_CLIENTSUB   = 21,
    UDP_REQS             = 22,
    TCP_REQS             = 23,
    DNS_EDNS_DO          = 24,
    DNS_EDNS_COOKIE_ERR  = 25,
    DNS_EDNS_COOKIE_OK   = 26,
    DNS_EDNS_COOKIE_INIT = 27,
    DNS_EDNS_COOKIE_BAD  = 28,
    TCP_PROXY            = 29,
    TCP_PROXY_FAIL       = 30,
    SLOT_COUNT           = 31,
} slot_t;

static const char json_fixed[] =
    "{\n"
    "\t\"uptime\": %" PRIu64 ",\n"
    "\t\"stats\": {\n"
    "\t\t\"noerror\": %" PRIuPTR ",\n"
    "\t\t\"refused\": %" PRIuPTR ",\n"
    "\t\t\"nxdomain\": %" PRIuPTR ",\n"
    "\t\t\"notimp\": %" PRIuPTR ",\n"
    "\t\t\"badvers\": %" PRIuPTR ",\n"
    "\t\t\"formerr\": %" PRIuPTR ",\n"
    "\t\t\"dropped\": %" PRIuPTR ",\n"
    "\t\t\"v6\": %" PRIuPTR ",\n"
    "\t\t\"edns\": %" PRIuPTR ",\n"
    "\t\t\"edns_clientsub\": %" PRIuPTR ",\n"
    "\t\t\"edns_do\": %" PRIuPTR ",\n"
    "\t\t\"edns_cookie_formerr\": %" PRIuPTR ",\n"
    "\t\t\"edns_cookie_ok\": %" PRIuPTR ",\n"
    "\t\t\"edns_cookie_init\": %" PRIuPTR ",\n"
    "\t\t\"edns_cookie_bad\": %" PRIuPTR "\n"
    "\t},\n"
    "\t\"udp\": {\n"
    "\t\t\"reqs\": %" PRIuPTR ",\n"
    "\t\t\"recvfail\": %" PRIuPTR ",\n"
    "\t\t\"sendfail\": %" PRIuPTR ",\n"
    "\t\t\"tc\": %" PRIuPTR ",\n"
    "\t\t\"edns_big\": %" PRIuPTR ",\n"
    "\t\t\"edns_tc\": %" PRIuPTR "\n"
    "\t},\n"
    "\t\"tcp\": {\n"
    "\t\t\"reqs\": %" PRIuPTR ",\n"
    "\t\t\"recvfail\": %" PRIuPTR ",\n"
    "\t\t\"sendfail\": %" PRIuPTR ",\n"
    "\t\t\"conns\": %" PRIuPTR ",\n"
    "\t\t\"close_c\": %" PRIuPTR ",\n"
    "\t\t\"close_s_ok\": %" PRIuPTR ",\n"
    "\t\t\"close_s_err\": %" PRIuPTR ",\n"
    "\t\t\"close_s_kill\": %" PRIuPTR ",\n"
    "\t\t\"proxy\": %" PRIuPTR ",\n"
    "\t\t\"proxy_fail\": %" PRIuPTR "\n"
    "\t}\n"
    "}\n";

static time_t start_time;
static unsigned num_dns_threads;

// This is memset to zero on startup, and then imports the final stats of the
// daemon we replaced (if applicable), and becomes the baseline for the
// accumulations into statio below.
static stats_uint_t statio_base[SLOT_COUNT];

// This is reset to statio_base and used to accumulate thread stats for output
static stats_uint_t statio[SLOT_COUNT];

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
    statio[DNS_NOERROR]  += l_noerror;
    statio[DNS_REFUSED]  += l_refused;
    statio[DNS_NXDOMAIN] += l_nxdomain;
    statio[DNS_NOTIMP]   += l_notimp;
    statio[DNS_BADVERS]  += l_badvers;
    statio[DNS_FORMERR]  += l_formerr;
    statio[DNS_DROPPED]  += l_dropped;

    const stats_uint_t this_reqs = l_noerror + l_refused + l_nxdomain
                                   + l_notimp + l_badvers + l_formerr + l_dropped;

    if (this_stats->is_udp) {
        statio[UDP_REQS]     += this_reqs;
        statio[UDP_RECVFAIL] += stats_get(&this_stats->udp.recvfail);
        statio[UDP_SENDFAIL] += stats_get(&this_stats->udp.sendfail);
        statio[UDP_TC]       += stats_get(&this_stats->udp.tc);
        statio[UDP_EDNS_BIG] += stats_get(&this_stats->udp.edns_big);
        statio[UDP_EDNS_TC]  += stats_get(&this_stats->udp.edns_tc);
    } else {
        statio[TCP_REQS]         += this_reqs;
        statio[TCP_RECVFAIL]     += stats_get(&this_stats->tcp.recvfail);
        statio[TCP_SENDFAIL]     += stats_get(&this_stats->tcp.sendfail);
        statio[TCP_CONNS]        += stats_get(&this_stats->tcp.conns);
        statio[TCP_CLOSE_C]      += stats_get(&this_stats->tcp.close_c);
        statio[TCP_CLOSE_S_OK]   += stats_get(&this_stats->tcp.close_s_ok);
        statio[TCP_CLOSE_S_ERR]  += stats_get(&this_stats->tcp.close_s_err);
        statio[TCP_CLOSE_S_KILL] += stats_get(&this_stats->tcp.close_s_kill);
        statio[TCP_PROXY]        += stats_get(&this_stats->tcp.proxy);
        statio[TCP_PROXY_FAIL]   += stats_get(&this_stats->tcp.proxy_fail);
    }

    statio[DNS_V6]               += stats_get(&this_stats->v6);
    statio[DNS_EDNS]             += stats_get(&this_stats->edns);
    statio[DNS_EDNS_CLIENTSUB]   += stats_get(&this_stats->edns_clientsub);
    statio[DNS_EDNS_DO]          += stats_get(&this_stats->edns_do);
    statio[DNS_EDNS_COOKIE_ERR]  += stats_get(&this_stats->edns_cookie_formerr);
    statio[DNS_EDNS_COOKIE_OK]   += stats_get(&this_stats->edns_cookie_ok);
    statio[DNS_EDNS_COOKIE_INIT] += stats_get(&this_stats->edns_cookie_init);
    statio[DNS_EDNS_COOKIE_BAD]  += stats_get(&this_stats->edns_cookie_bad);
}

static void populate_statio(void)
{
    memcpy(&statio, &statio_base, sizeof(statio));
    for (unsigned i = 0; i < num_dns_threads; i++)
        accumulate_statio(i);
}

char* statio_get_json(time_t nowish, size_t* len)
{
    populate_statio();
    // fill json output buffer
    uint64_t uptime64 = (uint64_t)nowish - (uint64_t)start_time;
    char* buf = xmalloc(json_buffer_max);
    int snp_rv = snprintf(buf, json_buffer_max, json_fixed, uptime64, statio[DNS_NOERROR], statio[DNS_REFUSED], statio[DNS_NXDOMAIN], statio[DNS_NOTIMP], statio[DNS_BADVERS], statio[DNS_FORMERR], statio[DNS_DROPPED], statio[DNS_V6], statio[DNS_EDNS], statio[DNS_EDNS_CLIENTSUB], statio[DNS_EDNS_DO], statio[DNS_EDNS_COOKIE_ERR], statio[DNS_EDNS_COOKIE_OK], statio[DNS_EDNS_COOKIE_INIT], statio[DNS_EDNS_COOKIE_BAD], statio[UDP_REQS], statio[UDP_RECVFAIL], statio[UDP_SENDFAIL], statio[UDP_TC], statio[UDP_EDNS_BIG], statio[UDP_EDNS_TC], statio[TCP_REQS], statio[TCP_RECVFAIL], statio[TCP_SENDFAIL], statio[TCP_CONNS], statio[TCP_CLOSE_C], statio[TCP_CLOSE_S_OK], statio[TCP_CLOSE_S_ERR], statio[TCP_CLOSE_S_KILL], statio[TCP_PROXY], statio[TCP_PROXY_FAIL]);
    gdnsd_assert(snp_rv > 0 && (size_t)snp_rv < json_buffer_max);
    *len = (size_t)snp_rv;
    return buf;
}

// Serializes as a set of 8-byte uint64_t values, one for each stat slot,
// followed by an extra one for the start_time value.
// *dlen_p holds the raw size of the allocated, returned buffer in bytes.
char* statio_serialize(size_t* dlen_p)
{
    populate_statio();
    const size_t count = SLOT_COUNT + 1U;
    uint64_t* data64 = xmalloc_n(count, sizeof(*data64));
    for (size_t i = 0; i < SLOT_COUNT; i++)
        data64[i] = (uint64_t)statio[i];
    data64[SLOT_COUNT] = (uint64_t)start_time;
    *dlen_p = count * sizeof(*data64);
    return (char*)data64;
}

// Deserialize as above, and handle compatibility: if we receive more stats
// slots than we support, ignore the trailing.  If we receive fewer than we
// support, the missing ones are implicitly zero.  Either way, true
// compatibility rests with the maintainer in never re-ordering slot numbers or
// re-using them for new/different meanings.  Future slot deletions will have
// to leave an unused hole in the sequence, future additions must go on the
// end, and future significant meaning changes will require deleting a slot and
// then adding a new one.
void statio_deserialize(uint64_t* data, size_t dlen)
{
    if (!dlen || dlen & 4U) {
        log_err("stats deserialization failed: length must be a non-zero multiple of 8");
    } else {
        size_t input_slot_count = (dlen >> 3) - 1U;
        start_time = (time_t)data[input_slot_count];
        for (size_t i = 0; i < SLOT_COUNT && i < input_slot_count; i++)
            statio_base[i] = (stats_uint_t)data[i];
    }
}

void statio_init(unsigned arg_num_dns_threads)
{
    num_dns_threads = arg_num_dns_threads;
    start_time = time(NULL);
    memset(&statio_base, 0, sizeof(statio_base));
    memset(&statio, 0, sizeof(statio_base));

    // stats counters are 32-bit on 32-bit machines, and 64 on 64
    const unsigned stat_len = sizeof(stats_uint_t) == 8 ? 20 : 10;
    json_buffer_max =
        (sizeof(json_fixed) - 1)               // json_fixed format string
        + (20 - strlen(PRIu64))                // uint64_t uptime
        + (SLOT_COUNT * (stat_len - strlen(PRIuPTR))); // SLOT_COUNT stats, 10 or 20 bytes long each

    // double it, because it's not that big and this gives us a lot of headroom for
    //   having made any stupid mistakes in the max len calcuations :P
    json_buffer_max <<= 1U;
}
