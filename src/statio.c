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

#include <gdnsd-prot/mon.h>
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <sys/uio.h>
#include <pthread.h>

// Macro to add an offset to a void* portably...
#define ADDVOID(_vstar,_offs) ((void*)(((char*)(_vstar)) + _offs))

typedef struct {
    stats_uint_t udp_recvfail;
    stats_uint_t udp_sendfail;
    stats_uint_t udp_tc;
    stats_uint_t udp_edns_big;
    stats_uint_t udp_edns_tc;
    stats_uint_t tcp_recvfail;
    stats_uint_t tcp_sendfail;
    stats_uint_t dns_noerror;
    stats_uint_t dns_refused;
    stats_uint_t dns_nxdomain;
    stats_uint_t dns_notimp;
    stats_uint_t dns_badvers;
    stats_uint_t dns_formerr;
    stats_uint_t dns_dropped;
    stats_uint_t dns_v6;
    stats_uint_t dns_edns;
    stats_uint_t dns_edns_clientsub;
    stats_uint_t udp_reqs;
    stats_uint_t tcp_reqs;
} statio_t;

typedef enum {
    READING_REQ = 0,
    WRITING_RES,
    READING_JUNK
} http_state_t;

// How many bytes of the request we really read()
#define HTTP_READ_BYTES 18

typedef struct {
    dmn_anysin_t* asin;
    char read_buffer[HTTP_READ_BYTES];
    struct iovec outbufs[2];
    char* hdr_buf;
    char* data_buf;
    ev_io* read_watcher;
    ev_io* write_watcher;
    ev_timer* timeout_watcher;
    unsigned read_done;
    http_state_t state;
} http_data_t;

// After reading the first 8 bytes of the request (all we care
//  about), we send the response and then linger
//  draining the remaining input in JUNK_SIZE chunks before
//  the final SHUT_RDWR/close().  junk_buffer should be per-
//  thread, but there's only one statio thread and it doesn't
//  matter if multiple connections step all over each other writing
//  to this.
#define JUNK_SIZE 4096
static char* junk_buffer;

// Various fixed sprintf strings for stats output formats

static const char log_dns[] =
    "noerror:%" PRIuPTR " refused:%" PRIuPTR " nxdomain:%" PRIuPTR " notimp:%" PRIuPTR " badvers:%" PRIuPTR " formerr:%" PRIuPTR " dropped:%" PRIuPTR " v6:%" PRIuPTR " edns:%" PRIuPTR " edns_clientsub:%" PRIuPTR;
static const char log_udp[] =
    "udp_reqs:%" PRIuPTR " udp_recvfail:%" PRIuPTR " udp_sendfail:%" PRIuPTR " udp_tc:%" PRIuPTR " udp_edns_big:%" PRIuPTR " udp_edns_tc:%" PRIuPTR;
static const char log_tcp[] =
    "tcp_reqs:%" PRIuPTR " tcp_recvfail:%" PRIuPTR " tcp_sendfail:%" PRIuPTR;

static const char http_404_hdr[] =
    "HTTP/1.0 404 Not Found\r\n"
    "Server: " PACKAGE_NAME "/" PACKAGE_VERSION "\r\n"
    "Content-type: text/plain; charset=utf-8\r\n"
    "Content-length: 11\r\n\r\n";

static const char http_404_data[] = "Not Found\r\n";

static const char http_headers[] =
    "HTTP/1.0 200 OK\r\n"
    "Server: " PACKAGE_NAME "/" PACKAGE_VERSION "\r\n"
    "Pragma: no-cache\r\n"
    "Expires: Sat, 26 Jul 1997 05:00:00 GMT\r\n"
    "Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0\r\n"
    "Refresh: 60\r\n"
    "Content-type: %s; charset=utf-8\r\n"
    "Content-length: %u\r\n\r\n";

static const char csv_fixed[] =
    "uptime\r\n"
    "%" PRIu64 "\r\n"
    "noerror,refused,nxdomain,notimp,badvers,formerr,dropped,v6,edns,edns_clientsub\r\n"
    "%" PRIuPTR ",%" PRIuPTR ",%" PRIuPTR ",%" PRIuPTR ",%" PRIuPTR ",%" PRIuPTR ",%" PRIuPTR ",%" PRIuPTR ",%" PRIuPTR ",%" PRIuPTR "\r\n"
    "udp_reqs,udp_recvfail,udp_sendfail,udp_tc,udp_edns_big,udp_edns_tc\r\n"
    "%" PRIuPTR ",%" PRIuPTR ",%" PRIuPTR ",%" PRIuPTR ",%" PRIuPTR ",%" PRIuPTR "\r\n"
    "tcp_reqs,tcp_recvfail,tcp_sendfail\r\n"
    "%" PRIuPTR ",%" PRIuPTR ",%" PRIuPTR "\r\n";

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

static const char html_fixed[] =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
    "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\r\n"
    "<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en\" xml:lang=\"en\">\r\n"
    "<head><title>" PACKAGE_NAME "</title><style type='text/css'>\r\n"
    ".bold { font-weight: bold }\r\n"
    ".big { font-size: 1.25em; }\r\n"
    "table { border-width: 2px; border-style: ridge; margin: 0.25em; padding: 1px }\r\n"
    "th,td { border-width: 2px; border-style: inset }\r\n"
    "th { background: #CCF; font-weight: bold }\r\n"
    "td.UP { background: #AFA }\r\n"
    "td.DOWN { background: #FAA }\r\n"
    "td.FORCE { background: #FA0 }\r\n"
    "</style></head><body>\r\n"
    "<h2>" PACKAGE_NAME "/" PACKAGE_VERSION "</h2>\r\n"
    "<p class='big'><span class='bold'>Current Time:</span> %s UTC</p>\r\n"
    "<p class='big'><span class='bold'>Uptime:</span> %s</p>\r\n"
    "<p><span class='bold big'>Stats:</span></p><table>\r\n"
    "<tr><th>noerror</th><th>refused</th><th>nxdomain</th><th>notimp</th><th>badvers</th><th>formerr</th><th>dropped</th><th>v6</th><th>edns</th><th>edns_clientsub</th></tr>\r\n"
    "<tr><td>%" PRIuPTR "</td><td>%" PRIuPTR "</td><td>%" PRIuPTR "</td><td>%" PRIuPTR "</td><td>%" PRIuPTR "</td><td>%" PRIuPTR "</td><td>%" PRIuPTR "</td><td>%" PRIuPTR "</td><td>%" PRIuPTR "</td><td>%" PRIuPTR "</td></tr>\r\n"
    "</table><table>\r\n"
    "<tr><th>udp_reqs</th><th>udp_recvfail</th><th>udp_sendfail</th><th>udp_tc</th><th>udp_edns_big</th><th>udp_edns_tc</th></tr>\r\n"
    "<tr><td>%" PRIuPTR "</td><td>%" PRIuPTR "</td><td>%" PRIuPTR "</td><td>%" PRIuPTR "</td><td>%" PRIuPTR "</td><td>%" PRIuPTR "</td></tr>\r\n"
    "</table><table>\r\n"
    "<tr><th>tcp_reqs</th><th>tcp_recvfail</th><th>tcp_sendfail</th></tr>\r\n"
    "<tr><td>%" PRIuPTR "</td><td>%" PRIuPTR "</td><td>%" PRIuPTR "</td></tr>\r\n"
    "</table>\r\n";

static const char html_footer[] =
    "<p>For machine-readable CSV output, use <a href='/csv'>/csv</a></p>\r\n"
    "<p>For machine-readable JSON output, use <a href='/json'>/json</a></p>\r\n"
    "<p>For delta stats (since last such query), append the query param '?f=1'</p>\r\n"
    "</body></html>\r\n";

static time_t start_time;
static time_t pop_statio_time = 0;
static ev_timer* log_watcher = NULL;
static ev_io** accept_watchers;
static struct ev_loop* statio_loop = NULL;
static int* lsocks;
static unsigned num_lsocks;
static bool* lsocks_bound;
static unsigned num_conn_watchers = 0;
static unsigned data_buffer_size = 0;
static unsigned hdr_buffer_size = 0;
static unsigned max_http_clients;
static unsigned http_timeout;
static unsigned num_dns_threads;

// This is memset to zero and re-accumulated for every output
static statio_t statio;

// Requests that specify ?f=1 (f for flush) only get the delta since
//  the last ?f=1 (or daemon start, whichever is more recent).
// All ?f=1 clients share one state, so don't have two independent ones!
static statio_t flush_hist; // copy of raw stats accum from last f=1

// coordination for final stats output
static ev_async* final_stats_async = NULL;
static pthread_mutex_t final_stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t final_stats_cond = PTHREAD_COND_INITIALIZER;
static bool final_stats_done = false;

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

static void populate_stats(const bool flush) {
    const time_t now = time(NULL);
    if(gcfg->realtime_stats || now > pop_statio_time) {
        memset(&statio, 0, sizeof(statio));

        for(unsigned i = 0; i < num_dns_threads; i++)
            accumulate_statio(i);
        pop_statio_time = now;
        if(flush) {
            // save past history to tmp_hist
            statio_t tmp_hist;
            memcpy(&tmp_hist, &flush_hist, sizeof(tmp_hist));
            // save new values to flush_hist for next time
            memcpy(&flush_hist, &statio, sizeof(flush_hist));
            // subtract past history from current counters for output
            statio.udp_recvfail       -= tmp_hist.udp_recvfail;
            statio.udp_sendfail       -= tmp_hist.udp_sendfail;
            statio.udp_tc             -= tmp_hist.udp_tc;
            statio.udp_edns_big       -= tmp_hist.udp_edns_big;
            statio.udp_edns_tc        -= tmp_hist.udp_edns_tc;
            statio.tcp_recvfail       -= tmp_hist.tcp_recvfail;
            statio.tcp_sendfail       -= tmp_hist.tcp_sendfail;
            statio.dns_noerror        -= tmp_hist.dns_noerror;
            statio.dns_refused        -= tmp_hist.dns_refused;
            statio.dns_nxdomain       -= tmp_hist.dns_nxdomain;
            statio.dns_notimp         -= tmp_hist.dns_notimp;
            statio.dns_badvers        -= tmp_hist.dns_badvers;
            statio.dns_formerr        -= tmp_hist.dns_formerr;
            statio.dns_dropped        -= tmp_hist.dns_dropped;
            statio.dns_v6             -= tmp_hist.dns_v6;
            statio.dns_edns           -= tmp_hist.dns_edns;
            statio.dns_edns_clientsub -= tmp_hist.dns_edns_clientsub;
            statio.udp_reqs           -= tmp_hist.udp_reqs;
            statio.tcp_reqs           -= tmp_hist.tcp_reqs;
        }
    }
    dmn_assert(pop_statio_time >= start_time);
}

static uint64_t get_uptime_u64(void) {
    dmn_assert(pop_statio_time >= start_time);
    return (uint64_t)pop_statio_time - (uint64_t)start_time;
}

#define IVAL_BUFSZ 16
static char ival_buf[IVAL_BUFSZ];
static const char* fmt_uptime(void) {
    dmn_assert(pop_statio_time >= start_time);
    const uint64_t interval = get_uptime_u64();
    const double dinterval = interval;

    if(interval < 128)      // 2m 8s
        snprintf(ival_buf, IVAL_BUFSZ, "%u secs", (unsigned)interval);
    else if(interval < 7680)     // 2h 8m
        snprintf(ival_buf, IVAL_BUFSZ, "~ %.1f mins", dinterval / 60.0);
    else if(interval < 180000)   // 50h
        snprintf(ival_buf, IVAL_BUFSZ, "~ %.1f hours", dinterval / 3600.0);
    else if(interval < 1209600)  // 14d
        snprintf(ival_buf, IVAL_BUFSZ, "~ %.1f days", dinterval / 86400.0);
    else if(interval < 7776000)  // 90d
        snprintf(ival_buf, IVAL_BUFSZ, "~ %.1f weeks", dinterval / 604800.0);
    else if(interval < 52560057) // ~20 months
        snprintf(ival_buf, IVAL_BUFSZ, "~ %.1f months", dinterval / 2622240.0);
    else
        snprintf(ival_buf, IVAL_BUFSZ, "~ %.1f years", dinterval / 31536000.0);

    return ival_buf;
}

static void statio_log_stats(void) {
    populate_stats(false);
    log_info(log_dns, statio.dns_noerror, statio.dns_refused, statio.dns_nxdomain, statio.dns_notimp, statio.dns_badvers, statio.dns_formerr, statio.dns_dropped, statio.dns_v6, statio.dns_edns, statio.dns_edns_clientsub);
    log_info(log_udp, statio.udp_reqs, statio.udp_recvfail, statio.udp_sendfail, statio.udp_tc, statio.udp_edns_big, statio.udp_edns_tc);
    log_info(log_tcp, statio.tcp_reqs, statio.tcp_recvfail, statio.tcp_sendfail);
}

F_NONNULL
static void statio_fill_outbuf_csv(struct iovec* outbufs, const bool flush) {
    populate_stats(flush);

    int snp_rv = snprintf(outbufs[1].iov_base, data_buffer_size, csv_fixed, get_uptime_u64(), statio.dns_noerror, statio.dns_refused, statio.dns_nxdomain, statio.dns_notimp, statio.dns_badvers, statio.dns_formerr, statio.dns_dropped, statio.dns_v6, statio.dns_edns, statio.dns_edns_clientsub, statio.udp_reqs, statio.udp_recvfail, statio.udp_sendfail, statio.udp_tc, statio.udp_edns_big, statio.udp_edns_tc, statio.tcp_reqs, statio.tcp_recvfail, statio.tcp_sendfail);
    dmn_assert(snp_rv > 0);
    outbufs[1].iov_len = (unsigned)snp_rv;
    outbufs[1].iov_len += gdnsd_mon_stats_out_csv(ADDVOID(outbufs[1].iov_base, outbufs[1].iov_len));

    snp_rv = snprintf(outbufs[0].iov_base, hdr_buffer_size, http_headers, "text/plain", (unsigned)outbufs[1].iov_len);
    dmn_assert(snp_rv > 0);
    outbufs[0].iov_len = (unsigned)snp_rv;
}

F_NONNULL
static void statio_fill_outbuf_json(struct iovec* outbufs, const bool flush) {
    populate_stats(flush);

    dmn_assert(pop_statio_time >= start_time);

    int snp_rv = snprintf(outbufs[1].iov_base, data_buffer_size, json_fixed, get_uptime_u64(), statio.dns_noerror, statio.dns_refused, statio.dns_nxdomain, statio.dns_notimp, statio.dns_badvers, statio.dns_formerr, statio.dns_dropped, statio.dns_v6, statio.dns_edns, statio.dns_edns_clientsub, statio.udp_reqs, statio.udp_recvfail, statio.udp_sendfail, statio.udp_tc, statio.udp_edns_big, statio.udp_edns_tc, statio.tcp_reqs, statio.tcp_recvfail, statio.tcp_sendfail);
    dmn_assert(snp_rv > 0);
    outbufs[1].iov_len = (unsigned)snp_rv;
    outbufs[1].iov_len += gdnsd_mon_stats_out_json(ADDVOID(outbufs[1].iov_base, outbufs[1].iov_len));
    memcpy(ADDVOID(outbufs[1].iov_base, outbufs[1].iov_len), json_footer, sizeof(json_footer) - 1U);
    outbufs[1].iov_len += (sizeof(json_footer) - 1U);

    snp_rv = snprintf(outbufs[0].iov_base, hdr_buffer_size, http_headers, "application/json", (unsigned)outbufs[1].iov_len);
    dmn_assert(snp_rv > 0);
    outbufs[0].iov_len = (unsigned)snp_rv;
}

F_NONNULL
static void statio_fill_outbuf_html(struct iovec* outbufs, const bool flush) {
    populate_stats(flush);

    struct tm now_tm;
    if(!gmtime_r(&pop_statio_time, &now_tm))
        log_fatal("gmtime_r() failed");

    char now_char[64];
    if(!strftime(now_char, 63, "%a %b %e %T %Y", &now_tm))
        log_fatal("strftime() failed");

    int snp_rv = snprintf(outbufs[1].iov_base, data_buffer_size, html_fixed, now_char, fmt_uptime(), statio.dns_noerror, statio.dns_refused, statio.dns_nxdomain, statio.dns_notimp, statio.dns_badvers, statio.dns_formerr, statio.dns_dropped, statio.dns_v6, statio.dns_edns, statio.dns_edns_clientsub, statio.udp_reqs, statio.udp_recvfail, statio.udp_sendfail, statio.udp_tc, statio.udp_edns_big, statio.udp_edns_tc, statio.tcp_reqs, statio.tcp_recvfail, statio.tcp_sendfail);
    dmn_assert(snp_rv > 0);
    outbufs[1].iov_len = (unsigned)snp_rv;
    outbufs[1].iov_len += gdnsd_mon_stats_out_html(ADDVOID(outbufs[1].iov_base, outbufs[1].iov_len));
    memcpy(ADDVOID(outbufs[1].iov_base, outbufs[1].iov_len), html_footer, sizeof(html_footer) - 1U);
    outbufs[1].iov_len += (sizeof(html_footer) - 1U);

    snp_rv = snprintf(outbufs[0].iov_base, hdr_buffer_size, http_headers, "application/xhtml+xml", (unsigned)outbufs[1].iov_len);
    dmn_assert(snp_rv > 0);
    outbufs[0].iov_len = (unsigned)snp_rv;
}

// Could be merged to a single iov, but this keeps things
//  "simple", so that the write code always expects to start
//  out with two iovecs to send.
F_NONNULL
static void statio_fill_outbuf_404(struct iovec* outbufs) {
    outbufs[0].iov_len = sizeof(http_404_hdr) - 1;
    outbufs[1].iov_len = sizeof(http_404_data) - 1;
    // iov_base=const hack
    memcpy(&outbufs[0].iov_base, &http_404_hdr[0], sizeof(void*));
    memcpy(&outbufs[1].iov_base, &http_404_data[0], sizeof(void*));
}

F_NONNULL
static void log_watcher_cb(struct ev_loop* loop V_UNUSED, ev_timer* t V_UNUSED, int revents V_UNUSED) {
    statio_log_stats();
}

typedef void (*ob_cb_t)(struct iovec*, const bool);

static struct {
    const char* match;
    const ob_cb_t func;
} http_lookup[]
= {
    // if one match is another's leading substring, the longer
    //   one must come first in the list!
    { "GET /json",     statio_fill_outbuf_json },
    { "GET /csv",      statio_fill_outbuf_csv  },
    { "GET /html",     statio_fill_outbuf_html },
    { "GET /",         statio_fill_outbuf_html },
};

static const unsigned n_http_lookup = ARRAY_SIZE(http_lookup);

// This still doesn't even remotely come close to properly parsing
//   the request, but it does handle a few basic things, and should
//   be enough to work for these purposes for now.  The "f=1" query
//   param must be the first.
F_NONNULL
static void process_http_query(char* inbuffer, struct iovec* outbufs) {
    bool matched = false;
    for(unsigned i = 0; i < n_http_lookup; i++) {
        const unsigned msize = strlen(http_lookup[i].match);
        dmn_assert(msize + 5 <= HTTP_READ_BYTES); // match + "/?f=1"
        if(!memcmp(inbuffer, http_lookup[i].match, msize)) {
            const char* trailptr = &inbuffer[msize];
            // allow for trailing slash, e.g. "GET /csv/ HTTP/1.0"
            if(*trailptr == '/')
                trailptr++;
            // require termination of the name with space, query, or frag
            if(strchr(" ?#", *trailptr)) {
                // check for f=1 only as first query arg
                const bool flush = !memcmp(trailptr, "?f=1", 4);
                http_lookup[i].func(outbufs, flush);
                matched = true;
            }
            break;
        }
    }

    if(!matched)
        statio_fill_outbuf_404(outbufs);
}

F_NONNULL
static void cleanup_conn_watchers(struct ev_loop* loop, http_data_t* tdata) {
    shutdown(tdata->read_watcher->fd, SHUT_RDWR);
    close(tdata->read_watcher->fd);
    ev_timer_stop(loop, tdata->timeout_watcher);
    ev_io_stop(loop, tdata->read_watcher);
    ev_io_stop(loop, tdata->write_watcher);
    free(tdata->data_buf);
    free(tdata->hdr_buf);
    free(tdata->timeout_watcher);
    free(tdata->read_watcher);
    free(tdata->write_watcher);
    free(tdata->asin);

    if((num_conn_watchers-- == max_http_clients))
        for(unsigned i = 0; i < num_lsocks; i++)
            ev_io_start(loop, accept_watchers[i]);

    free(tdata);
}

F_NONNULL
static void timeout_cb(struct ev_loop* loop V_UNUSED, ev_timer* t, const int revents V_UNUSED) {
    http_data_t* tdata = t->data;
    log_debug("HTTP connection timed out while %s %s",
        tdata->state == READING_REQ
            ? "reading from"
            : tdata->state == WRITING_RES
                ? "writing to"
                : "lingering with",
        dmn_logf_anysin(tdata->asin));

    cleanup_conn_watchers(loop, tdata);
}

F_NONNULL
static void write_cb(struct ev_loop* loop, ev_io* io, const int revents V_UNUSED) {
    dmn_assert(revents == EV_WRITE);

    http_data_t* tdata = io->data;
    struct iovec* iovs = tdata->outbufs;

    struct iovec* iovs_writev;
    int iovcnt_writev;
    if(iovs[0].iov_len) {
        iovs_writev = &iovs[0];
        iovcnt_writev = 2;
    }
    else {
        iovs_writev = &iovs[1];
        iovcnt_writev = 1;
    }
    const ssize_t write_rv = writev(io->fd, iovs_writev, iovcnt_writev);

    if(unlikely(write_rv < 0)) {
        if(!ERRNO_WOULDBLOCK && errno != EINTR) {
            log_debug("HTTP writev() failed (%s), dropping response to %s", dmn_logf_errno(), dmn_logf_anysin(tdata->asin));
            cleanup_conn_watchers(loop, tdata);
        }
        return;
    }

    size_t written = (size_t)write_rv;

    if(iovs[0].iov_len) {
        if(written >= iovs[0].iov_len) {
            written -= iovs[0].iov_len;
            iovs[0].iov_len = 0;
            // fall through to processing 2nd buffer below
        }
        else {
            iovs[0].iov_base = (char*)iovs[0].iov_base + written;
            iovs[0].iov_len -= written;
            return; // we'll send the rest of iovs[0]+iovs[1] on next EV_WRITE
        }
    }

    if(written < iovs[1].iov_len) {
        iovs[1].iov_base = (char*)iovs[1].iov_base + written;
        iovs[1].iov_len -= written;
        return; // we'll send the rest of iovs[1] on next EV_WRITE
    }

    dmn_assert(written == iovs[1].iov_len);
    tdata->state = READING_JUNK;
    ev_io_stop(loop, tdata->write_watcher);
    ev_io_start(loop, tdata->read_watcher);
}

F_NONNULL
static void read_cb(struct ev_loop* loop, ev_io* io, const int revents V_UNUSED) {
    dmn_assert(revents == EV_READ);
    http_data_t* tdata = io->data;

    dmn_assert(tdata);
    dmn_assert(tdata->state != WRITING_RES);

    if(tdata->state == READING_JUNK) {
        const ssize_t recv_rv = recv(io->fd, junk_buffer, JUNK_SIZE, 0);
        if(unlikely(recv_rv < 0)) {
            if(ERRNO_WOULDBLOCK || errno == EINTR)
                return;
            log_debug("HTTP recv() error (lingering) from %s: %s", dmn_logf_anysin(tdata->asin), dmn_logf_errno());
        }
        if(recv_rv < 1)
            cleanup_conn_watchers(loop, tdata);
        return;
    }

    dmn_assert(tdata->state == READING_REQ);
    dmn_assert(tdata->read_done < HTTP_READ_BYTES);
    char* destination = &tdata->read_buffer[tdata->read_done];
    const size_t wanted = HTTP_READ_BYTES - tdata->read_done;
    const ssize_t recv_rv = recv(io->fd, destination, wanted, 0);
    if(unlikely(recv_rv < 0)) {
        if(!ERRNO_WOULDBLOCK && errno != EINTR) {
            log_debug("HTTP recv() error from %s: %s", dmn_logf_anysin(tdata->asin), dmn_logf_errno());
            cleanup_conn_watchers(loop, tdata);
        }
        return;
    }
    const size_t recvlen = (size_t)recv_rv;
    tdata->read_done += recvlen;
    if(tdata->read_done < HTTP_READ_BYTES) return;

    // We're relying on the OS to buffer the rest of the request while
    //  we write the response.  After we're done writing we'll drain
    //  the rest of it for a proper lingering close.

    process_http_query(tdata->read_buffer, tdata->outbufs);
    tdata->state = WRITING_RES;
    ev_io_stop(loop, tdata->read_watcher);
    ev_io_start(loop, tdata->write_watcher);
}

F_NONNULL
static void accept_cb(struct ev_loop* loop, ev_io* io, int revents V_UNUSED) {
    dmn_assert(revents == EV_READ);

    dmn_anysin_t* asin = xmalloc(sizeof(dmn_anysin_t));
    asin->len = DMN_ANYSIN_MAXLEN;

    const int sock = accept(io->fd, &asin->sa, &asin->len);

    if(unlikely(sock < 0)) {
        free(asin);
        switch(errno) {
            case EAGAIN:
#if EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
            case EINTR:
                break;
#ifdef ENONET
            case ENONET:
#endif
            case ENETDOWN:
#ifdef EPROTO
            case EPROTO:
#endif
            case EHOSTDOWN:
            case EHOSTUNREACH:
            case ENETUNREACH:
                log_debug("HTTP: early tcp socket death: %s", dmn_logf_errno());
                break;
            default:
                log_err("HTTP: accept() error: %s", dmn_logf_errno());
        }
        return;
    }

    log_debug("HTTP: Received connection from %s", dmn_logf_anysin(asin));

    if(fcntl(sock, F_SETFL, (fcntl(sock, F_GETFL, 0)) | O_NONBLOCK) == -1) {
        free(asin);
        close(sock);
        log_err("Failed to set O_NONBLOCK on inbound HTTP socket: %s", dmn_logf_errno());
        return;
    }

    ev_io* read_watcher = xmalloc(sizeof(ev_io));
    ev_io* write_watcher = xmalloc(sizeof(ev_io));
    ev_timer* timeout_watcher = xmalloc(sizeof(ev_timer));

    http_data_t* tdata = xcalloc(1, sizeof(http_data_t));
    tdata->state = READING_REQ;
    tdata->asin = asin;
    tdata->read_watcher = read_watcher;
    tdata->write_watcher = write_watcher;
    tdata->timeout_watcher = timeout_watcher;

    tdata->hdr_buf = tdata->outbufs[0].iov_base = xmalloc(hdr_buffer_size);
    tdata->data_buf = tdata->outbufs[1].iov_base = xmalloc(data_buffer_size);

    read_watcher->data = tdata;
    write_watcher->data = tdata;
    timeout_watcher->data = tdata;

    ev_io_init(tdata->write_watcher, write_cb, sock, EV_WRITE);
    ev_set_priority(tdata->write_watcher, 1);

    ev_io_init(read_watcher, read_cb, sock, EV_READ);
    ev_set_priority(read_watcher, 0);
    ev_io_start(loop, read_watcher);

    ev_timer_init(timeout_watcher, timeout_cb, http_timeout, 0);
    ev_set_priority(timeout_watcher, -1);
    ev_timer_start(loop, timeout_watcher);

    if((++num_conn_watchers == max_http_clients)) {
        log_warn("Stats HTTP connection limit reached");
        for(unsigned i = 0; i < num_lsocks; i++)
            ev_io_stop(loop, accept_watchers[i]);
    }

#ifdef TCP_DEFER_ACCEPT
    // Since we use DEFER_ACCEPT, the request is likely already
    //  queued and available at this point, so start read()-ing
    //  without going through the event loop
    ev_invoke(loop, read_watcher, EV_READ);
#endif
}

void statio_init(const socks_cfg_t* socks_cfg) {
    start_time = time(NULL);

    // initial flush history
    memset(&flush_hist, 0, sizeof(flush_hist));

    // the junk buffer
    junk_buffer = xmalloc(JUNK_SIZE);

    // The largest our output sizes can possibly be:
    hdr_buffer_size =
        (sizeof(http_headers) - 1)      // http_headers format string
        + (21 - 2)                      // "application/xhtml+xml" - "%s"
        + (10 - 2);                     // 32-bit len - "%u"

    // stats counters are 32-bit on 32-bit machines, and 64 on 64
    const unsigned stat_len = sizeof(stats_uint_t) == 8 ? 20 : 10;

    // in the other cases, html is obviously-bigger, but if I have
    //  to count it out to know, may as well automated it...
    const unsigned fixed = sizeof(html_fixed) > sizeof(json_fixed)
        ? sizeof(html_fixed) - 1
        : sizeof(json_fixed) - 1;

    data_buffer_size =
        fixed                                 // html_fixed format string
        + (63 - 2)                            // max strftime output - 2 for the original %s
        + (IVAL_BUFSZ - 2)                    // max fmt_uptime output, again - 2 for %s
        + (19 * (stat_len - strlen(PRIuPTR))) // 19 stats, up to 20 bytes long each
        + gdnsd_mon_stats_get_max_len()       // whatever mon.c tells us...
        + (sizeof(html_footer) - 1);          // html_footer fixed string

    // double it, because it's not that big and this gives us a lot of headroom for
    //   having made any stupid mistakes in the max len calcuations :P
    data_buffer_size <<= 1U;

    // now set up the normal stuff, like libev event watchers
    if(gcfg->log_stats) {
        log_watcher = xmalloc(sizeof(ev_timer));
        ev_timer_init(log_watcher, log_watcher_cb, gcfg->log_stats, gcfg->log_stats);
        ev_set_priority(log_watcher, -2);
    }

    num_lsocks = socks_cfg->num_http_addrs;
    max_http_clients = socks_cfg->max_http_clients;
    http_timeout = socks_cfg->http_timeout;
    num_dns_threads = socks_cfg->num_dns_threads;
    lsocks = xmalloc(sizeof(int) * num_lsocks);
    lsocks_bound = xcalloc(num_lsocks, sizeof(bool));
    accept_watchers = xmalloc(sizeof(ev_io*) * num_lsocks);

    for(unsigned i = 0; i < num_lsocks; i++) {
        const dmn_anysin_t* asin = &socks_cfg->http_addrs[i];
        lsocks[i] = tcp_listen_pre_setup(asin, socks_cfg->http_timeout);
    }
}

void statio_bind_socks(void) {
    for(unsigned i = 0; i < num_lsocks; i++)
        if(!lsocks_bound[i])
            if(!socks_helper_bind("TCP stats", lsocks[i], &scfg->http_addrs[i], false))
                lsocks_bound[i] = true;
}

bool statio_check_socks(const socks_cfg_t* socks_cfg, bool soft) {
    unsigned rv = false;
    for(unsigned i = 0; i < num_lsocks; i++)
        if(!socks_sock_is_bound_to(lsocks[i], &socks_cfg->http_addrs[i]) && !soft)
            log_fatal("Failed to bind() stats TCP socket to %s", dmn_logf_anysin(&socks_cfg->http_addrs[i]));
        else
            rv = true;
    return rv;
}

// called within our thread/loop to do the final stats output
F_NONNULL
static void final_stats_cb(struct ev_loop* loop, ev_async* w V_UNUSED, int revents V_UNUSED) {
    // stop further periodic log output and do final output
    if(log_watcher)
        ev_timer_stop(loop, log_watcher);
    statio_log_stats();

    // let mainthread return from statio_final_stats_wait()
    pthread_mutex_lock(&final_stats_mutex);
    final_stats_done = true;
    pthread_cond_signal(&final_stats_cond);
    pthread_mutex_unlock(&final_stats_mutex);
}

// called from main thread to feed ev_async for final stats
void statio_final_stats(void) {
    dmn_assert(statio_loop); dmn_assert(final_stats_async);
    ev_async_send(statio_loop, final_stats_async);
}

// called from main thread to wait on final_stats_cb() completion
void statio_final_stats_wait(void) {
    pthread_mutex_lock(&final_stats_mutex);
    while(!final_stats_done)
        pthread_cond_wait(&final_stats_cond, &final_stats_mutex);
    pthread_mutex_unlock(&final_stats_mutex);
}

void statio_start(struct ev_loop* statio_loop_arg, const socks_cfg_t* socks_cfg) {
    statio_loop = statio_loop_arg;
    if(log_watcher)
        ev_timer_start(statio_loop, log_watcher);

    final_stats_async = xmalloc(sizeof(ev_async));
    ev_async_init(final_stats_async, final_stats_cb);
    ev_async_start(statio_loop, final_stats_async);

    for(unsigned i = 0; i < num_lsocks; i++) {
        if(listen(lsocks[i], 128) == -1)
            log_fatal("Failed to listen(s, %i) on stats TCP socket %s: %s", 128, dmn_logf_anysin(&socks_cfg->http_addrs[i]), dmn_logf_errno());
        accept_watchers[i] = xmalloc(sizeof(ev_io));
        ev_io_init(accept_watchers[i], accept_cb, lsocks[i], EV_READ);
        ev_set_priority(accept_watchers[i], -2);
        ev_io_start(statio_loop, accept_watchers[i]);
    }
}
