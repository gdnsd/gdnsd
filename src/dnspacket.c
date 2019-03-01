/* Copyright © 2012 Brandon L Black <blblack@gmail.com> and Jay Reitz <jreitz@gmail.com>
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
#include "dnspacket.h"

#include "conf.h"
#include "socks.h"
#include "dnswire.h"
#include "ltree.h"
#include "chal.h"
#include "cookie.h"

#include "plugins/plugapi.h"
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/misc.h>
#include <gdnsd/rand.h>

#include <string.h>
#include <stddef.h>
#include <pthread.h>
#include <time.h>

#include <urcu-qsbr.h>

// Max number of compression targets we'll store info about, to avoid
// performance regression for crazy response packets.  Note there are separate
// targets per super-domain, e.g. storing targets for "www.example.com"
// consumes 3 entries.
#define COMPTARGETS_MAX 16U

// Fixed HINFO record with TTL=3600 for RFC 8482
static const char hinfo_for_any[] = "\0\015\0\01\0\0\016\020\0\011\07RFC8482";
#define hinfo_for_any_len sizeof(hinfo_for_any)

// Storage for general-purpose compression target info
typedef struct {
    const uint8_t* orig; // aliases original dname storage, starting at first label len (no compression in this copy)
    unsigned len; // the length of this dname (what would be in the first byte of a proper "dname" in ltree)
    unsigned offset; // where this named was stored in the packet (this & 0xC000 is our target if match)
} ctarget_t;


// EDNS Cookie-related states:
typedef struct {
    // Client sent COOKIE option, perhaps a malformed one
    bool recvd;

    // Client sent well-formed COOKIE option, and we will respond with one
    bool respond;

    // Client sent a full client+server cookie value that we recognize as one we issued
    bool valid;

    // Output cookie option data, if edns.cookie.respond
    uint8_t output[16U];
} cookie_t;

// Sub-struct of txn_t below for EDNS-related state at the per-transaction level
typedef struct {
    // dns source IP + optional EDNS client subnet info for plugins
    client_info_t client_info;

    // EDNS Client Subnet response mask.
    // Not valid/useful in DNS responses unless edns.respond_client_subnet is true
    // below, *and* the source mask was non-zero.
    // For static responses, this is set to zero by dnspacket.c
    // For dynamic responses, this is set from .ans_dyn{a,cname}.edns_client_mask,
    //   which is in turn defaulted to zero.
    unsigned client_scope_mask;

    // How many bytes the OPTRR will consume at the end of the packet
    unsigned out_bytes;

    // Whether this request had a valid EDNS optrr
    bool req_edns;

    // DO bit in edns, if edns used at all
    bool do_bit;

    // Client sent EDNS Client Subnet option, and we must respond with one
    bool respond_client_subnet;

    // If above is true, this records the original family value verbatim
    unsigned client_family;

    // Whether the query requested NSID *and* we have it configured
    bool respond_nsid;

    // Cookie-related states
    cookie_t cookie;
} edns_t;

// txn_t tracks various per-transaction state (the scope of a single
// process_dns_query execution from a dnsio caller), and is explicitly memset
// back to zero at the start of processing a fresh txn
typedef struct {
    // this is the packet buffer from the io code, this value is passed in and
    // set here at the start of every request
    uint8_t* packet;

    // RFC 8490 DSO state tracking, NULL in UDP case.  Like "packet" this is
    // passed in as a pointer on each request, overwriting this every time.
    dso_state_t* dso;

    // Max response size for this individual request, as determined
    //  by protocol type, expected edns output bytes at the end, and in the
    //  case of UDP, the EDNS max response size (if any).
    unsigned this_max_response;

    // The queried type.  Note that this gets switched internally to CNAME in
    // the case of queries which land on a CNAME RR.
    unsigned qtype;

    // The queried class.
    unsigned qclass;

    // Compression pointer to query name.  For most queries this remains set to
    // the fixed offset where the real query starts, but when chasing CNAME
    // pointers, we re-set this to point at the CNAME's target.
    unsigned qname_comp;

    // As above, but for the authority within the qname (zone/deleg start point)
    unsigned auth_comp;

    unsigned qdcount;
    unsigned ancount;
    unsigned nscount;
    unsigned arcount;
    unsigned cname_ancount;

    // The original query name input from the question is stored here,
    // normalized to lowercase, and in our "dname" format, which means
    // prefixing the wire version with an overall length byte.
    uint8_t lqname[256];

    // synthetic rrsets for DYNC
    ltree_rrset_t dync_synth_rrset;

    // needs room for 1x CNAME target
    uint8_t dync_store[256];

    // Compression targets, for the few cases where we do general-case compression
    unsigned ctarget_count;
    ctarget_t ctargets[COMPTARGETS_MAX];

    // EDNS-related states
    edns_t edns;
} txn_t;

// per-thread persistent context
struct dnsp_ctx {
    // stats reference for this thread, permanent from startup
    dnspacket_stats_t* stats;

    // used to pseudo-randomly rotate some RRsets (A, AAAA, and NS)
    gdnsd_rstate32_t rand_state;

    // allocated at startup, memset to zero before each callback
    dyn_result_t* dyn;

    // whether the thread using this context is a udp or tcp thread,
    // set permanently at startup
    bool is_udp;

    // Whether to use EDNS and DSO Padding in TCP responses (encrypted transport)
    bool tcp_pad;

    // For UDP, the configured maximum response size, set permanently at
    // startup based on the UDP address family and the max_response options.
    unsigned udp_edns_max;

    // TCP Keepalive / TCP DSO Inactivity: these are the same value in
    // different units (100ms units for the EDNS version, and 1ms units for the
    // DSO version).  Set at thread start, reset to zero if dnsp_ctx_grace() is
    // called on this structure, to adverise zeros to clients and ask them to
    // disconnect gracefully as we're shutting down.
    unsigned edns_tcp_keepalive;
    unsigned dso_inactivity;

    // The current transaction state
    txn_t txn;
};

static pthread_mutex_t stats_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t stats_init_cond = PTHREAD_COND_INITIALIZER;
static unsigned stats_initialized = 0;
static unsigned result_v6_offset = 0;

dnspacket_stats_t** dnspacket_stats;

// Allocates the array of pointers to stats structures, one per I/O thread
// Called from main thread before I/O threads are spawned.
void dnspacket_global_setup(const socks_cfg_t* socks_cfg)
{
    dnspacket_stats = xcalloc_n(socks_cfg->num_dns_threads, sizeof(*dnspacket_stats));
    result_v6_offset = gdnsd_result_get_v6_offset();
}

// Called from main thread after starting all of the I/O threads,
//  ensures they all finish allocating their stats and storing the pointers
//  into dnspacket_stats before allowing the main thread to continue.
void dnspacket_wait_stats(const socks_cfg_t* socks_cfg)
{
    const unsigned waitfor = socks_cfg->num_dns_threads;
    pthread_mutex_lock(&stats_init_mutex);
    while (stats_initialized < waitfor)
        pthread_cond_wait(&stats_init_cond, &stats_init_mutex);
    pthread_mutex_unlock(&stats_init_mutex);
}

static dnsp_ctx_t* dnspacket_ctx_init(dnspacket_stats_t** stats_out, const bool is_udp, const bool udp_is_ipv6, const bool tcp_pad, const unsigned tcp_timeout_secs)
{
    dnsp_ctx_t* ctx = xcalloc(sizeof(*ctx));
    if (udp_is_ipv6)
        gdnsd_assert(is_udp);
    if (tcp_pad)
        gdnsd_assert(!is_udp);
    if (tcp_timeout_secs)
        gdnsd_assert(!is_udp);

    gdnsd_rand32_init(&ctx->rand_state);
    ctx->is_udp = is_udp;
    ctx->udp_edns_max = udp_is_ipv6 ? gcfg->max_edns_response_v6 : gcfg->max_edns_response;
    ctx->tcp_pad = tcp_pad;
    ctx->edns_tcp_keepalive = tcp_timeout_secs * 10;
    ctx->dso_inactivity = tcp_timeout_secs * 1000;
    ctx->dyn = xmalloc(gdnsd_result_get_alloc());

    gdnsd_plugins_action_iothread_init();

    pthread_mutex_lock(&stats_init_mutex);
    ctx->stats = dnspacket_stats[stats_initialized++] = xcalloc(sizeof(*ctx->stats));
    ctx->stats->is_udp = is_udp;
    pthread_cond_signal(&stats_init_cond);
    pthread_mutex_unlock(&stats_init_mutex);

    *stats_out = ctx->stats;
    return ctx;
}

dnsp_ctx_t* dnspacket_ctx_init_udp(dnspacket_stats_t** stats_out, const bool is_ipv6)
{
    return dnspacket_ctx_init(stats_out, true, is_ipv6, false, 0);
}

dnsp_ctx_t* dnspacket_ctx_init_tcp(dnspacket_stats_t** stats_out, const bool pad, const unsigned timeout_secs)
{
    return dnspacket_ctx_init(stats_out, false, false, pad, timeout_secs);
}

void dnspacket_ctx_set_grace(dnsp_ctx_t* ctx)
{
    ctx->edns_tcp_keepalive = 0;
    ctx->dso_inactivity = 0;
}

void dnspacket_ctx_cleanup(dnsp_ctx_t* ctx)
{
    gdnsd_plugins_action_iothread_cleanup();

    free(ctx->dyn);
    free(ctx);
}

typedef enum {
    DECODE_IGNORE  = -4, // totally invalid packet (len < header len or QR-bit set in query) - NO RESPONSE PACKET
    // (^ also used for immediate connection abort in case of DSO session + edns keepalive)
    DECODE_FORMERR = -3, // slightly better but still invalid input, we return FORMERR
    DECODE_BADVERS = -2, // EDNS version higher than ours (0)
    DECODE_NOTIMP  = -1, // unsupported opcode or QUERY meta-type, we return NOTIMP
    DECODE_OK      =  0, // normal and valid, QUERY opcode
    DECODE_DSO     =  1, // DSO opcode, kicks out to special handling
} rcode_rv_t;

F_NONNULL
static rcode_rv_t handle_edns_client_subnet(edns_t* edns, unsigned opt_len, const uint8_t* opt_data)
{
    if (opt_len < 4) {
        log_devdebug("edns_client_subnet data too short (%u bytes)", opt_len);
        return DECODE_FORMERR;
    }

    const unsigned family = ntohs(gdnsd_get_una16(opt_data));
    opt_data += 2;
    const unsigned src_mask = *opt_data++;
    const unsigned scope_mask = *opt_data++;
    if (scope_mask) {
        log_devdebug("edns_client_subnet: non-zero scope mask in request: %u", scope_mask);
        return DECODE_FORMERR;
    }

    // Validate family and validate non-zero src_mask as appropriate
    if (family == 1U) { // IPv4
        if (src_mask > 32U) {
            log_devdebug("edns_client_subnet: invalid src_mask of %u for IPv4", src_mask);
            return DECODE_FORMERR;
        }
    } else if (family == 2U) { // IPv6
        if (src_mask > 128U) {
            log_devdebug("edns_client_subnet: invalid src_mask of %u for IPv6", src_mask);
            return DECODE_FORMERR;
        }
    } else {
        log_devdebug("edns_client_subnet has unknown family %u", family);
        return DECODE_FORMERR;
    }

    // There should be exactly enough address bytes to cover the provided source mask (possibly 0)
    const unsigned whole_bytes = src_mask >> 3;
    const unsigned trailing_bits = src_mask & 7;
    const unsigned addr_bytes = whole_bytes + (trailing_bits ? 1 : 0);
    if (opt_len != 4 + addr_bytes) {
        log_devdebug("edns_client_subnet: option length %u mismatches src_mask of %u", opt_len, src_mask);
        return DECODE_FORMERR;
    }

    // Also, we need to check that any unmasked trailing bits in the final
    // byte are explicitly set to zero
    if (trailing_bits) {
        const unsigned final_byte = opt_data[src_mask >> 3];
        const unsigned final_mask = ~(0xFFU << (8U - trailing_bits)) & 0xFFU;
        if (final_byte & final_mask) {
            log_devdebug("edns_client_subnet: non-zero bits beyond src_mask");
            return DECODE_FORMERR;
        }
    }

    // If we made it this far, the input data is completely-valid, and
    // should be used if the source mask is non-zero:
    if (src_mask) {
        if (family == 1U) { // IPv4
            edns->client_info.edns_client.sa.sa_family = AF_INET;
            memcpy(&edns->client_info.edns_client.sin4.sin_addr.s_addr, opt_data, addr_bytes);
        } else {
            gdnsd_assert(family == 2U); // IPv6
            edns->client_info.edns_client.sa.sa_family = AF_INET6;
            memcpy(edns->client_info.edns_client.sin6.sin6_addr.s6_addr, opt_data, addr_bytes);
        }
    }

    edns->out_bytes += (8 + addr_bytes); // leave room for response option
    edns->respond_client_subnet = true;
    edns->client_info.edns_client_mask = src_mask;
    edns->client_family = family; // copy family for output
    return DECODE_OK;
}

F_NONNULL
static rcode_rv_t handle_edns_cookie(dnsp_ctx_t* ctx, unsigned opt_len, const uint8_t* opt_data)
{
    ctx->txn.edns.cookie.recvd = true;
    // FORMERR if illegal data len, only legal lens are 8, or 16-40
    if (opt_len != 8U && (opt_len < 16U || opt_len > 40U)) {
        stats_own_inc(&ctx->stats->edns_cookie_formerr);
        return DECODE_FORMERR;
    }
    ctx->txn.edns.cookie.respond = true;
    ctx->txn.edns.out_bytes += 20U;
    ctx->txn.edns.cookie.valid = cookie_process(ctx->txn.edns.cookie.output, opt_data, &ctx->txn.edns.client_info.dns_source, opt_len);
    if (ctx->txn.edns.cookie.valid)
        stats_own_inc(&ctx->stats->edns_cookie_ok);
    else if (opt_len == 8U)
        stats_own_inc(&ctx->stats->edns_cookie_init);
    else
        stats_own_inc(&ctx->stats->edns_cookie_bad);
    return DECODE_OK;
}

F_NONNULL
static rcode_rv_t handle_edns_option(dnsp_ctx_t* ctx, unsigned opt_code, unsigned opt_len, const uint8_t* opt_data)
{
    gdnsd_assert(ctx->stats);

    rcode_rv_t rv = DECODE_OK;
    if (opt_code == EDNS_CLIENTSUB_OPTCODE) {
        if (gcfg->edns_client_subnet) {
            stats_own_inc(&ctx->stats->edns_clientsub);
            rv = handle_edns_client_subnet(&ctx->txn.edns, opt_len, opt_data);
        }
    } else if (opt_code == EDNS_NSID_OPTCODE) {
        if (!opt_len) {
            if (gcfg->nsid.len) {
                gdnsd_assert(gcfg->nsid.data);
                ctx->txn.edns.out_bytes += (4U + gcfg->nsid.len);
                ctx->txn.edns.respond_nsid = true;
            }
        } else {
            rv = DECODE_FORMERR; // nsid req MUST NOT have data
        }
    } else if (opt_code == EDNS_TCP_KEEPALIVE_OPTCODE) {
        // DSO Protoerr F: EDNS TCP Keepalive inside established DSO session
        if (!ctx->is_udp) {
            gdnsd_assert(ctx->txn.dso);
            if (ctx->txn.dso->estab) {
                log_devdebug("Got EDNS Keepalive during DSO session, Proto Err -> Conn Abort");
                stats_own_inc(&ctx->stats->tcp.dso_protoerr);
                rv = DECODE_IGNORE; // causes retval 0 to TCP, forcing conn abort
            }
        }
        // Otherwise we ignore the client values sent here since we always send
        // the response version of this when legal, with our own fixed values.
    } else if (opt_code == EDNS_PADDING) {
        // Ditto, we emit padding in response to any EDNS request over TCP when
        // tcp_pad is enabled, so we don't care what padding they did (or
        // didn't) send.
    } else if (opt_code == EDNS_COOKIE_OPTCODE) {
        // ignore any cookie after the first one, per RFC
        if (!gcfg->disable_cookies && !ctx->txn.edns.cookie.recvd)
            rv = handle_edns_cookie(ctx, opt_len, opt_data);
    } else {
        log_devdebug("Unknown EDNS option code: %x", opt_code);
    }

    return rv;
}

F_NONNULL
static rcode_rv_t handle_edns_options(dnsp_ctx_t* ctx, unsigned rdlen, const uint8_t* rdata)
{
    gdnsd_assert(rdlen);

    // minimum edns option length is 4 bytes (2 byte option code, 2 byte data len)
    do {
        if (rdlen < 4) {
            log_devdebug("EDNS option too short");
            return DECODE_FORMERR;
        }
        unsigned opt_code = ntohs(gdnsd_get_una16(rdata));
        rdata += 2;
        unsigned opt_dlen = ntohs(gdnsd_get_una16(rdata));
        rdata += 2;
        rdlen -= 4;
        if (opt_dlen > rdlen) {
            log_devdebug("EDNS option too long");
            return DECODE_FORMERR;
        }
        rcode_rv_t rv = handle_edns_option(ctx, opt_code, opt_dlen, rdata);
        if (rv != DECODE_OK)
            return rv;
        rdlen -= opt_dlen;
        rdata += opt_dlen;
    } while (rdlen);

    return DECODE_OK;
}

F_NONNULL
static rcode_rv_t parse_optrr(dnsp_ctx_t* ctx, unsigned* offset_ptr, const unsigned packet_len)
{
    gdnsd_assert(ctx->stats);

    uint8_t* packet = ctx->txn.packet;

    unsigned offset = *offset_ptr;
    // assumptions caller has checked for us:
    gdnsd_assert(offset + 11 <= packet_len); // enough bytes for minimal OPT RR
    gdnsd_assert(packet[offset] == '\0'); // root name
    gdnsd_assert(ntohs(gdnsd_get_una16(&packet[offset + 1])) == DNS_TYPE_OPT);

    // skip past the above and grab the other fields we need
    offset += 3;
    unsigned edns_maxsize = ntohs(gdnsd_get_una16(&packet[offset]));
    offset += 2;
    unsigned edns_extflags = ntohl(gdnsd_get_una32(&packet[offset]));
    offset += 4;
    unsigned edns_rdlen = ntohs(gdnsd_get_una16(&packet[offset]));
    offset += 2;

    rcode_rv_t rcode = DECODE_OK;
    ctx->txn.edns.req_edns = true;            // send OPT RR with response
    ctx->txn.edns.out_bytes = 11;

    stats_own_inc(&ctx->stats->edns);

    // DO-bit from extflags
    if (edns_extflags & 0x8000) {
        ctx->txn.edns.do_bit = true;
        stats_own_inc(&ctx->stats->edns_do);
    }

    // derive version from extflags
    const unsigned edns_version = (edns_extflags & 0xFF0000) >> 16;
    if (likely(edns_version == 0)) {
        if (likely(ctx->is_udp)) {
            if (edns_maxsize < 512U)
                edns_maxsize = 512U;
            ctx->txn.this_max_response = edns_maxsize < ctx->udp_edns_max
                                         ? edns_maxsize
                                         : ctx->udp_edns_max;
        } else if (!ctx->txn.dso->estab) {
            ctx->txn.edns.out_bytes += 6U; // tcp keepalive option space
        }

        if (edns_rdlen) {
            if (packet_len < offset + edns_rdlen) {
                log_devdebug("Received EDNS OPT RR with options data longer than packet length");
                rcode = DECODE_FORMERR;
            } else {
                rcode = handle_edns_options(ctx, edns_rdlen, &packet[offset]);
            }
            offset += edns_rdlen;
        }
    } else {
        log_devdebug("Received EDNS OPT RR with VERSION > 0 (BADVERSION)");
        rcode = DECODE_BADVERS;
    }

    if (rcode == DECODE_OK)
        *offset_ptr = offset;
    return rcode;
}

F_NONNULL
static bool parse_first_question(txn_t* txn, unsigned* offset_ptr, const unsigned packet_len)
{
    const unsigned len = packet_len - *offset_ptr;
    if (unlikely(!len))
        return true;

    const uint8_t* buf = &txn->packet[*offset_ptr];
    uint8_t* lqname_ptr = &txn->lqname[1];
    unsigned pos = 0;
    unsigned llen;
    while ((llen = *lqname_ptr++ = buf[pos++])) {
        if (unlikely(llen & 0xC0)) {
            log_devdebug("Label compression detected in question, failing.");
            return true;
        }

        if (unlikely(pos + llen >= len)) {
            log_devdebug("Query name truncated (runs off end of packet)");
            return true;
        }

        if (unlikely(pos + llen > 254)) {
            log_devdebug("Query domain name too long");
            return true;
        }

        while (llen--) {
            if (unlikely((buf[pos] < 0x5B) && (buf[pos] > 0x40)))
                *lqname_ptr++ = buf[pos++] | 0x20;
            else
                *lqname_ptr++ = buf[pos++];
        }
    }

    // Store the overall length of the lowercased name
    txn->lqname[0] = pos;

    if (likely(pos + 4 <= len)) {
        txn->qtype = ntohs(gdnsd_get_una16(&buf[pos]));
        pos += 2;
        txn->qclass = ntohs(gdnsd_get_una16(&buf[pos]));
        pos += 2;
    } else {
        log_devdebug("Packet length exhausted before parsing question type/class!");
        return true;
    }

    *offset_ptr += pos;
    gdnsd_assert(*offset_ptr <= packet_len);
    return false;
}

F_NONNULL
static unsigned parse_rr_name_minimal(const uint8_t* buf, unsigned len)
{
    gdnsd_assert(len);
    // input len is whole remaining buffer, so cap it to legal name length so
    // we can check both limits together.
    if (len > 255)
        len = 255;
    unsigned pos = 0;
    unsigned llen;
    while ((llen = buf[pos++])) {
        if (unlikely(llen & 0xC0)) {
            pos++;
            if (unlikely(pos >= len))
                return 0;
            return pos;
        }
        pos += llen;
        if (unlikely(pos >= len))
            return 0;
    }

    return pos;
}

F_NONNULL
static bool parse_rr_minimal(txn_t* txn, unsigned* offset_ptr, const unsigned packet_len, const bool has_data)
{
    const unsigned len = packet_len - *offset_ptr;
    if (unlikely(!len))
        return true;

    const uint8_t* buf = &txn->packet[*offset_ptr];
    unsigned pos = parse_rr_name_minimal(buf, len);
    if (unlikely(!pos))
        return true;

    if (has_data) {
        if (unlikely(pos + 10 > len)) // type/class/ttl/rdlen
            return true;
        pos += 8; // type/class/ttl
        const unsigned rdlen = ntohs(gdnsd_get_una16(&buf[pos]));
        pos += 2;
        pos += rdlen;
        if (unlikely(pos > len))
            return true;
    } else {
        if (unlikely(pos + 4 > len)) // type/class
            return true;
        pos += 4;
    }

    *offset_ptr += pos;
    gdnsd_assert(*offset_ptr <= packet_len);
    return false;
}

F_NONNULL
static rcode_rv_t parse_query_rrs(dnsp_ctx_t* ctx, unsigned* output_offset_ptr, const unsigned packet_len)
{
    gdnsd_assert(*output_offset_ptr == sizeof(wire_dns_header_t));
    gdnsd_assert(packet_len >= sizeof(wire_dns_header_t));

    const wire_dns_header_t* hdr = (const wire_dns_header_t*)ctx->txn.packet;
    unsigned offset = sizeof(wire_dns_header_t);

    gdnsd_assert(!ctx->txn.qdcount);

    const unsigned qdcount = DNSH_GET_QDCOUNT(hdr);
    const unsigned ancount = DNSH_GET_ANCOUNT(hdr);
    const unsigned nscount = DNSH_GET_NSCOUNT(hdr);
    const unsigned arcount = DNSH_GET_ARCOUNT(hdr);

    if (qdcount) {
        if (parse_first_question(&ctx->txn, &offset, packet_len))
            return DECODE_FORMERR;
        // If we can parse the first question, we'll include it in the
        // output, even if the rest below may result in some other error
        // response.  Note we don't currently reflect any additional questions
        // even if they parse correctly, because it's too burdensome on our
        // output sizing constraints.
        ctx->txn.qdcount = 1;
        *output_offset_ptr = offset;
    }

    for (unsigned i = 1; i < qdcount; i++)
        if (parse_rr_minimal(&ctx->txn, &offset, packet_len, false))
            return DECODE_FORMERR;

    for (unsigned i = 0; i < ancount; i++)
        if (parse_rr_minimal(&ctx->txn, &offset, packet_len, true))
            return DECODE_FORMERR;

    for (unsigned i = 0; i < nscount; i++)
        if (parse_rr_minimal(&ctx->txn, &offset, packet_len, true))
            return DECODE_FORMERR;

    bool seen_optrr = false;
    for (unsigned i = 0; i < arcount; i++) {
        if (likely(packet_len >= (offset + 11) && ctx->txn.packet[offset] == '\0'
                   && ntohs(gdnsd_get_una16(&ctx->txn.packet[offset + 1])) == DNS_TYPE_OPT)) {
            if (seen_optrr) // >1 OPT RRs
                return DECODE_FORMERR;
            seen_optrr = true;
            rcode_rv_t rc = parse_optrr(ctx, &offset, packet_len);
            if (rc != DECODE_OK)
                return rc;
            continue;
        }
        if (parse_rr_minimal(&ctx->txn, &offset, packet_len, true))
            return DECODE_FORMERR;
    }

    return DECODE_OK;
}

F_NONNULL
static rcode_rv_t decode_query(dnsp_ctx_t* ctx, unsigned* output_offset_ptr, const unsigned packet_len)
{
    gdnsd_assert(ctx->txn.packet);
    gdnsd_assert(*output_offset_ptr == sizeof(wire_dns_header_t));

    if (unlikely(packet_len < (sizeof(wire_dns_header_t)))) {
        log_devdebug("Ignoring short request of length %u", packet_len);
        return DECODE_IGNORE;
    }

    uint8_t* packet = ctx->txn.packet;
    const wire_dns_header_t* hdr = (const wire_dns_header_t*)packet;

    if (unlikely(DNSH_GET_QR(hdr))) {
        log_devdebug("QR bit set in query, ignoring");
        return DECODE_IGNORE;
    }

    // In all cases other than the 2 ignores above, we will do our best to
    // parse the query RRs, and always send some kind of response packet...
    rcode_rv_t rcode = parse_query_rrs(ctx, output_offset_ptr, packet_len);

    if (rcode != DECODE_OK)
        return rcode;

    const unsigned opcode = DNSH_GET_OPCODE(hdr);

    if (opcode == DNS_OPCODE_QUERY) {
        // We could FORMERR-reject QUERY operations here if they have trailing
        // junk beyond the parsed RRs, but we'll choose not to for now and just
        // ignore such data.  For other opcodes, whether any data after the
        // indicated RR counts is illegal or not depends on the opcode, so we'd
        // rather NOTIMP them.

        // Require exactly one question, except in the case that an EDNS cookie
        // was received, in which case that standard allows zero questions as a
        // cookie-refresh ping.
        const unsigned hdr_qdcount = DNSH_GET_QDCOUNT(hdr);
        if (unlikely(hdr_qdcount > 1U || (!hdr_qdcount && !ctx->txn.edns.cookie.recvd))) {
            log_devdebug("Received QUERY request with %hu questions, FORMERR", DNSH_GET_QDCOUNT(hdr));
            return DECODE_FORMERR;
        }

        if (unlikely(ctx->txn.qtype > 127 && ctx->txn.qtype < 255)) {
            // Range 128-255 is meta-query types, not data types.  We implement ANY
            // (255) in normal response process, but we do not implement any others
            // (e.g. IXFR, AXFR, MAILA, MAILB, TKEY, TSIG, etc).
            log_devdebug("Unsupported meta-query type %u (NOTIMP) attempted", ctx->txn.qtype);
            return DECODE_NOTIMP;
        }

        return DECODE_OK;
    }

    if (opcode == DNS_OPCODE_DSO && !gcfg->disable_tcp_dso)
        return DECODE_DSO;

    log_devdebug("NOTIMP: unsupported opcode %u", opcode);
    return DECODE_NOTIMP;
}

// Always first thing added, once we hit a situation where general compression is warranted
F_NONNULL
static void ctargets_add_qname(txn_t* txn)
{
    gdnsd_assert(!txn->ctarget_count);
    unsigned offset = sizeof(wire_dns_header_t);
    const uint8_t* orig = &txn->packet[offset];
    unsigned len = txn->lqname[0];
    // root is "." => "\0" => len==1 and is not worth compressing
    // next-shortest is "a." => "\1a\0" => len==3, and is worth compressing
    while (len > 2 && txn->ctarget_count < COMPTARGETS_MAX) {
        txn->ctargets[txn->ctarget_count].orig = orig;
        txn->ctargets[txn->ctarget_count].len = len;
        txn->ctargets[txn->ctarget_count].offset = offset;
        txn->ctarget_count++;
        const unsigned jump = *orig + 1U;
        orig += jump;
        offset += jump;
        len -= jump;
    }
}

// When it's necessary to store a dname into the packet, and compression
// against existing targets is desired, this is the function to call.
// "dname" should be straight from ltree
// "offset" is where the name (in possibly-compressed form) should be stored at.
// "make_targets" means use this name to create new compression targets for future invocations
static unsigned store_dname_comp(txn_t* txn, const uint8_t* dname, const unsigned offset, const bool make_targets)
{
    // most response types don't use general compression at all, so we only
    // initialize qname into the set on the first use of this per response
    if (!txn->ctarget_count)
        ctargets_add_qname(txn);

    const unsigned dn_full_len = *dname++; // dname now starts at first label len
    const uint8_t* dname_read = dname;
    unsigned dnread_len = dn_full_len;
    unsigned dnread_offset = offset;

    // Search for a match, take the first match found since they're pre-sorted by len
    for (unsigned i = 0; i < txn->ctarget_count; i++) {
        // So long as the target (longest remaining in sorted list) is shorter
        // than the input, we must iterate storing new names into the list
        while (txn->ctargets[i].len < dnread_len) {
            if (make_targets && txn->ctarget_count < COMPTARGETS_MAX) {
                gdnsd_assert(dnread_len > 2U); // implied by rest of the logic...
                unsigned to_move = txn->ctarget_count - i;
                memmove(txn->ctargets + i + 1U, txn->ctargets + i, to_move * sizeof(ctarget_t));
                txn->ctargets[i].orig = dname_read;
                txn->ctargets[i].len = dnread_len;
                txn->ctargets[i].offset = dnread_offset;
                i++;
                txn->ctarget_count++;
            }
            const unsigned jump = *dname_read + 1U;
            dname_read += jump;
            dnread_offset += jump;
            dnread_len -= jump;
        }

        if (txn->ctargets[i].len == dnread_len && !memcmp(dname_read, txn->ctargets[i].orig, dnread_len)) {
            // exact match!
            unsigned match_depth = dn_full_len - dnread_len;
            memcpy(&txn->packet[offset], dname, match_depth);
            gdnsd_put_una16(htons(0xC000u | txn->ctargets[i].offset), &txn->packet[offset + match_depth]);
            gdnsd_assert(!(txn->packet[txn->ctargets[i].offset] & 0xC0u)); // no ptr-to-ptr
            return match_depth + 2U;
        }

        // otherwise txn->ctargets[i].len is > dnread_len, or == dnread_len but no
        // match yet, so we iterate further in the sorted list to find a case
        // that triggers one of the above
    }

    // Target list exhausted without any match.
    // For the make_targets case, we may still have one or more new entries to
    // add to the txn.ctargets set, all at the end (<= len of shortest existing)
    if (make_targets) {
        while (dnread_len > 2U && txn->ctarget_count < COMPTARGETS_MAX) {
            txn->ctargets[txn->ctarget_count].orig = dname_read;
            txn->ctargets[txn->ctarget_count].len = dnread_len;
            txn->ctargets[txn->ctarget_count].offset = dnread_offset;
            txn->ctarget_count++;
            const unsigned jump = *dname_read + 1U;
            dname_read += jump;
            dnread_offset += jump;
            dnread_len -= jump;
        }
    }

    // store dname in full
    memcpy(&txn->packet[offset], dname, dn_full_len);
    return dn_full_len;
}

// store a dname without attempting compression-related things at all
F_NONNULL
static unsigned store_dname_nocomp(uint8_t* packet, const uint8_t* dn, const unsigned offset)
{
    const unsigned sz = *dn++;
    memcpy(&packet[offset], dn, sz);
    return sz;
}

// We know a given name was stored at packet+orig_offset already.  We
//  want to repeat it at packet+store_at_offset by using simple compression.
//  if the original is also compressed, copy the compression bytes instead of
//  creating a compression pointer-to-pointer scenario needlessly.  Note this
//  doesn't prevent 2-byte compression pointers pointing at 1-byte names (which
//  is the root of the DNS), which makes root zone responses slightly
//  less-efficient in some cases.  However, I doubt anyone's running a public
//  global root on gdnsd, and it will make other code simpler later if we can
//  assume all compressions are 2-byte results.
F_NONNULL
static unsigned repeat_name(uint8_t* packet, unsigned store_at_offset, unsigned orig_offset)
{
    unsigned rv = 2;

    if (packet[orig_offset]) {
        // Copy a compression start, or point at a non-compression start
        if (packet[orig_offset] & 0xC0)
            gdnsd_put_una16(gdnsd_get_una16(&packet[orig_offset]), &packet[store_at_offset]);
        else
            gdnsd_put_una16(htons(0xC000 | orig_offset), &packet[store_at_offset]);
    } else {
        // If orig is the root of DNS, no point compressing
        packet[store_at_offset] = 0;
        rv = 1;
    }

    return rv;
}

F_NONNULL
static unsigned enc_a_static(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_a_t* rrset, const unsigned nameptr, const bool is_addtl)
{
    gdnsd_assert(rrset->gen.count);

    uint8_t* packet = ctx->txn.packet;

    const unsigned total = rrset->gen.count;
    gdnsd_assert(total);

    if (is_addtl)
        ctx->txn.arcount += total;
    else
        ctx->txn.ancount += total;

    const uint32_t* addr_ptr = (total <= LTREE_V4A_SIZE)
                               ? &rrset->v4a[0]
                               : rrset->addrs;
    unsigned ct = total;
    unsigned i = gdnsd_rand32_bounded(&ctx->rand_state, total);
    while (ct--) {
        offset += repeat_name(packet, offset, nameptr);
        gdnsd_put_una32(DNS_RRFIXED_A, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 4;
        gdnsd_put_una16(htons(4), &packet[offset]);
        offset += 2;
        gdnsd_put_una32(addr_ptr[i], &packet[offset]);
        offset += 4;
        if (++i == total)
            i = 0;
    }
    return offset;
}

F_NONNULL
static unsigned enc_aaaa_static(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_aaaa_t* rrset, const unsigned nameptr, const bool is_addtl)
{
    gdnsd_assert(rrset->gen.count);

    uint8_t* packet = ctx->txn.packet;

    const unsigned total = rrset->gen.count;
    gdnsd_assert(total);

    if (is_addtl)
        ctx->txn.arcount += total;
    else
        ctx->txn.ancount += total;

    unsigned ct = total;
    unsigned i = gdnsd_rand32_bounded(&ctx->rand_state, total);
    while (ct--) {
        offset += repeat_name(packet, offset, nameptr);
        gdnsd_put_una32(DNS_RRFIXED_AAAA, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 4;
        gdnsd_put_una16(htons(16), &packet[offset]);
        offset += 2;
        memcpy(&packet[offset], rrset->addrs + (i << 4), 16);
        offset += 16;
        if (++i == total)
            i = 0;
    }
    return offset;
}

F_NONNULL
static unsigned enc_a_dynamic(dnsp_ctx_t* ctx, unsigned offset, const unsigned nameptr, const unsigned ttl)
{
    gdnsd_assert(ctx->txn.packet);

    uint8_t* packet = ctx->txn.packet;
    const dyn_result_t* dr = ctx->dyn;
    gdnsd_assert(!dr->is_cname);

    const unsigned total = dr->count_v4;
    gdnsd_assert(total);

    ctx->txn.ancount += total;

    unsigned ct = total;
    unsigned i = gdnsd_rand32_bounded(&ctx->rand_state, total);
    while (ct--) {
        offset += repeat_name(packet, offset, nameptr);
        gdnsd_put_una32(DNS_RRFIXED_A, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(ttl, &packet[offset]);
        offset += 4;
        gdnsd_put_una16(htons(4), &packet[offset]);
        offset += 2;
        gdnsd_put_una32(dr->v4[i], &packet[offset]);
        offset += 4;
        if (++i == total)
            i = 0;
    }
    return offset;
}

F_NONNULL
static unsigned enc_aaaa_dynamic(dnsp_ctx_t* ctx, unsigned offset, const unsigned nameptr, const unsigned ttl)
{
    gdnsd_assert(ctx->txn.packet);

    uint8_t* packet = ctx->txn.packet;
    const dyn_result_t* dr = ctx->dyn;
    gdnsd_assert(!dr->is_cname);

    const unsigned total = dr->count_v6;
    gdnsd_assert(total);

    ctx->txn.ancount += total;

    const uint8_t* v6 = &dr->storage[result_v6_offset];
    unsigned ct = total;
    unsigned i = gdnsd_rand32_bounded(&ctx->rand_state, total);
    while (ct--) {
        offset += repeat_name(packet, offset, nameptr);
        gdnsd_put_una32(DNS_RRFIXED_AAAA, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(ttl, &packet[offset]);
        offset += 4;
        gdnsd_put_una16(htons(16), &packet[offset]);
        offset += 2;
        memcpy(&packet[offset], &v6[i << 4], 16);
        offset += 16;
        if (++i == total)
            i = 0;
    }
    return offset;
}

// Invoke dyna callback for DYN[AC], taking care of zeroing
//   out ctx->dyn and cleaning up the ttl + scope_mask issues,
//   returning the TTL to actually use, in network order.
F_NONNULLX(1, 2)
static unsigned do_dyn_callback(dnsp_ctx_t* ctx, gdnsd_resolve_cb_t func, const unsigned res, const unsigned ttl_max_net, const unsigned ttl_min)
{
    dyn_result_t* dr = ctx->dyn;
    memset(dr, 0, sizeof(*dr));
    const gdnsd_sttl_t sttl = func(res, &ctx->txn.edns.client_info, dr);
    if (dr->edns_scope_mask > ctx->txn.edns.client_scope_mask)
        ctx->txn.edns.client_scope_mask = dr->edns_scope_mask;
    assert_valid_sttl(sttl);
    unsigned ttl = sttl & GDNSD_STTL_TTL_MASK;
    if (ttl > ntohl(ttl_max_net))
        ttl = ttl_max_net;
    else if (ttl < ttl_min)
        ttl = htonl(ttl_min);
    else
        ttl = htonl(ttl);
    return ttl;
}

F_NONNULL
static unsigned encode_rrs_a(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_a_t* rrset)
{
    gdnsd_assert(offset);
    gdnsd_assert(ctx->txn.qtype == DNS_TYPE_A);

    if (rrset->gen.count) {
        offset = enc_a_static(ctx, offset, rrset, ctx->txn.qname_comp, false);
    } else {
        const unsigned ttl = do_dyn_callback(ctx, rrset->dyn.func, rrset->dyn.resource, rrset->gen.ttl, rrset->dyn.ttl_min);
        gdnsd_assert(!ctx->dyn->is_cname);
        if (ctx->dyn->count_v4)
            offset = enc_a_dynamic(ctx, offset, ctx->txn.qname_comp, ttl);
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_aaaa(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_aaaa_t* rrset)
{
    gdnsd_assert(offset);
    gdnsd_assert(ctx->txn.qtype == DNS_TYPE_AAAA);

    if (rrset->gen.count) {
        offset = enc_aaaa_static(ctx, offset, rrset, ctx->txn.qname_comp, false);
    } else {
        const unsigned ttl = do_dyn_callback(ctx, rrset->dyn.func, rrset->dyn.resource, rrset->gen.ttl, rrset->dyn.ttl_min);
        gdnsd_assert(!ctx->dyn->is_cname);
        if (ctx->dyn->count_v6)
            offset = enc_aaaa_dynamic(ctx, offset, ctx->txn.qname_comp, ttl);
    }

    return offset;
}

// This is only used when qtype == NS and the qname doesn't land in a
// delegation cut, which implies it only gets called for explicit output of NS
// records at a zone root.  ltree doesn't currently allow these to have glue.
F_NONNULL
static unsigned encode_rrs_ns(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_ns_t* rrset)
{
    gdnsd_assert(offset);
    gdnsd_assert(rrset->gen.count); // we never call encode_rrs_ns without an NS record present

    uint8_t* packet = ctx->txn.packet;

    const unsigned rrct = rrset->gen.count;
    gdnsd_assert(rrct <= MAX_NS_COUNT);
    ctx->txn.ancount += rrct;
    for (unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(packet, offset, ctx->txn.qname_comp);
        gdnsd_put_una32(DNS_RRFIXED_NS, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;
        const unsigned newlen = store_dname_comp(&ctx->txn, rrset->rdata[i].dname, offset, true);
        gdnsd_put_una16(htons(newlen), &packet[offset - 2]);
        gdnsd_assert(!rrset->rdata[i].glue_v4 && !rrset->rdata[i].glue_v6);
        offset += newlen;
    }

    return offset;
}

// This is called for all delegation outputs, which may have glue from
// addresses inside (possibly a different) delegation or defined as explicit
// out-of-zone glue
F_NONNULL
static unsigned encode_rrs_ns_deleg(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_ns_t* rrset)
{
    gdnsd_assert(offset);
    gdnsd_assert(rrset->gen.count); // we never call encode_rrs_ns without an NS record present

    uint16_t glue_name_offset[MAX_NS_COUNT];

    uint8_t* packet = ctx->txn.packet;

    const unsigned rrct = rrset->gen.count;
    gdnsd_assert(rrct <= MAX_NS_COUNT);
    ctx->txn.nscount += rrct;
    for (unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(packet, offset, ctx->txn.auth_comp);
        gdnsd_put_una32(DNS_RRFIXED_NS, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;
        const unsigned newlen = store_dname_comp(&ctx->txn, rrset->rdata[i].dname, offset, true);
        gdnsd_put_una16(htons(newlen), &packet[offset - 2]);
        glue_name_offset[i] = offset;
        offset += newlen;
    }

    for (unsigned i = 0; i < rrct; i++) {
        ltree_rrset_a_t* glue_v4 = rrset->rdata[i].glue_v4;
        if (glue_v4) {
            gdnsd_assert(glue_v4->gen.count);
            offset = enc_a_static(ctx, offset, glue_v4, glue_name_offset[i], true);
        }
        ltree_rrset_aaaa_t* glue_v6 = rrset->rdata[i].glue_v6;
        if (glue_v6) {
            gdnsd_assert(glue_v6->gen.count);
            offset = enc_aaaa_static(ctx, offset, glue_v6, glue_name_offset[i], true);
        }
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_ptr(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_ptr_t* rrset)
{
    gdnsd_assert(ctx->txn.packet);
    gdnsd_assert(offset);

    uint8_t* packet = ctx->txn.packet;

    const unsigned rrct = rrset->gen.count;
    ctx->txn.ancount += rrct;
    for (unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(packet, offset, ctx->txn.qname_comp);
        gdnsd_put_una32(DNS_RRFIXED_PTR, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;
        const unsigned newlen = store_dname_nocomp(packet, rrset->rdata[i], offset);
        gdnsd_put_una16(htons(newlen), &packet[offset - 2]);
        offset += newlen;
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_mx(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_mx_t* rrset)
{
    gdnsd_assert(ctx->txn.packet);
    gdnsd_assert(offset);

    uint8_t* packet = ctx->txn.packet;

    const unsigned rrct = rrset->gen.count;
    ctx->txn.ancount += rrct;
    for (unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(packet, offset, ctx->txn.qname_comp);
        gdnsd_put_una32(DNS_RRFIXED_MX, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;
        const ltree_rdata_mx_t* rd = &rrset->rdata[i];
        gdnsd_put_una16(rd->pref, &packet[offset]);
        offset += 2;
        const unsigned newlen = store_dname_comp(&ctx->txn, rd->dname, offset, true);
        gdnsd_put_una16(htons(newlen + 2), &packet[offset - 4]);
        offset += newlen;
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_srv(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_srv_t* rrset)
{
    gdnsd_assert(ctx->txn.packet);

    uint8_t* packet = ctx->txn.packet;

    const unsigned rrct = rrset->gen.count;
    ctx->txn.ancount += rrct;
    for (unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(packet, offset, ctx->txn.qname_comp);
        gdnsd_put_una32(DNS_RRFIXED_SRV, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;
        const ltree_rdata_srv_t* rd = &rrset->rdata[i];
        gdnsd_put_una16(rd->priority, &packet[offset]);
        offset += 2;
        gdnsd_put_una16(rd->weight, &packet[offset]);
        offset += 2;
        gdnsd_put_una16(rd->port, &packet[offset]);
        offset += 2;
        // SRV target can't be compressed
        const unsigned newlen = store_dname_nocomp(packet, rd->dname, offset);
        gdnsd_put_una16(htons(newlen + 6), &packet[offset - 8]);
        offset += newlen;
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_naptr(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_naptr_t* rrset)
{
    gdnsd_assert(ctx->txn.packet);
    gdnsd_assert(offset);

    uint8_t* packet = ctx->txn.packet;

    const unsigned rrct = rrset->gen.count;
    ctx->txn.ancount += rrct;
    for (unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(packet, offset, ctx->txn.qname_comp);
        gdnsd_put_una32(DNS_RRFIXED_NAPTR, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;
        const unsigned rdata_offset = offset;
        const ltree_rdata_naptr_t* rd = &rrset->rdata[i];
        gdnsd_put_una16(rd->order, &packet[offset]);
        offset += 2;
        gdnsd_put_una16(rd->pref, &packet[offset]);
        offset += 2;
        memcpy(&packet[offset], rd->text, rd->text_len);
        offset += rd->text_len;

        // NAPTR target can't be compressed
        offset += store_dname_nocomp(packet, rd->dname, offset);
        gdnsd_put_una16(htons(offset - rdata_offset), &packet[rdata_offset - 2]);
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_txt(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_txt_t* rrset)
{
    gdnsd_assert(ctx->txn.packet);
    gdnsd_assert(offset);

    uint8_t* packet = ctx->txn.packet;

    const unsigned rrct = rrset->gen.count;
    ctx->txn.ancount += rrct;
    for (unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(packet, offset, ctx->txn.qname_comp);
        gdnsd_put_una32(DNS_RRFIXED_TXT, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 4;
        const ltree_rdata_txt_t* rd = &rrset->rdata[i];
        gdnsd_put_una16(htons(rd->text_len), &packet[offset]);
        offset += 2;
        memcpy(&packet[offset], rd->text, rd->text_len);
        offset += rd->text_len;
    }

    return offset;
}

F_NONNULL
static unsigned encode_rr_cname_common(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_cname_t* rd, const bool chain)
{
    gdnsd_assert(ctx->txn.packet);
    gdnsd_assert(offset);

    uint8_t* packet = ctx->txn.packet;

    offset += repeat_name(packet, offset, ctx->txn.qname_comp);
    gdnsd_put_una32(DNS_RRFIXED_CNAME, &packet[offset]);
    offset += 4;
    gdnsd_put_una32(rd->gen.ttl, &packet[offset]);
    offset += 6;
    const unsigned rdata_offset = offset;
    offset += store_dname_comp(&ctx->txn, rd->dname, offset, false);
    gdnsd_put_una16(htons(offset - rdata_offset), &packet[rdata_offset - 2]);

    if (chain) {
        // adjust qname_comp to point at cname's data for re-querying
        ctx->txn.qname_comp = rdata_offset;
        // cname answer count tracked separately, so that other logic on the
        // zeroness of ancount still works
        ctx->txn.cname_ancount++;
    } else {
        // direct answer record for qtype=CNAME
        ctx->txn.ancount++;
    }

    return offset;
}

F_NONNULL
static unsigned encode_rr_cname(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_cname_t* rd)
{
    return encode_rr_cname_common(ctx, offset, rd, false);
}

F_NONNULL
static unsigned encode_rr_cname_chain(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_cname_t* rd)
{
    return encode_rr_cname_common(ctx, offset, rd, true);
}

F_NONNULL
static unsigned encode_rr_soa(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_soa_t* rdata)
{
    gdnsd_assert(ctx->txn.packet);
    gdnsd_assert(offset);

    uint8_t* packet = ctx->txn.packet;

    offset += repeat_name(packet, offset, ctx->txn.auth_comp);
    gdnsd_put_una32(DNS_RRFIXED_SOA, &packet[offset]);
    offset += 4;
    gdnsd_put_una32(rdata->gen.ttl, &packet[offset]);
    offset += 6;

    // fill in the rdata
    const unsigned rdata_offset = offset;
    offset += store_dname_comp(&ctx->txn, rdata->master, offset, true);
    offset += store_dname_comp(&ctx->txn, rdata->email, offset, false);
    memcpy(&packet[offset], &rdata->times, 20);
    offset += 20; // 5x 32-bits

    // set rdata_len
    gdnsd_put_una16(htons(offset - rdata_offset), &packet[rdata_offset - 2]);

    ctx->txn.ancount++;

    return offset;
}

static unsigned encode_rrs_rfc3597(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_rfc3597_t* rrset)
{
    gdnsd_assert(ctx->txn.packet);
    gdnsd_assert(offset);

    // assert that DYNC (which is technically in the range
    //  served exclusively by this function, but which we
    //  should be translating earlier and never serving on
    //  the wire) never appears here.
    gdnsd_assert(rrset->gen.type != DNS_TYPE_DYNC);

    uint8_t* packet = ctx->txn.packet;

    const unsigned rrct = rrset->gen.count;
    ctx->txn.ancount += rrct;
    for (unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(packet, offset, ctx->txn.qname_comp);
        gdnsd_put_una16(htons(rrset->gen.type), &packet[offset]);
        offset += 2;
        gdnsd_put_una16(htons(DNS_CLASS_IN), &packet[offset]);
        offset += 2;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 4;
        gdnsd_put_una16(htons(rrset->rdata[i].rdlen), &packet[offset]);
        offset += 2;
        memcpy(&packet[offset], rrset->rdata[i].rd, rrset->rdata[i].rdlen);
        offset += rrset->rdata[i].rdlen;
    }

    return offset;
}

// These have no test for falling out with a NULL if we reach the end
//  of the list because ltree already validated at startup that in all
//  cases where we call these, the given RRset exists.
#define MK_RRSET_GET(_typ, _nam, _dtyp) \
F_NONNULL F_PURE \
static const ltree_rrset_ ## _typ ## _t* ltree_node_get_rrset_ ## _nam (const ltree_node_t* node) {\
    const ltree_rrset_t* rrsets = node->rrsets;\
    gdnsd_assert(rrsets);\
    while (rrsets->gen.type != _dtyp) {\
        rrsets = rrsets->gen.next;\
        gdnsd_assert(rrsets);\
    }\
    return &rrsets-> _typ;\
}
MK_RRSET_GET(soa, soa, DNS_TYPE_SOA)
MK_RRSET_GET(ns, ns, DNS_TYPE_NS)

// typedef+cast for the encode funcs in the funcptr table
typedef unsigned(*encode_funcptr)(dnsp_ctx_t*, unsigned, const void*);
#define EC (encode_funcptr)

static encode_funcptr encode_funcptrs[128] = {
    EC encode_rrs_rfc3597, // 000
    EC encode_rrs_a,       // 001 - DNS_TYPE_A
    EC encode_rrs_ns,      // 002 - DNS_TYPE_NS
    EC encode_rrs_rfc3597, // 003
    EC encode_rrs_rfc3597, // 004
    EC encode_rr_cname,    // 005 - DNS_TYPE_CNAME
    EC encode_rr_soa,      // 006 - DNS_TYPE_SOA
    EC encode_rrs_rfc3597, // 007
    EC encode_rrs_rfc3597, // 008
    EC encode_rrs_rfc3597, // 009
    EC encode_rrs_rfc3597, // 010
    EC encode_rrs_rfc3597, // 011
    EC encode_rrs_ptr,     // 012 - DNS_TYPE_PTR
    EC encode_rrs_rfc3597, // 013
    EC encode_rrs_rfc3597, // 014
    EC encode_rrs_mx,      // 015 - DNS_TYPE_MX
    EC encode_rrs_txt,     // 016 - DNS_TYPE_TXT
    EC encode_rrs_rfc3597, // 017
    EC encode_rrs_rfc3597, // 018
    EC encode_rrs_rfc3597, // 019
    EC encode_rrs_rfc3597, // 020
    EC encode_rrs_rfc3597, // 021
    EC encode_rrs_rfc3597, // 022
    EC encode_rrs_rfc3597, // 023
    EC encode_rrs_rfc3597, // 024
    EC encode_rrs_rfc3597, // 025
    EC encode_rrs_rfc3597, // 026
    EC encode_rrs_rfc3597, // 027
    EC encode_rrs_aaaa,    // 028 - DNS_TYPE_AAAA
    EC encode_rrs_rfc3597, // 029
    EC encode_rrs_rfc3597, // 030
    EC encode_rrs_rfc3597, // 031
    EC encode_rrs_rfc3597, // 032
    EC encode_rrs_srv,     // 033 - DNS_TYPE_SRV
    EC encode_rrs_rfc3597, // 034
    EC encode_rrs_naptr,   // 035 - DNS_TYPE_NAPTR
    EC encode_rrs_rfc3597, // 036
    EC encode_rrs_rfc3597, // 037
    EC encode_rrs_rfc3597, // 038
    EC encode_rrs_rfc3597, // 039
    EC encode_rrs_rfc3597, // 040
    EC encode_rrs_rfc3597, // 041
    EC encode_rrs_rfc3597, // 042
    EC encode_rrs_rfc3597, // 043
    EC encode_rrs_rfc3597, // 044
    EC encode_rrs_rfc3597, // 045
    EC encode_rrs_rfc3597, // 046
    EC encode_rrs_rfc3597, // 047
    EC encode_rrs_rfc3597, // 048
    EC encode_rrs_rfc3597, // 049
    EC encode_rrs_rfc3597, // 050
    EC encode_rrs_rfc3597, // 051
    EC encode_rrs_rfc3597, // 052
    EC encode_rrs_rfc3597, // 053
    EC encode_rrs_rfc3597, // 054
    EC encode_rrs_rfc3597, // 055
    EC encode_rrs_rfc3597, // 056
    EC encode_rrs_rfc3597, // 057
    EC encode_rrs_rfc3597, // 058
    EC encode_rrs_rfc3597, // 059
    EC encode_rrs_rfc3597, // 060
    EC encode_rrs_rfc3597, // 061
    EC encode_rrs_rfc3597, // 062
    EC encode_rrs_rfc3597, // 063
    EC encode_rrs_rfc3597, // 064
    EC encode_rrs_rfc3597, // 065
    EC encode_rrs_rfc3597, // 066
    EC encode_rrs_rfc3597, // 067
    EC encode_rrs_rfc3597, // 068
    EC encode_rrs_rfc3597, // 069
    EC encode_rrs_rfc3597, // 070
    EC encode_rrs_rfc3597, // 071
    EC encode_rrs_rfc3597, // 072
    EC encode_rrs_rfc3597, // 073
    EC encode_rrs_rfc3597, // 074
    EC encode_rrs_rfc3597, // 075
    EC encode_rrs_rfc3597, // 076
    EC encode_rrs_rfc3597, // 077
    EC encode_rrs_rfc3597, // 078
    EC encode_rrs_rfc3597, // 079
    EC encode_rrs_rfc3597, // 080
    EC encode_rrs_rfc3597, // 081
    EC encode_rrs_rfc3597, // 082
    EC encode_rrs_rfc3597, // 083
    EC encode_rrs_rfc3597, // 084
    EC encode_rrs_rfc3597, // 085
    EC encode_rrs_rfc3597, // 086
    EC encode_rrs_rfc3597, // 087
    EC encode_rrs_rfc3597, // 088
    EC encode_rrs_rfc3597, // 089
    EC encode_rrs_rfc3597, // 090
    EC encode_rrs_rfc3597, // 091
    EC encode_rrs_rfc3597, // 092
    EC encode_rrs_rfc3597, // 093
    EC encode_rrs_rfc3597, // 094
    EC encode_rrs_rfc3597, // 095
    EC encode_rrs_rfc3597, // 096
    EC encode_rrs_rfc3597, // 097
    EC encode_rrs_rfc3597, // 098
    EC encode_rrs_rfc3597, // 099 (SPF, deprecated)
    EC encode_rrs_rfc3597, // 100
    EC encode_rrs_rfc3597, // 101
    EC encode_rrs_rfc3597, // 102
    EC encode_rrs_rfc3597, // 103
    EC encode_rrs_rfc3597, // 104
    EC encode_rrs_rfc3597, // 105
    EC encode_rrs_rfc3597, // 106
    EC encode_rrs_rfc3597, // 107
    EC encode_rrs_rfc3597, // 108
    EC encode_rrs_rfc3597, // 109
    EC encode_rrs_rfc3597, // 110
    EC encode_rrs_rfc3597, // 111
    EC encode_rrs_rfc3597, // 112
    EC encode_rrs_rfc3597, // 113
    EC encode_rrs_rfc3597, // 114
    EC encode_rrs_rfc3597, // 115
    EC encode_rrs_rfc3597, // 116
    EC encode_rrs_rfc3597, // 117
    EC encode_rrs_rfc3597, // 118
    EC encode_rrs_rfc3597, // 119
    EC encode_rrs_rfc3597, // 120
    EC encode_rrs_rfc3597, // 121
    EC encode_rrs_rfc3597, // 122
    EC encode_rrs_rfc3597, // 123
    EC encode_rrs_rfc3597, // 124
    EC encode_rrs_rfc3597, // 125
    EC encode_rrs_rfc3597, // 126
    EC encode_rrs_rfc3597, // 127
};

F_NONNULL
static unsigned construct_normal_response(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_t* node_rrset)
{
    gdnsd_assert(ctx->txn.qtype < 128 || ctx->txn.qtype & 0xFF00);
    do {
        if (node_rrset->gen.type == ctx->txn.qtype) {
            if (unlikely(ctx->txn.qtype & 0xFF00))
                offset = encode_rrs_rfc3597(ctx, offset, &node_rrset->rfc3597);
            else
                offset = encode_funcptrs[ctx->txn.qtype](ctx, offset, node_rrset);
            break;
        }
        node_rrset = node_rrset->gen.next;
    } while (node_rrset);

    return offset;
}

// Find the start of the (uncompressed) auth zone name at auth_depth bytes into the name at qname_offset,
//  chasing compression pointers as necc.
// XXX - really, the necessity of this is sort of the last straw on the current scheme involving
//  the interactions of ctx->txn.qname_comp, ctx->txn.auth_comp, lqname, store_dname(), search_ltree(), and CNAME
//  processing.  It's too complex to understand easily and needs refactoring.
F_NONNULL F_PURE
static unsigned chase_auth_ptr(const uint8_t* packet, unsigned offset, unsigned auth_depth)
{
    gdnsd_assert(offset);
    gdnsd_assert(offset < MAX_RESPONSE_DATA);
    gdnsd_assert(auth_depth < 256);

    unsigned llen = packet[offset];
    while (auth_depth || llen & 0xC0) {
        if (llen & 0xC0) { // compression pointer
            offset = ntohs(gdnsd_get_una16(&packet[offset])) & ~0xC000U;
        } else {
            const unsigned move = llen + 1;
            gdnsd_assert(auth_depth >= move);
            offset += move;
            auth_depth -= move;
        }
        llen = packet[offset];
    }

    return offset;
}

typedef struct {
    const ltree_node_t* dom;
    const ltree_node_t* auth;
    unsigned auth_depth;
} search_result_t;

F_NONNULL
static ltree_dname_status_t search_ltree_for_dname(const uint8_t* dname, search_result_t* res)
{
    gdnsd_assert(*dname != 0);
    gdnsd_assert(*dname != 2); // these are always illegal dnames

    ltree_dname_status_t rval = DNAME_NOAUTH;
    const ltree_node_t* rv_node = NULL;

    // construct label ptr stack
    const uint8_t* lstack[127];
    unsigned lcount = dname_to_lstack(dname, lstack);

    const ltree_node_t* current = rcu_dereference(root_tree);
    const ltree_node_t* auth = NULL;
    unsigned depth_lc = lcount;
    while (!rv_node && current) {
        if (LTN_GET_FLAG_ZCUT(current) && auth) {
            gdnsd_assert(rval == DNAME_AUTH);
            rval = DNAME_DELEG;
            depth_lc = lcount;
            rv_node = current;
        } else {
            if (LTN_GET_FLAG_ZCUT(current)) {
                gdnsd_assert(rval == DNAME_NOAUTH);
                gdnsd_assert(!auth);
                rval = DNAME_AUTH;
                depth_lc = lcount;
                auth = current;
            }
            if (!lcount) {
                rv_node = current; // exact match of full label count
            } else  {
                lcount--;
                const uint8_t* child_label = lstack[lcount];
                ltree_node_t* next = ltree_node_find_child(current, child_label);
                // If no deeper match, try wildcard if in auth space
                if (!next && rval == DNAME_AUTH) {
                    static const uint8_t label_wild[2] =  { '\001', '*' };
                    rv_node = ltree_node_find_child(current, label_wild);
                }
                current = next;
            }
        }
    }

    // Calculate auth depth for cases where it matters
    unsigned auth_depth = 0;
    if (rval != DNAME_NOAUTH) {
        auth_depth = depth_lc;
        while (depth_lc--)
            auth_depth += lstack[depth_lc][0];
    }

    res->dom = rv_node;
    res->auth = auth;
    res->auth_depth = auth_depth;
    return rval;
}

// DYNC handling.  This translates a DYNC RR from the ltree into
//   a new rrset (possibly NULL) via the plugin, using context
//   storage.
F_NONNULL
static const ltree_rrset_t* process_dync(dnsp_ctx_t* ctx, const ltree_rrset_dync_t* rd, const unsigned qtype)
{
    gdnsd_assert(!rd->gen.next); // DYNC does not co-exist with other rrsets

    const unsigned ttl = do_dyn_callback(ctx, rd->func, rd->resource, rd->gen.ttl, rd->ttl_min);
    dyn_result_t* dr = ctx->dyn;
    ltree_rrset_t* rv = NULL;

    if (dr->is_cname) {
        gdnsd_assert(gdnsd_dname_status(dr->storage) == DNAME_VALID);
        dname_copy(ctx->txn.dync_store, dr->storage);
        ctx->txn.dync_synth_rrset.gen.type = DNS_TYPE_CNAME;
        ctx->txn.dync_synth_rrset.gen.count = 1;
        ctx->txn.dync_synth_rrset.gen.ttl = ttl;
        ctx->txn.dync_synth_rrset.cname.dname = ctx->txn.dync_store;
        rv = &ctx->txn.dync_synth_rrset;
    } else if (qtype == DNS_TYPE_A && dr->count_v4) {
        ctx->txn.dync_synth_rrset.gen.type = DNS_TYPE_A;
        ctx->txn.dync_synth_rrset.gen.ttl = ttl;
        ctx->txn.dync_synth_rrset.gen.count = dr->count_v4;
        if (dr->count_v4 <= LTREE_V4A_SIZE)
            memcpy(ctx->txn.dync_synth_rrset.a.v4a, dr->v4, sizeof(*dr->v4) * dr->count_v4);
        else
            ctx->txn.dync_synth_rrset.a.addrs = dr->v4;
        rv = &ctx->txn.dync_synth_rrset;
    } else if (qtype == DNS_TYPE_AAAA && dr->count_v6) {
        ctx->txn.dync_synth_rrset.gen.type = DNS_TYPE_AAAA;
        ctx->txn.dync_synth_rrset.gen.ttl = ttl;
        ctx->txn.dync_synth_rrset.gen.count = dr->count_v6;
        ctx->txn.dync_synth_rrset.aaaa.addrs = &dr->storage[result_v6_offset];
        rv = &ctx->txn.dync_synth_rrset;
    }

    return rv;
}

// like dname_isinzone, but the zone is in raw wire format (no existing length
// prefix), used only for hacky CNAME-chasing stuff.
F_NONNULL
static bool dname_is_in_wire_zone(const uint8_t* wire_zone, const uint8_t* check)
{
    // transform wire_zone into dname format (give it a prefix byte in local storage)
    uint8_t zone_to_check[256];
    unsigned oal = 0;
    uint8_t llen;
    while ((llen = wire_zone[oal])) {
        llen++;
        oal += llen;
    }
    oal++; // terminal \0
    zone_to_check[0] = oal;
    memcpy(&zone_to_check[1], wire_zone, oal);
    // use standard comparator from dname.h
    return dname_isinzone(zone_to_check, check);
}

F_NONNULLX(1, 2, 4)
static unsigned do_final_auth_response(dnsp_ctx_t* ctx, const uint8_t* qname, const ltree_node_t* dom, const ltree_node_t* auth, const ltree_rrset_t* rrsets, unsigned offset)
{
    wire_dns_header_t* res_hdr = (wire_dns_header_t*)ctx->txn.packet;
    res_hdr->flags1 |= 4; // AA bit

    bool chal_matched = false;

    if (likely(rrsets)) {
        // ANY queries against CNAME data should be treated like explicit CNAME queries:
        if (unlikely(ctx->txn.qtype == DNS_TYPE_ANY && rrsets->gen.type == DNS_TYPE_CNAME))
            ctx->txn.qtype = DNS_TYPE_CNAME;
        if (likely(ctx->txn.qtype != DNS_TYPE_ANY))
            offset = construct_normal_response(ctx, offset, rrsets);
    }

    if (ctx->txn.qtype == DNS_TYPE_TXT || !ctx->txn.ancount)
        chal_matched = chal_respond(ctx->txn.qname_comp, ctx->txn.qtype, qname, ctx->txn.packet, &ctx->txn.ancount, &offset, ctx->txn.this_max_response);

    if (unlikely(ctx->txn.qtype == DNS_TYPE_ANY)) {
        // construct_normal_response is not called for ANY, and
        // chal_respond does not inject an RR for ANY, so there should
        // still be zero answers here:
        gdnsd_assert(!ctx->txn.ancount);
        // ANY->CNAME was already handled above construct_normal_response by changing ctx->txn.qtype
        gdnsd_assert(!rrsets || rrsets->gen.type != DNS_TYPE_CNAME);

        // The conditional here basically means "if this wouldn't be an NXDOMAIN below"
        if (dom || chal_matched) {
            ctx->txn.ancount = 1;
            offset += repeat_name(ctx->txn.packet, offset, ctx->txn.qname_comp);
            memcpy(&ctx->txn.packet[offset], hinfo_for_any, hinfo_for_any_len);
            offset += hinfo_for_any_len;
        }
    }

    if (!ctx->txn.ancount) {
        offset = encode_rr_soa(ctx, offset, ltree_node_get_rrset_soa(auth));
        // Transfer the singleton SOA's count from answer to auth section.
        gdnsd_assert(ctx->txn.ancount == 1 && !ctx->txn.nscount);
        ctx->txn.nscount = 1;
        ctx->txn.ancount = 0;
        if (!dom && !chal_matched) {
            res_hdr->flags2 = DNS_RCODE_NXDOMAIN;
            stats_own_inc(&ctx->stats->nxdomain);
        }
    }

    return offset;
}

F_NONNULL
static unsigned db_lookup(dnsp_ctx_t* ctx, const uint8_t* qname, unsigned offset, const bool via_cname);

F_NONNULLX(1, 2, 4)
static unsigned do_auth_response(dnsp_ctx_t* ctx, const uint8_t* qname, const ltree_node_t* dom, const ltree_node_t* auth, unsigned offset)
{
    const ltree_rrset_t* rrsets = dom ? dom->rrsets : NULL;
    if (rrsets) {
        if (rrsets->gen.type == DNS_TYPE_DYNC) {
            // If DYNC, we may get a CNAME but we don't need to recurse
            gdnsd_assert(!rrsets->gen.next); // DYNC does not co-exist with other rrsets
            rrsets = process_dync(ctx, &rrsets->dync, ctx->txn.qtype);
            if (rrsets && rrsets->gen.type == DNS_TYPE_CNAME)
                ctx->txn.qtype = DNS_TYPE_CNAME;
        } else if (rrsets->gen.type == DNS_TYPE_CNAME
                   && ctx->txn.qtype != DNS_TYPE_CNAME && ctx->txn.qtype != DNS_TYPE_ANY) {
            // If we have a real CNAME without qtype=CNAME|ANY, we may have to recurse
            gdnsd_assert(!rrsets->gen.next); // CNAME does not co-exist with other rrsets
            const ltree_rrset_cname_t* cname = &rrsets->cname;
            if (!gcfg->experimental_no_chain && dname_is_in_wire_zone(&ctx->txn.packet[ctx->txn.auth_comp], cname->dname)) {
                // If the target is in zone and chaining isn't disabled,
                // encode the CNAME into the response manually now and
                // recurse back into db_lookup
                wire_dns_header_t* res_hdr = (wire_dns_header_t*)ctx->txn.packet;
                res_hdr->flags1 |= 4; // pre-set AA bit in case cname goes into a delegation
                offset = encode_rr_cname_chain(ctx, offset, cname);
                return db_lookup(ctx, cname->dname, offset, true);
            }
            // If target isn't in zone or chaining is disabled, switch
            // query type to CNAME and emit a 1-RR CNAME response via the
            // normal mechanisms in do_final_auth_response
            ctx->txn.qtype = DNS_TYPE_CNAME;
        }
    }

    return do_final_auth_response(ctx, qname, dom, auth, rrsets, offset);
}

F_NONNULL
static unsigned db_lookup(dnsp_ctx_t* ctx, const uint8_t* qname, unsigned offset, const bool via_cname)
{
    ltree_dname_status_t status;
    search_result_t res;
    status = search_ltree_for_dname(qname, &res);
    if (status == DNAME_NOAUTH) {
        gdnsd_assert(!via_cname); // we checked for same-zone before recursing for CNAME
        wire_dns_header_t* res_hdr = (wire_dns_header_t*)ctx->txn.packet;
        res_hdr->flags2 = DNS_RCODE_REFUSED;
        stats_own_inc(&ctx->stats->refused);
        return offset;
    }

    gdnsd_assert(res.auth);

    // In the initial search, it's known that "qname" is in fact the real query name and therefore
    //  uncompressed, which is what makes the simplistic ctx->txn.auth_comp calculation possible.
    if (!via_cname)
        ctx->txn.auth_comp = ctx->txn.qname_comp + res.auth_depth;
    else
        ctx->txn.auth_comp = chase_auth_ptr(ctx->txn.packet, ctx->txn.qname_comp, res.auth_depth);

    if (status == DNAME_DELEG) {
        gdnsd_assert(res.dom);
        const ltree_rrset_ns_t* ns = ltree_node_get_rrset_ns(res.dom);
        gdnsd_assert(ns);
        return encode_rrs_ns_deleg(ctx, offset, ns);
    }

    gdnsd_assert(status == DNAME_AUTH);

    return do_auth_response(ctx, qname, res.dom, res.auth, offset);
}

F_NONNULL
static unsigned answer_from_db(dnsp_ctx_t* ctx, unsigned offset)
{
    gdnsd_assert(offset);
    gdnsd_assert(ctx->stats);

    const unsigned full_trunc_offset = offset;

    // Initial qname_comp set to original query
    ctx->txn.qname_comp = sizeof(wire_dns_header_t);
    const uint8_t* qname = ctx->txn.lqname;

    // Respond from the DB
    rcu_read_lock();
    offset = db_lookup(ctx, qname, offset, false);
    rcu_read_unlock();

    // UDP truncation handling
    if (ctx->is_udp) {
        if (!ctx->txn.edns.cookie.valid && gcfg->max_nocookie_response && gcfg->max_nocookie_response < ctx->txn.this_max_response)
            ctx->txn.this_max_response = gcfg->max_nocookie_response;

        if ((offset + ctx->txn.edns.out_bytes) > ctx->txn.this_max_response) {
            offset = full_trunc_offset;
            ((wire_dns_header_t*)ctx->txn.packet)->flags1 |= 0x2; // TC bit
            // avoid potential confusion over NXDOMAIN+TC (can only happen in CNAME-chaining case)
            ((wire_dns_header_t*)ctx->txn.packet)->flags2 = DNS_RCODE_NOERROR;
            ctx->txn.ancount = 0;
            ctx->txn.nscount = 0;
            ctx->txn.arcount = 0;
            ctx->txn.cname_ancount = 0;
            if (ctx->txn.edns.req_edns)
                stats_own_inc(&ctx->stats->udp.edns_tc);
            else
                stats_own_inc(&ctx->stats->udp.tc);
        }
    }

    return offset;
}

F_NONNULL
static unsigned do_edns_output(dnsp_ctx_t* ctx, uint8_t* packet, unsigned res_offset, const rcode_rv_t status)
{
    uint32_t extflags = (status == DECODE_BADVERS) ? 0x01000000 : 0;
    if (ctx->txn.edns.do_bit)
        extflags |= 0x8000;

    packet[res_offset++] = '\0'; // domainname part of OPT
    gdnsd_put_una16(htons(DNS_TYPE_OPT), &packet[res_offset]);
    res_offset += 2;
    gdnsd_put_una16(htons(DNS_EDNS_SIZE), &packet[res_offset]);
    res_offset += 2;
    gdnsd_put_una32(htonl(extflags), &packet[res_offset]);
    res_offset += 4;
    uint8_t* rdlen_ptr = &packet[res_offset]; // filled in at end, after we know
    res_offset += 2;

    // code below which tacks on options should increment this for the overall rdlen of the OPT RR
    unsigned rdlen = 0;

    if (ctx->txn.edns.respond_client_subnet) {
        const unsigned src_mask = ctx->txn.edns.client_info.edns_client_mask;
        const unsigned scope_mask = src_mask ? ctx->txn.edns.client_scope_mask : 0;
        const unsigned addr_bytes = (src_mask >> 3) + ((src_mask & 7) ? 1 : 0);
        rdlen += (8 + addr_bytes);
        gdnsd_put_una16(htons(EDNS_CLIENTSUB_OPTCODE), &packet[res_offset]);
        res_offset += 2;
        gdnsd_put_una16(htons(4 + addr_bytes), &packet[res_offset]);
        res_offset += 2;
        gdnsd_put_una16(htons(ctx->txn.edns.client_family), &packet[res_offset]);
        res_offset += 2;
        packet[res_offset++] = src_mask;
        packet[res_offset++] = scope_mask;
        if (src_mask) {
            gdnsd_assert(addr_bytes);
            if (ctx->txn.edns.client_family == 1U) { // IPv4
                memcpy(&packet[res_offset], &ctx->txn.edns.client_info.edns_client.sin4.sin_addr.s_addr, addr_bytes);
            } else {
                gdnsd_assert(ctx->txn.edns.client_family == 2U); // IPv6
                memcpy(&packet[res_offset], ctx->txn.edns.client_info.edns_client.sin6.sin6_addr.s6_addr, addr_bytes);
            }
            res_offset += addr_bytes;
        }
    }

    // EDNS Cookie output
    if (ctx->txn.edns.cookie.respond) {
        gdnsd_assert(ctx->txn.edns.cookie.recvd);
        rdlen += 20U;
        gdnsd_put_una16(htons(EDNS_COOKIE_OPTCODE), &packet[res_offset]);
        res_offset += 2;
        gdnsd_put_una16(htons(16), &packet[res_offset]);
        res_offset += 2;
        memcpy(&packet[res_offset], ctx->txn.edns.cookie.output, 16U);
        res_offset += 16U;
    }

    // TCP keepalive is emitted with every response to an EDNS query over
    // TCP if DSO isn't established, using either the fixed timeout set
    // from config at startup, or zero if we're in shutdown_grace mode and
    // trying to get clients to disconnect.
    if (!ctx->is_udp) {
        gdnsd_assert(ctx->txn.dso);
        if (!ctx->txn.dso->estab) {
            rdlen += 6U;
            gdnsd_put_una16(htons(EDNS_TCP_KEEPALIVE_OPTCODE), &packet[res_offset]);
            res_offset += 2;
            gdnsd_put_una16(htons(2), &packet[res_offset]);
            res_offset += 2;
            gdnsd_put_una16(htons(ctx->edns_tcp_keepalive), &packet[res_offset]);
            res_offset += 2;
        }
    }

    // NSID, if configured by user
    if (ctx->txn.edns.respond_nsid) {
        gdnsd_assert(gcfg->nsid.data);
        gdnsd_assert(gcfg->nsid.len);
        rdlen += (4U + gcfg->nsid.len);
        gdnsd_put_una16(htons(EDNS_NSID_OPTCODE), &packet[res_offset]);
        res_offset += 2;
        gdnsd_put_una16(htons(gcfg->nsid.len), &packet[res_offset]);
        res_offset += 2;
        memcpy(&packet[res_offset], gcfg->nsid.data, gcfg->nsid.len);
        res_offset += gcfg->nsid.len;
    }

    // predicted edns.out_bytes correctly earlier for truncation.  note
    // this happens before padding below.
    gdnsd_assert(ctx->txn.edns.out_bytes == (11U + rdlen));

    // Padding, must be the last option, as it must make calculations based
    // on the total size of the packet including any updates to
    // "res_offset" from earlier options
    if (ctx->tcp_pad) {
        gdnsd_assert(!ctx->is_udp);
        // RFC 8467 recommends block padding to 468, which we'll stick with
        // here even though MTU-size concerns don't really matter as much
        // for now, as we only support the TCP case.  The minimum size
        // added to a packet by the Padding option itself is 4 bytes (for
        // option code and option len of zero), plus however many bytes of
        // actual padding length is tacked on).  Note MAX_RESPONSE_DATA
        // allows us to always add the option and always obtain perfect
        // padding within MAX_RESPONSE_BUF at a block size of 468 as
        // documented in dnswire.h.
        gdnsd_assert(res_offset <= MAX_RESPONSE_DATA);
        size_t pad_dlen = (((res_offset + 4U + PAD_BLOCK_SIZE - 1U) / PAD_BLOCK_SIZE) * PAD_BLOCK_SIZE) - 4U - res_offset;
        gdnsd_assert(res_offset + 4U + pad_dlen <= MAX_RESPONSE_BUF);

        rdlen += (4U + pad_dlen);
        gdnsd_put_una16(htons(EDNS_PADDING), &packet[res_offset]);
        res_offset += 2;
        gdnsd_put_una16(htons(pad_dlen), &packet[res_offset]);
        res_offset += 2;
        memset(&packet[res_offset], 0, pad_dlen);
        res_offset += pad_dlen;

        gdnsd_assert(res_offset <= MAX_RESPONSE_BUF);
        gdnsd_assert((res_offset % PAD_BLOCK_SIZE) == 0);
    }

    // Update OPT RR's rdlen for any options emitted above, and bump arcount for it
    gdnsd_put_una16(htons(rdlen), rdlen_ptr);
    ctx->txn.arcount++;

    // We only do one kind of truncation: complete truncation.
    //  therefore if we're returning a >512 packet, it wasn't truncated
    if (ctx->is_udp && res_offset > 512U)
        stats_own_inc(&ctx->stats->udp.edns_big);

    return res_offset;
}

F_NONNULL
static size_t handle_dso(dnsp_ctx_t* ctx, const size_t packet_len)
{
    uint8_t* packet = ctx->txn.packet;
    gdnsd_assert(packet);
    wire_dns_header_t* hdr = (wire_dns_header_t*)packet;

    // Ensure all the Z-bits (flags) are clear in any DSO response:
    // The main process_dns_query code already clears TC and AA from flags1,
    // but leaves RD as-is and sets QR for us, and we assign our rcodes
    // unmasked to flags2, which clears the other 4 bits in them (RA, reserved,
    // AD, CD) implicitly.  So all we *should* have to do here on top of that
    // is ensure we don't reflect client's RD bit, but better safe than sorry
    // in case of code changes elsewhere, so clear all but QR+Opcode:
    hdr->flags1 &= 0xF8;
    hdr->flags2 = 0;

    // If we get a DSO opcode over UDP, send a FORMERR response with no data
    // Non-zero RR counts with DSO *MUST* generate a FORMERR by the standard
    if (ctx->is_udp || (hdr->qdcount | hdr->ancount | hdr->nscount | hdr->arcount)) {
        log_devdebug("Got DSO packet over UDP or with non-zero RR counts, FORMERR");
        hdr->qdcount = 0;
        hdr->ancount = 0;
        hdr->nscount = 0;
        hdr->arcount = 0;
        stats_own_inc(&ctx->stats->formerr);
        hdr->flags2 = DNS_RCODE_FORMERR;
        return sizeof(wire_dns_header_t);
    }

    gdnsd_assert(ctx->txn.dso); // TCP always has this pointer

    // All of these cases are protocol-fatal and the standard requires immediate connection abort:
    //    A. Any unidirectional of any TLV type (ID = 0)
    //    B. Lack of a primary TLV
    //    C. Any known non-Keepalive TLV (RetryDelay, Padding) as primary
    //    D. Any length errors in blindly parsing all TLVs (TLV runs off end of
    //       packet, junk data at end of packet, etc).
    //    E. A Keepalive TLV with a data length other than 8.
    //    F. If we see EDNS Keepalive in an established DSO session (elsewhere)

    if (!hdr->id || packet_len < sizeof(wire_dns_header_t) + 4U) { // Protoerr A||B
        log_devdebug("Got DSO packet with zero id (uni) or no room for primary TLV, Proto Err -> Conn Abort");
        stats_own_inc(&ctx->stats->tcp.dso_protoerr);
        return 0;
    }

    // Offset used to parse primary TLV
    size_t offset = sizeof(wire_dns_header_t);

    // Grab type primary request TLV
    const unsigned dtype = ntohs(gdnsd_get_una16(&packet[offset]));
    offset += 2;

    if (dtype == DNS_DSO_RETRY_DELAY || dtype == DNS_DSO_PADDING) { // Protoerr C
        log_devdebug("Got DSO packet with primary TLV known and illegal (retry or padding), Proto Err -> Conn Abort");
        stats_own_inc(&ctx->stats->tcp.dso_protoerr);
        return 0;
    }

    // Grab data len of primary request TLV
    const size_t dlen = ntohs(gdnsd_get_una16(&packet[offset]));
    offset += 2;

    // Consume and ignore primary TLV data bytes (dlen) and all additional TLVs
    // so long as there's still room in the packet for them
    size_t atlv_offset = offset + dlen; // start of first atlv
    while (packet_len >= (atlv_offset + 4U)) { // while 1+ ATLVs present
        const size_t adlen = ntohs(gdnsd_get_una16(&packet[atlv_offset + 2U]));
        atlv_offset += (4U + adlen);
    }

    if (atlv_offset != packet_len) { // Protoerr D
        log_devdebug("Got DSO packet with a length parsing error, Proto Err -> Conn Abort");
        stats_own_inc(&ctx->stats->tcp.dso_protoerr);
        return 0;
    }

    if (dtype == DNS_DSO_KEEPALIVE) {
        if (dlen != 8) { // Protoerr E
            log_devdebug("Got DSO KeepAlive Request with data len %zu, should be 8, Proto Err -> Conn Abort", dlen);
            stats_own_inc(&ctx->stats->tcp.dso_protoerr);
            return 0;
        }

        // We have a legitimate well-formed client KeepAlive, establishing a
        // session and requiring a matching response from us.  last_was_ka
        // informs the TCP layer not to reset the inactivity timer.
        ctx->txn.dso->last_was_ka = true;
        if (!ctx->txn.dso->estab) {
            ctx->txn.dso->estab = true;
            stats_own_inc(&ctx->stats->tcp.dso_estab);
        }

        // offset is already sitting just past the keepalive type+len, just add our data:
        gdnsd_put_una32(0xFFFFFFFFU, &packet[offset]); // keepalive interval = infinite
        offset += 4U;
        gdnsd_put_una32(htonl(ctx->dso_inactivity), &packet[offset]); // inactivity interval
        offset += 4U;
        gdnsd_assert(offset == 24U); // 12 hdr + 12 KA primary tlv response
        return offset;
    }

    // A DSO request with an unknown primary TLV type causes a DSOTYPENI error
    // response and does not establish a DSO session, but keeps the connection.
    log_devdebug("Got DSO Request of unknown type %u, DSOTYPENI", dtype);
    stats_own_inc(&ctx->stats->tcp.dso_typeni);
    hdr->flags2 = DNS_RCODE_DSOTYPENI;
    return sizeof(wire_dns_header_t);
}

F_NONNULL
static size_t handle_dso_with_padding(dnsp_ctx_t* ctx, const size_t packet_len)
{
    size_t offset = handle_dso(ctx, packet_len);

    // assert that all our known responses from above are small enough to use
    // the simplest padding case (always fits in the first padding block with
    // room for the padding option itself with zero or more bytes of pad).
    gdnsd_assert(offset <= (PAD_BLOCK_SIZE - 4U));

    // Crypto padding Additional TLV if appropriate (note that it's ok to have
    // an Additional TLV in cases where no Primary is required/allowed, such as
    // DSOTYPENI and FORMERR responses):
    if (ctx->tcp_pad && offset) {
        gdnsd_assert(!ctx->is_udp);
        gdnsd_assert(offset >= sizeof(wire_dns_header_t)); // non-zero offsets are 12+
        uint8_t* packet = ctx->txn.packet;
        gdnsd_assert(packet);
        const size_t pad_dlen = PAD_BLOCK_SIZE - offset - 4U;
        gdnsd_put_una16(htons(DNS_DSO_PADDING), &packet[offset]);
        offset += 2U;
        gdnsd_put_una16(htons(pad_dlen), &packet[offset]);
        offset += 2U;
        memset(&packet[offset], 0, pad_dlen);
        offset += pad_dlen;
        gdnsd_assert(offset == PAD_BLOCK_SIZE);
    }

    return offset;
}

unsigned process_dns_query(dnsp_ctx_t* ctx, const gdnsd_anysin_t* sa, uint8_t* packet, dso_state_t* dso, const unsigned packet_len)
{
    // iothreads don't allow queries larger than this
    gdnsd_assert(packet_len <= DNS_RECV_SIZE);

    memset(&ctx->txn, 0, sizeof(ctx->txn));
    gdnsd_assert(ctx->stats);
    if (ctx->is_udp)
        gdnsd_assert(!dso);
    else
        gdnsd_assert(dso);
    ctx->txn.packet = packet;
    ctx->txn.dso = dso;
    memcpy(&ctx->txn.edns.client_info.dns_source, sa, sizeof(*sa));

    if (sa->sa.sa_family == AF_INET6)
        stats_own_inc(&ctx->stats->v6);

    // parse_optrr() will raise this value in the udp edns case as necc.
    ctx->txn.this_max_response = ctx->is_udp ? 512U : MAX_RESPONSE_DATA;

    /*
        log_devdebug("Processing %sv%u DNS query of length %u from %s",
            (ctx->is_udp ? "UDP" : "TCP"),
            (sa->sa.sa_family == AF_INET6) ? 6 : 4,
            packet_len,
            logf_anysin(sa));
    */

    unsigned res_offset = sizeof(wire_dns_header_t);
    const rcode_rv_t status = decode_query(ctx, &res_offset, packet_len);

    if (status == DECODE_IGNORE) {
        stats_own_inc(&ctx->stats->dropped);
        return 0;
    }

    wire_dns_header_t* hdr = (wire_dns_header_t*)packet;
    hdr->flags1 &= 0x79; // Clears QR, TC, AA bits, preserves RD and Opcode
    hdr->flags1 |= 0x80; // Sets QR

    if (status == DECODE_DSO)
        return handle_dso_with_padding(ctx, packet_len);

    if (likely(status == DECODE_OK)) {
        hdr->flags2 = DNS_RCODE_NOERROR;
        if (likely(DNSH_GET_QDCOUNT(hdr) == 1U)) {
            if (likely(ctx->txn.qclass == DNS_CLASS_IN) || ctx->txn.qclass == DNS_CLASS_ANY) {
                res_offset = answer_from_db(ctx, res_offset);
            } else if (ctx->txn.qclass == DNS_CLASS_CH) {
                ctx->txn.ancount = 1;
                memcpy(&packet[res_offset], gcfg->chaos.data, gcfg->chaos.len);
                res_offset += gcfg->chaos.len;
            } else {
                hdr->flags2 = DNS_RCODE_REFUSED;
                stats_own_inc(&ctx->stats->refused);
            }
        } else {
            gdnsd_assert(ctx->txn.edns.cookie.recvd);
        }
        if (hdr->flags2 == DNS_RCODE_NOERROR)
            stats_own_inc(&ctx->stats->noerror);
    } else {
        if (status == DECODE_FORMERR) {
            hdr->flags2 = DNS_RCODE_FORMERR;
            stats_own_inc(&ctx->stats->formerr);
        } else if (status == DECODE_NOTIMP) {
            hdr->flags2 = DNS_RCODE_NOTIMP;
            stats_own_inc(&ctx->stats->notimp);
        } else {
            gdnsd_assert(status == DECODE_BADVERS);
            hdr->flags2 = DNS_RCODE_NOERROR;
            stats_own_inc(&ctx->stats->badvers);
        }
    }

    if (ctx->txn.edns.req_edns)
        res_offset = do_edns_output(ctx, packet, res_offset, status);

    gdnsd_put_una16(htons(ctx->txn.qdcount), &hdr->qdcount);
    gdnsd_put_una16(htons(ctx->txn.ancount + ctx->txn.cname_ancount), &hdr->ancount);
    gdnsd_put_una16(htons(ctx->txn.nscount), &hdr->nscount);
    gdnsd_put_una16(htons(ctx->txn.arcount), &hdr->arcount);

    gdnsd_assert(res_offset <= MAX_RESPONSE_BUF);

    return res_offset;
}
