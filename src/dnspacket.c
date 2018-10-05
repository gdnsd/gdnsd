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
#include "ztree.h"
#include "chal.h"

#include <gdnsd-prot/plugapi.h>
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/misc.h>

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

// Storage for general-purpose compression target info
typedef struct {
    const uint8_t* orig; // aliases original dname storage, starting at first label len (no compression in this copy)
    unsigned len; // the length of this dname (what would be in the first byte of a proper "dname" in ltree)
    unsigned offset; // where this named was stored in the packet (this & 0xC000 is our target if match)
} ctarget_t;

// per-thread context
typedef struct {
    // this is the packet buffer from the io code, this value is passed in and
    // overwritten at the start or every request
    uint8_t* packet;

    // stats reference for this thread, permanent from startup
    dnspacket_stats_t* stats;

    // used to pseudo-randomly rotate some RRsets (A, AAAA, and NS)
    gdnsd_rstate32_t* rand_state;

    // allocated at startup, memset to zero before each callback
    dyn_result_t* dyn;

    // whether the thread using this context is a udp or tcp thread,
    // set permanently at startup
    bool is_udp;

// ---
// From this point on, all of this gets memset to zero at the start of each
// request and is set with new values as we parse the query and create the
// response
// ---

    // Max UDP response size for this individual request, as determined
    //  by protocol type and EDNS (or lack thereof), not used for TCP
    unsigned this_max_response;

    // The queried type.  Note that this gets switched internally to CNAME in
    // the case of queries which land on a CNAME RR.
    unsigned qtype;

    // Compression pointer to query name.  For most queries this remains set to
    // the fixed offset where the real query starts, but when chasing CNAME
    // pointers, we re-set this to point at the CNAME's target.
    unsigned qname_comp;

    // As above, but for the authority within the qname (zone/deleg start point)
    unsigned auth_comp;

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

    // dns source IP + optional EDNS client subnet info for plugins
    client_info_t client_info;

    // EDNS Client Subnet response mask.
    // Not valid/useful in DNS reponses unless respond_edns_client_subnet is true
    // below, *and* the source mask was non-zero.
    // For static responses, this is set to zero by dnspacket.c
    // For dynamic responses, this is set from .ans_dyn{a,cname}.edns_client_mask,
    //   which is in turn defaulted to zero.
    unsigned edns_client_scope_mask;

    // Whether this request had a valid EDNS0 optrr
    bool use_edns;

    // Client sent EDNS Client Subnet option, and we must respond with one
    bool respond_edns_client_subnet;

    // If above is true, this records the original family value verbatim
    unsigned edns_client_family;

    // units of 100ms, sent by dnsio_tcp code
    unsigned edns0_tcp_keepalive;

    // If this is true, the query class was CH
    bool chaos;

    // Compression targets, for the few cases where we do general-case compression
    unsigned ctarget_count;
    ctarget_t ctargets[COMPTARGETS_MAX];
} dnsp_ctx_t;

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

void* dnspacket_ctx_init(dnspacket_stats_t** stats_out, const bool is_udp)
{
    dnsp_ctx_t* ctx = xcalloc(sizeof(*ctx));

    ctx->rand_state = gdnsd_rand32_init();
    ctx->is_udp = is_udp;
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

void dnspacket_ctx_cleanup(void* ctxv)
{
    gdnsd_plugins_action_iothread_cleanup();

    dnsp_ctx_t* ctx = (dnsp_ctx_t*)ctxv;
    free(ctx->dyn);
    free(ctx->rand_state);
    free(ctx);
}

F_NONNULL
static void reset_context(dnsp_ctx_t* ctx)
{
    memset(
        &ctx->this_max_response, 0,
        sizeof(dnsp_ctx_t) - offsetof(dnsp_ctx_t, this_max_response)
    );
}

// "buf" points to the question section of an input packet.
F_NONNULL
static unsigned parse_question(dnsp_ctx_t* ctx, const uint8_t* buf, const unsigned len)
{
    uint8_t* lqname_ptr = &ctx->lqname[1];
    unsigned pos = 0;
    unsigned llen;
    while ((llen = *lqname_ptr++ = buf[pos++])) {
        if (unlikely(llen & 0xC0)) {
            log_devdebug("Label compression detected in question, failing.");
            pos = 0;
            break;
        }

        if (unlikely(pos + llen >= len)) {
            log_devdebug("Query name truncated (runs off end of packet)");
            pos = 0;
            break;
        }

        if (unlikely(pos + llen > 254)) {
            log_devdebug("Query domain name too long");
            pos = 0;
            break;
        }

        while (llen--) {
            if (unlikely((buf[pos] < 0x5B) && (buf[pos] > 0x40)))
                *lqname_ptr++ = buf[pos++] | 0x20;
            else
                *lqname_ptr++ = buf[pos++];
        }
    }

    if (likely(pos)) {
        // Store the overall length of the lowercased name
        ctx->lqname[0] = pos;

        if (likely(pos + 4 <= len)) {
            ctx->qtype = ntohs(gdnsd_get_una16(&buf[pos]));
            pos += 2;
            const unsigned cls = ntohs(gdnsd_get_una16(&buf[pos]));
            pos += 2;
            if (cls != DNS_CLASS_IN && cls != DNS_CLASS_ANY) {
                if (cls == DNS_CLASS_CH) {
                    ctx->chaos = true;
                } else {
                    log_devdebug("Question class was not IN, CH, or ANY (was %u)", cls);
                    pos = 0;
                }
            }
        } else {
            log_devdebug("Packet length exhausted before parsing question type/class!");
            pos = 0;
        }
    }

    return pos;
}

// retval: true -> FORMERR, false -> OK
F_NONNULL
static bool handle_edns_client_subnet(dnsp_ctx_t* ctx, unsigned opt_len, const uint8_t* opt_data)
{
    bool rv = false;

    do {
        if (opt_len < 4) {
            log_devdebug("edns_client_subnet data too short (%u bytes)", opt_len);
            rv = true;
            break;
        }

        const unsigned family = ntohs(gdnsd_get_una16(opt_data));
        opt_data += 2;
        const unsigned src_mask = *opt_data++;
        const unsigned scope_mask = *opt_data++;
        if (scope_mask) {
            log_devdebug("edns_client_subnet: non-zero scope mask in request: %u", scope_mask);
            rv = true;
            break;
        }

        // Validate family iff src_mask is non-zero, and validate non-zero
        // src_mask as appropriate for the know families.
        if (src_mask) {
            if (family == 1U) { // IPv4
                if (src_mask > 32U) {
                    log_devdebug("edns_client_subnet: invalid src_mask of %u for IPv4", src_mask);
                    rv = true;
                    break;
                }
            } else if (family == 2U) { // IPv6
                if (src_mask > 128U) {
                    log_devdebug("edns_client_subnet: invalid src_mask of %u for IPv6", src_mask);
                    rv = true;
                    break;
                }
            } else {
                log_devdebug("edns_client_subnet has unknown family %u", family);
                rv = true;
                break;
            }
        }

        // There should be exactly enough address bytes to cover the provided source mask (possibly 0)
        const unsigned whole_bytes = src_mask >> 3;
        const unsigned trailing_bits = src_mask & 7;
        const unsigned addr_bytes = whole_bytes + (trailing_bits ? 1 : 0);
        if (opt_len != 4 + addr_bytes) {
            log_devdebug("edns_client_subnet: option length %u mismatches src_mask of %u", opt_len, src_mask);
            rv = true;
            break;
        }

        // Also, we need to check that any unmasked trailing bits in the final
        // byte are explicitly set to zero
        if (trailing_bits) {
            const unsigned final_byte = opt_data[src_mask >> 3];
            const unsigned final_mask = ~(0xFFu << (8U - trailing_bits)) & 0xFFu;
            if (final_byte & final_mask) {
                log_devdebug("edns_client_subnet: non-zero bits beyond src_mask");
                rv = true;
                break;
            }
        }

        // If we made it this far, the input data is completely-valid, and
        // should be used if the source mask is non-zero:
        if (src_mask) {
            if (family == 1U) { // IPv4
                ctx->client_info.edns_client.sa.sa_family = AF_INET;
                memcpy(&ctx->client_info.edns_client.sin.sin_addr.s_addr, opt_data, addr_bytes);
            } else {
                gdnsd_assert(family == 2U); // IPv6
                ctx->client_info.edns_client.sa.sa_family = AF_INET6;
                memcpy(ctx->client_info.edns_client.sin6.sin6_addr.s6_addr, opt_data, addr_bytes);
            }
        }

        ctx->this_max_response -= (8 + addr_bytes); // leave room for response option
        ctx->respond_edns_client_subnet = true;
        ctx->client_info.edns_client_mask = src_mask;
        ctx->edns_client_family = family; // copy family literally, in case src_mask==0 + junk family echo
    } while (0);

    gdnsd_assert(ctx->stats);
    stats_own_inc(&ctx->stats->edns_clientsub);
    return rv;
}

// retval: true -> FORMERR, false -> OK
F_NONNULL
static bool handle_edns_option(dnsp_ctx_t* ctx, unsigned opt_code, unsigned opt_len, const uint8_t* opt_data)
{
    bool rv = false;
    if (opt_code == EDNS_CLIENTSUB_OPTCODE) {
        if (gcfg->edns_client_subnet)
            rv = handle_edns_client_subnet(ctx, opt_len, opt_data);
    } else if (opt_code == EDNS_TCP_KEEPALIVE_OPTCODE) {
        // no-op
        // Note we don't explicitly parse RFC 7828 edns0 tcp keepalive here, but
        // this is where we'd install the handler function if we did.  Our
        // implementation does not choose to change its behavior (e.g. longer
        // timeouts) based on the client's request for keepalive, and always sends
        // its own keepalive option whenever possible (any time the client tcp
        // query has an edns0 opt rr at all).  Therefore we gain little by
        // attempting to parse the client's option here, and we can just ignore it.
        // We could hypothetically parse it just to FORMERR-reject it if the client
        // violates the RFC by sending a non-zero data length, but that seems
        // needlessly aggressive.
    } else {
        log_devdebug("Unknown EDNS option code: %x", opt_code);
    }

    return rv;
}

// retval: true -> FORMERR, false -> OK
F_NONNULL
static bool handle_edns_options(dnsp_ctx_t* ctx, unsigned rdlen, const uint8_t* rdata)
{
    gdnsd_assert(rdlen);

    bool rv = false;

    // minimum edns option length is 4 bytes (2 byte option code, 2 byte data len)
    while (rdlen) {
        if (rdlen < 4) {
            log_devdebug("EDNS option too short");
            rv = true;
            break;
        }
        unsigned opt_code = ntohs(gdnsd_get_una16(rdata));
        rdata += 2;
        unsigned opt_dlen = ntohs(gdnsd_get_una16(rdata));
        rdata += 2;
        rdlen -= 4;
        if (opt_dlen > rdlen) {
            log_devdebug("EDNS option too long");
            rv = true;
            break;
        }
        if (handle_edns_option(ctx, opt_code, opt_dlen, rdata)) {
            rv = true; // option handler indicated FORMERR
            break;
        }
        rdlen -= opt_dlen;
        rdata += opt_dlen;
    }

    return rv;
}

typedef enum {
    DECODE_IGNORE  = -4, // totally invalid packet (len < header len or unparseable question, and we do not respond)
    DECODE_FORMERR = -3, // slightly better but still invalid input, we return FORMERR
    DECODE_BADVERS = -2, // EDNS version higher than ours (0)
    DECODE_NOTIMP  = -1, // non-QUERY opcode or [AI]XFER, we return NOTIMP
    DECODE_OK      =  0, // normal and valid
} rcode_rv_t;

F_NONNULL
static rcode_rv_t parse_optrr(dnsp_ctx_t* ctx, const wire_dns_rr_opt_t* opt, const gdnsd_anysin_t* asin V_UNUSED, const unsigned packet_len, const unsigned offset)
{
    gdnsd_assert(ctx->stats);

    rcode_rv_t rcode = DECODE_OK;
    ctx->use_edns = true;            // send OPT RR with response
    stats_own_inc(&ctx->stats->edns);
    if (likely(DNS_OPTRR_GET_VERSION(opt) == 0)) {
        if (likely(ctx->is_udp)) {
            unsigned client_req = DNS_OPTRR_GET_MAXSIZE(opt);
            if (client_req < 512U)
                client_req = 512U;
            ctx->this_max_response = client_req < gcfg->max_edns_response
                                     ? client_req
                                     : gcfg->max_edns_response;
        }

        // leave room for basic OPT RR (edns-client-subnet room is addressed elsewhere)
        ctx->this_max_response -= 11;

        // Leave room for NSID if configured
        if (gcfg->nsid_len)
            ctx->this_max_response -= (4U + gcfg->nsid_len);

        unsigned rdlen = htons(gdnsd_get_una16(&opt->rdlen));
        if (rdlen) {
            if (packet_len < offset + sizeof_optrr + rdlen) {
                log_devdebug("Received EDNS OPT RR with options data longer than packet length from %s", logf_anysin(asin));
                rcode = DECODE_FORMERR;
            } else if (handle_edns_options(ctx, rdlen, opt->rdata)) {
                rcode = DECODE_FORMERR;
            }
        }
    } else {
        log_devdebug("Received EDNS OPT RR with VERSION > 0 (BADVERSION) from %s", logf_anysin(asin));
        rcode = DECODE_BADVERS;
    }

    return rcode;
}

F_NONNULL
static rcode_rv_t decode_query(dnsp_ctx_t* ctx, unsigned* question_len_ptr, const unsigned packet_len, const gdnsd_anysin_t* asin)
{
    gdnsd_assert(ctx->packet);

    rcode_rv_t rcode = DECODE_OK;

    do {
        // 5 is the minimal question length (1 byte root, 2 bytes each type and class)
        if (unlikely(packet_len < (sizeof(wire_dns_header_t) + 5))) {
            log_devdebug("Ignoring short request from %s of length %u", logf_anysin(asin), packet_len);
            rcode = DECODE_IGNORE;
            break;
        }

        uint8_t* packet = ctx->packet;
        const wire_dns_header_t* hdr = (const wire_dns_header_t*)packet;

        /*
            log_devdebug("Query header details: ID:%hu QR:%i OPCODE:%hhu AA:%i TC:%i RD:%i RA:%i AD:%i CD:%i RCODE:%hhu QDCOUNT:%hu ANCOUNT:%hu NSCOUNT:%hu ARCOUNT:%hu",
                DNSH_GET_ID(hdr), DNSH_GET_QR(hdr) ? 1 : 0,
                DNSH_GET_OPCODE(hdr), DNSH_GET_AA(hdr) ? 1 : 0,
                DNSH_GET_TC(hdr) ? 1 : 0, DNSH_GET_RD(hdr) ? 1 : 0,
                DNSH_GET_RA(hdr) ? 1 : 0, DNSH_GET_AD(hdr) ? 1 : 0,
                DNSH_GET_CD(hdr) ? 1 : 0, DNSH_GET_RCODE(hdr),
                DNSH_GET_QDCOUNT(hdr), DNSH_GET_ANCOUNT(hdr),
                DNSH_GET_NSCOUNT(hdr), DNSH_GET_ARCOUNT(hdr)
            );
        */

        if (unlikely(DNSH_GET_QDCOUNT(hdr) != 1)) {
            log_devdebug("Received request from %s with %hu questions, ignoring", logf_anysin(asin), DNSH_GET_QDCOUNT(hdr));
            rcode = DECODE_IGNORE;
            break;
        }

        if (unlikely(DNSH_GET_QR(hdr))) {
            log_devdebug("QR bit set in query from %s, ignoring", logf_anysin(asin));
            rcode = DECODE_IGNORE;
            break;
        }

        if (unlikely(DNSH_GET_TC(hdr))) {
            log_devdebug("TC bit set in query from %s, ignoring", logf_anysin(asin));
            rcode = DECODE_IGNORE;
            break;
        }

        unsigned offset = sizeof(wire_dns_header_t);
        if (unlikely(!(*question_len_ptr = parse_question(ctx, &packet[offset], packet_len - offset)))) {
            log_devdebug("Failed to parse question, ignoring %s", logf_anysin(asin));
            rcode = DECODE_IGNORE;
            break;
        }

        if (DNSH_GET_OPCODE(hdr)) {
            log_devdebug("Non-QUERY request (NOTIMP) from %s, opcode is %i", logf_anysin(asin), DNSH_GET_OPCODE(hdr));
            rcode = DECODE_NOTIMP;
            break;
        }

        if (unlikely(ctx->qtype == DNS_TYPE_AXFR)) {
            log_devdebug("AXFR attempted (NOTIMP) from %s", logf_anysin(asin));
            rcode = DECODE_NOTIMP;
            break;
        }

        if (unlikely(ctx->qtype == DNS_TYPE_IXFR)) {
            log_devdebug("IXFR attempted (NOTIMP) from %s", logf_anysin(asin));
            rcode = DECODE_NOTIMP;
            break;
        }

        offset += *question_len_ptr;

        // this_max_response isn't used in the TCP case, but other code will
        // subtract from it anyways, so set a large value to keep things sane.
        // parse_optrr() will raise this value in the udp edns0 case as necc.
        ctx->this_max_response = ctx->is_udp ? 512U : MAX_RESPONSE;

        // Note this will only catch OPT RR as the first addtl record.  It may not always
        //  be in that place, and it would be more robust to attempt to search the addtl
        //  records for the first OPT one (there should only be one OPT).  For that matter,
        //  for reasons yet unknown, future DNS packets might have other intervening non-
        //  addtl records (answer, auth).  But this handles the common use case today,
        //  and the worst fallout is an edns0 detection failure, which results in traditional
        //  dns comms.
        // At some point in the future, we need to pay attention all of ancount/nscount/adcount,
        //  and step through any such records looking for an appropriate OPT record in addtl.
        const wire_dns_rr_opt_t* opt = (const wire_dns_rr_opt_t*)&packet[offset + 1];
        if (DNSH_GET_ARCOUNT(hdr)
                && likely(packet_len >= (offset + sizeof_optrr + 1))
                && likely(packet[offset] == '\0')
                && likely(DNS_OPTRR_GET_TYPE(opt) == DNS_TYPE_OPT)) {
            rcode = parse_optrr(ctx, opt, asin, packet_len, offset + 1);
        }
    } while (0);

    return rcode;
}

// Always first thing added, once we hit a situation where general compression is warranted
F_NONNULL
static void ctargets_add_qname(dnsp_ctx_t* ctx)
{
    gdnsd_assert(!ctx->ctarget_count);
    unsigned offset = sizeof(wire_dns_header_t);
    const uint8_t* orig = &ctx->packet[offset];
    unsigned len = ctx->lqname[0];
    // root is "." => "\0" => len==1 and is not worth compressing
    // next-shortest is "a." => "\1a\0" => len==3, and is worth compressing
    while (len > 2 && ctx->ctarget_count < COMPTARGETS_MAX) {
        ctx->ctargets[ctx->ctarget_count].orig = orig;
        ctx->ctargets[ctx->ctarget_count].len = len;
        ctx->ctargets[ctx->ctarget_count].offset = offset;
        ctx->ctarget_count++;
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
static unsigned store_dname_comp(dnsp_ctx_t* ctx, const uint8_t* dname, const unsigned offset, const bool make_targets)
{
    // most response types don't use general compression at all, so we only
    // initialize qname into the set on the first use of this per response
    if (!ctx->ctarget_count)
        ctargets_add_qname(ctx);

    const unsigned dn_full_len = *dname++; // dname now starts at first label len
    const uint8_t* dname_read = dname;
    unsigned dnread_len = dn_full_len;
    unsigned dnread_offset = offset;

    // Search for a match, take the first match found since they're pre-sorted by len
    for (unsigned i = 0; i < ctx->ctarget_count; i++) {
        // So long as the target (longest remaining in sorted list) is shorter
        // than the input, we must iterate storing new names into the list
        while (ctx->ctargets[i].len < dnread_len) {
            if (make_targets && ctx->ctarget_count < COMPTARGETS_MAX) {
                gdnsd_assert(dnread_len > 2U); // implied by rest of the logic...
                unsigned to_move = ctx->ctarget_count - i;
                memmove(ctx->ctargets + i + 1U, ctx->ctargets + i, to_move * sizeof(ctarget_t));
                ctx->ctargets[i].orig = dname_read;
                ctx->ctargets[i].len = dnread_len;
                ctx->ctargets[i].offset = dnread_offset;
                i++;
                ctx->ctarget_count++;
            }
            const unsigned jump = *dname_read + 1U;
            dname_read += jump;
            dnread_offset += jump;
            dnread_len -= jump;
        }

        if (ctx->ctargets[i].len == dnread_len && !memcmp(dname_read, ctx->ctargets[i].orig, dnread_len)) {
            // exact match!
            unsigned match_depth = dn_full_len - dnread_len;
            memcpy(&ctx->packet[offset], dname, match_depth);
            gdnsd_put_una16(htons(0xC000u | ctx->ctargets[i].offset), &ctx->packet[offset + match_depth]);
            gdnsd_assert(!(ctx->packet[ctx->ctargets[i].offset] & 0xC0u)); // no ptr-to-ptr
            return match_depth + 2U;
        }

        // otherwise ctx->ctargets[i].len is > dnread_len, or == dnread_len but no
        // match yet, so we iterate further in the sorted list to find a case
        // that triggers one of the above
    }

    // Target list exhausted without any match.
    // For the make_targets case, we may still have one or more new entries to
    // add to the ctargets set, all at the end (<= len of shortest existing)
    if (make_targets) {
        while (dnread_len > 2U && ctx->ctarget_count < COMPTARGETS_MAX) {
            ctx->ctargets[ctx->ctarget_count].orig = dname_read;
            ctx->ctargets[ctx->ctarget_count].len = dnread_len;
            ctx->ctargets[ctx->ctarget_count].offset = dnread_offset;
            ctx->ctarget_count++;
            const unsigned jump = *dname_read + 1U;
            dname_read += jump;
            dnread_offset += jump;
            dnread_len -= jump;
        }
    }

    // store dname in full
    memcpy(&ctx->packet[offset], dname, dn_full_len);
    return dn_full_len;
}

// store a dname without attempting compression-related things at all
F_NONNULL
static unsigned store_dname_nocomp(dnsp_ctx_t* ctx, const uint8_t* dn, const unsigned offset)
{
    const unsigned sz = *dn++;
    memcpy(&ctx->packet[offset], dn, sz);
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
static unsigned repeat_name(dnsp_ctx_t* ctx, unsigned store_at_offset, unsigned orig_offset)
{
    uint8_t* packet = ctx->packet;
    gdnsd_assert(packet);

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

// These macros define a common pattern around the body of a loop encoding
//  an rrset.  They behave like a for-loop specified as...
//    for (unsigned i = 0; i < _limit; i++) { ... }
//  ... with the exception that they start at a pseudo-random "i" value
//  from the sequence 0->(_total-1), and "i" will wrap-around to zero
//  as appropriate to stay within the _total while iterating _limit times.

#define OFFSET_LOOP_START(_total, _limit) \
    {\
        const unsigned _tot = (_total);\
        unsigned _x_count = (_limit);\
        unsigned i = gdnsd_rand32_get(ctx->rand_state) % _tot;\
        while (_x_count--) {\

#define OFFSET_LOOP_END \
            if (++i == _tot)\
              i = 0;\
        }\
    }

F_NONNULL
static unsigned enc_a_static(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_addr_t* rrset, const unsigned nameptr, const bool is_addtl)
{
    gdnsd_assert(rrset->gen.count);

    uint8_t* packet = ctx->packet;

    if (is_addtl)
        ctx->arcount += rrset->limit_v4;
    else
        ctx->ancount += rrset->limit_v4;

    const uint32_t* addr_ptr = (!rrset->count_v6 && rrset->gen.count <= LTREE_V4A_SIZE)
                               ? &rrset->v4a[0]
                               : rrset->addrs.v4;
    OFFSET_LOOP_START(rrset->gen.count, rrset->limit_v4) {
        offset += repeat_name(ctx, offset, nameptr);
        gdnsd_put_una32(DNS_RRFIXED_A, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 4;
        gdnsd_put_una16(htons(4), &packet[offset]);
        offset += 2;
        gdnsd_put_una32(addr_ptr[i], &packet[offset]);
        offset += 4;
    }
    OFFSET_LOOP_END
    return offset;
}

F_NONNULL
static unsigned enc_aaaa_static(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_addr_t* rrset, const unsigned nameptr, const bool is_addtl)
{
    gdnsd_assert(rrset->count_v6);

    uint8_t* packet = ctx->packet;

    if (is_addtl)
        ctx->arcount += rrset->limit_v6;
    else
        ctx->ancount += rrset->limit_v6;

    OFFSET_LOOP_START(rrset->count_v6, rrset->limit_v6) {
        offset += repeat_name(ctx, offset, nameptr);
        gdnsd_put_una32(DNS_RRFIXED_AAAA, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 4;
        gdnsd_put_una16(htons(16), &packet[offset]);
        offset += 2;
        memcpy(&packet[offset], rrset->addrs.v6 + (i << 4), 16);
        offset += 16;
    }
    OFFSET_LOOP_END
    return offset;
}

F_NONNULL
static unsigned enc_a_dynamic(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_addr_t* rrset, const unsigned nameptr, const unsigned ttl)
{
    gdnsd_assert(ctx->packet);

    uint8_t* packet = ctx->packet;
    const dyn_result_t* dr = ctx->dyn;
    gdnsd_assert(!dr->is_cname);
    gdnsd_assert(dr->count_v4);

    const unsigned limit_v4 = rrset->limit_v4 && rrset->limit_v4 < dr->count_v4
                              ? rrset->limit_v4
                              : dr->count_v4;

    ctx->ancount += limit_v4;

    OFFSET_LOOP_START(dr->count_v4, limit_v4) {
        offset += repeat_name(ctx, offset, nameptr);
        gdnsd_put_una32(DNS_RRFIXED_A, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(ttl, &packet[offset]);
        offset += 4;
        gdnsd_put_una16(htons(4), &packet[offset]);
        offset += 2;
        gdnsd_put_una32(dr->v4[i], &packet[offset]);
        offset += 4;
    }
    OFFSET_LOOP_END
    return offset;
}

F_NONNULL
static unsigned enc_aaaa_dynamic(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_addr_t* rrset, const unsigned nameptr, const unsigned ttl)
{
    gdnsd_assert(ctx->packet);

    uint8_t* packet = ctx->packet;
    const dyn_result_t* dr = ctx->dyn;
    gdnsd_assert(!dr->is_cname);
    gdnsd_assert(dr->count_v6);

    const unsigned limit_v6 = rrset->limit_v6 && rrset->limit_v6 < dr->count_v6
                              ? rrset->limit_v6
                              : dr->count_v6;

    ctx->ancount += limit_v6;

    const uint8_t* v6 = &dr->storage[result_v6_offset];
    OFFSET_LOOP_START(dr->count_v6, limit_v6) {
        offset += repeat_name(ctx, offset, nameptr);
        gdnsd_put_una32(DNS_RRFIXED_AAAA, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(ttl, &packet[offset]);
        offset += 4;
        gdnsd_put_una16(htons(16), &packet[offset]);
        offset += 2;
        memcpy(&packet[offset], &v6[i << 4], 16);
        offset += 16;
    }
    OFFSET_LOOP_END
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
    const gdnsd_sttl_t sttl = func(res, &ctx->client_info, dr);
    if (dr->edns_scope_mask > ctx->edns_client_scope_mask)
        ctx->edns_client_scope_mask = dr->edns_scope_mask;
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

// This is only used for filling out all possible A/AAAA/DYNA in the answer
// section in response to an ANY query
F_NONNULL
static unsigned encode_rrs_anyaddr(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_addr_t* rrset)
{
    if (rrset->gen.count | rrset->count_v6) {
        if (rrset->gen.count)
            offset = enc_a_static(ctx, offset, rrset, ctx->qname_comp, false);
        if (rrset->count_v6)
            offset = enc_aaaa_static(ctx, offset, rrset, ctx->qname_comp, false);
    } else {
        const unsigned ttl = do_dyn_callback(ctx, rrset->dyn.func, rrset->dyn.resource, rrset->gen.ttl, rrset->dyn.ttl_min);
        gdnsd_assert(!ctx->dyn->is_cname);
        if (ctx->dyn->count_v4)
            offset = enc_a_dynamic(ctx, offset, rrset, ctx->qname_comp, ttl);
        if (ctx->dyn->count_v6)
            offset = enc_aaaa_dynamic(ctx, offset, rrset, ctx->qname_comp, ttl);
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_a(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_addr_t* rrset)
{
    gdnsd_assert(offset);
    gdnsd_assert(ctx->qtype == DNS_TYPE_A);

    if (rrset->gen.count) {
        offset = enc_a_static(ctx, offset, rrset, ctx->qname_comp, false);
    } else if (!rrset->count_v6) {
        const unsigned ttl = do_dyn_callback(ctx, rrset->dyn.func, rrset->dyn.resource, rrset->gen.ttl, rrset->dyn.ttl_min);
        gdnsd_assert(!ctx->dyn->is_cname);
        if (ctx->dyn->count_v4)
            offset = enc_a_dynamic(ctx, offset, rrset, ctx->qname_comp, ttl);
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_aaaa(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_addr_t* rrset)
{
    gdnsd_assert(offset);
    gdnsd_assert(ctx->qtype == DNS_TYPE_AAAA);

    if (rrset->count_v6) {
        offset = enc_aaaa_static(ctx, offset, rrset, ctx->qname_comp, false);
    } else if (!rrset->gen.count) {
        const unsigned ttl = do_dyn_callback(ctx, rrset->dyn.func, rrset->dyn.resource, rrset->gen.ttl, rrset->dyn.ttl_min);
        gdnsd_assert(!ctx->dyn->is_cname);
        if (ctx->dyn->count_v6)
            offset = enc_aaaa_dynamic(ctx, offset, rrset, ctx->qname_comp, ttl);
    }

    return offset;
}

// This is only used when qtype == NS|ANY and the qname doesn't land in a
// delegation cut, which implies it only gets called for explicit output of NS
// records at a zone root.  ltree doesn't currently allow these to have glue.
F_NONNULL
static unsigned encode_rrs_ns(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_ns_t* rrset)
{
    gdnsd_assert(offset);
    gdnsd_assert(rrset->gen.count); // we never call encode_rrs_ns without an NS record present

    uint8_t* packet = ctx->packet;

    const unsigned rrct = rrset->gen.count;
    gdnsd_assert(rrct <= MAX_NS_COUNT);
    ctx->ancount += rrct;
    for (unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(ctx, offset, ctx->qname_comp);
        gdnsd_put_una32(DNS_RRFIXED_NS, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;
        const unsigned newlen = store_dname_comp(ctx, rrset->rdata[i].dname, offset, true);
        gdnsd_put_una16(htons(newlen), &packet[offset - 2]);
        gdnsd_assert(!rrset->rdata[i].glue);
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

    uint8_t* packet = ctx->packet;

    const unsigned rrct = rrset->gen.count;
    gdnsd_assert(rrct <= MAX_NS_COUNT);
    ctx->nscount += rrct;
    for (unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(ctx, offset, ctx->auth_comp);
        gdnsd_put_una32(DNS_RRFIXED_NS, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;
        const unsigned newlen = store_dname_comp(ctx, rrset->rdata[i].dname, offset, true);
        gdnsd_put_una16(htons(newlen), &packet[offset - 2]);
        glue_name_offset[i] = offset;
        offset += newlen;
    }

    for (unsigned i = 0; i < rrct; i++) {
        ltree_rrset_addr_t* glue = rrset->rdata[i].glue;
        if (glue) {
            gdnsd_assert(glue->gen.count | glue->count_v6);
            if (glue->gen.count)
                offset = enc_a_static(ctx, offset, glue, glue_name_offset[i], true);
            if (glue->count_v6)
                offset = enc_aaaa_static(ctx, offset, glue, glue_name_offset[i], true);
        }
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_ptr(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_ptr_t* rrset)
{
    gdnsd_assert(ctx->packet);
    gdnsd_assert(offset);

    uint8_t* packet = ctx->packet;

    const unsigned rrct = rrset->gen.count;
    ctx->ancount += rrct;
    for (unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(ctx, offset, ctx->qname_comp);
        gdnsd_put_una32(DNS_RRFIXED_PTR, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;
        const unsigned newlen = store_dname_nocomp(ctx, rrset->rdata[i].dname, offset);
        gdnsd_put_una16(htons(newlen), &packet[offset - 2]);
        offset += newlen;
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_mx(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_mx_t* rrset)
{
    gdnsd_assert(ctx->packet);
    gdnsd_assert(offset);

    uint8_t* packet = ctx->packet;

    const unsigned rrct = rrset->gen.count;
    ctx->ancount += rrct;
    for (unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(ctx, offset, ctx->qname_comp);
        gdnsd_put_una32(DNS_RRFIXED_MX, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;
        const ltree_rdata_mx_t* rd = &rrset->rdata[i];
        gdnsd_put_una16(rd->pref, &packet[offset]);
        offset += 2;
        const unsigned newlen = store_dname_comp(ctx, rd->dname, offset, true);
        gdnsd_put_una16(htons(newlen + 2), &packet[offset - 4]);
        offset += newlen;
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_srv(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_srv_t* rrset)
{
    gdnsd_assert(ctx->packet);

    uint8_t* packet = ctx->packet;

    const unsigned rrct = rrset->gen.count;
    ctx->ancount += rrct;
    for (unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(ctx, offset, ctx->qname_comp);
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
        const unsigned newlen = store_dname_nocomp(ctx, rd->dname, offset);
        gdnsd_put_una16(htons(newlen + 6), &packet[offset - 8]);
        offset += newlen;
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_naptr(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_naptr_t* rrset)
{
    gdnsd_assert(ctx->packet);
    gdnsd_assert(offset);

    uint8_t* packet = ctx->packet;

    const unsigned rrct = rrset->gen.count;
    ctx->ancount += rrct;
    for (unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(ctx, offset, ctx->qname_comp);
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
        offset += store_dname_nocomp(ctx, rd->dname, offset);
        gdnsd_put_una16(htons(offset - rdata_offset), &packet[rdata_offset - 2]);
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_txt(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_txt_t* rrset)
{
    gdnsd_assert(ctx->packet);
    gdnsd_assert(offset);

    uint8_t* packet = ctx->packet;

    const unsigned rrct = rrset->gen.count;
    ctx->ancount += rrct;
    for (unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(ctx, offset, ctx->qname_comp);
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
static unsigned encode_rr_cname(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_cname_t* rd)
{
    gdnsd_assert(ctx->packet);
    gdnsd_assert(offset);

    uint8_t* packet = ctx->packet;

    offset += repeat_name(ctx, offset, ctx->qname_comp);
    gdnsd_put_una32(DNS_RRFIXED_CNAME, &packet[offset]);
    offset += 4;
    gdnsd_put_una32(rd->gen.ttl, &packet[offset]);
    offset += 6;
    const unsigned rdata_offset = offset;
    offset += store_dname_comp(ctx, rd->dname, offset, false);
    gdnsd_put_una16(htons(offset - rdata_offset), &packet[rdata_offset - 2]);
    ctx->ancount++;

    return offset;
}

F_NONNULL
static unsigned encode_rr_cname_chain(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_cname_t* rd)
{
    gdnsd_assert(ctx->packet);
    gdnsd_assert(offset);

    uint8_t* packet = ctx->packet;

    offset += repeat_name(ctx, offset, ctx->qname_comp);
    gdnsd_put_una32(DNS_RRFIXED_CNAME, &packet[offset]);
    offset += 4;
    gdnsd_put_una32(rd->gen.ttl, &packet[offset]);
    offset += 6;
    const unsigned rdata_offset = offset;
    offset += store_dname_comp(ctx, rd->dname, offset, false);
    gdnsd_put_una16(htons(offset - rdata_offset), &packet[rdata_offset - 2]);

    // adjust qname_comp to point at cname's data for re-querying
    ctx->qname_comp = rdata_offset;

    // cname answer count tracked separately, so that other logic on the
    // zeroness of ancount still works
    ctx->cname_ancount++;

    return offset;
}

F_NONNULL
static unsigned encode_rr_soa(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_soa_t* rdata)
{
    gdnsd_assert(ctx->packet);
    gdnsd_assert(offset);

    uint8_t* packet = ctx->packet;

    offset += repeat_name(ctx, offset, ctx->auth_comp);
    gdnsd_put_una32(DNS_RRFIXED_SOA, &packet[offset]);
    offset += 4;
    gdnsd_put_una32(rdata->gen.ttl, &packet[offset]);
    offset += 6;

    // fill in the rdata
    const unsigned rdata_offset = offset;
    offset += store_dname_comp(ctx, rdata->master, offset, true);
    offset += store_dname_comp(ctx, rdata->email, offset, false);
    memcpy(&packet[offset], &rdata->times, 20);
    offset += 20; // 5x 32-bits

    // set rdata_len
    gdnsd_put_una16(htons(offset - rdata_offset), &packet[rdata_offset - 2]);

    ctx->ancount++;

    return offset;
}

static unsigned encode_rrs_rfc3597(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_rfc3597_t* rrset)
{
    gdnsd_assert(ctx->packet);
    gdnsd_assert(offset);

    // assert that DYNC (which is technically in the range
    //  served exclusively by this function, but which we
    //  should be translating earlier and never serving on
    //  the wire) never appears here.
    gdnsd_assert(rrset->gen.type != DNS_TYPE_DYNC);

    uint8_t* packet = ctx->packet;

    const unsigned rrct = rrset->gen.count;
    ctx->ancount += rrct;
    for (unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(ctx, offset, ctx->qname_comp);
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

F_NONNULLX(1)
static unsigned encode_rrs_any(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_t* res_rrsets)
{
    const ltree_rrset_t* rrset = res_rrsets;
    while (rrset) {
        switch (rrset->gen.type) {
        case DNS_TYPE_A:
            offset = encode_rrs_anyaddr(ctx, offset, &rrset->addr);
            break;
        case DNS_TYPE_SOA:
            offset = encode_rr_soa(ctx, offset, &rrset->soa);
            break;
        case DNS_TYPE_NS:
            offset = encode_rrs_ns(ctx, offset, &rrset->ns);
            break;
        case DNS_TYPE_PTR:
            offset = encode_rrs_ptr(ctx, offset, &rrset->ptr);
            break;
        case DNS_TYPE_MX:
            offset = encode_rrs_mx(ctx, offset, &rrset->mx);
            break;
        case DNS_TYPE_SRV:
            offset = encode_rrs_srv(ctx, offset, &rrset->srv);
            break;
        case DNS_TYPE_NAPTR:
            offset = encode_rrs_naptr(ctx, offset, &rrset->naptr);
            break;
        case DNS_TYPE_TXT:
            offset = encode_rrs_txt(ctx, offset, &rrset->txt);
            break;
        case DNS_TYPE_CNAME:
            offset = encode_rr_cname(ctx, offset, &rrset->cname);
            break;
        default:
            gdnsd_assert(rrset->gen.type != DNS_TYPE_DYNC);
            offset = encode_rrs_rfc3597(ctx, offset, &rrset->rfc3597);
            break;
        }
        rrset = rrset->gen.next;
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

static encode_funcptr encode_funcptrs[256] = {
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
    EC encode_rrs_rfc3597, // 128
    EC encode_rrs_rfc3597, // 129
    EC encode_rrs_rfc3597, // 130
    EC encode_rrs_rfc3597, // 131
    EC encode_rrs_rfc3597, // 132
    EC encode_rrs_rfc3597, // 133
    EC encode_rrs_rfc3597, // 134
    EC encode_rrs_rfc3597, // 135
    EC encode_rrs_rfc3597, // 136
    EC encode_rrs_rfc3597, // 137
    EC encode_rrs_rfc3597, // 138
    EC encode_rrs_rfc3597, // 139
    EC encode_rrs_rfc3597, // 140
    EC encode_rrs_rfc3597, // 141
    EC encode_rrs_rfc3597, // 142
    EC encode_rrs_rfc3597, // 143
    EC encode_rrs_rfc3597, // 144
    EC encode_rrs_rfc3597, // 145
    EC encode_rrs_rfc3597, // 146
    EC encode_rrs_rfc3597, // 147
    EC encode_rrs_rfc3597, // 148
    EC encode_rrs_rfc3597, // 149
    EC encode_rrs_rfc3597, // 150
    EC encode_rrs_rfc3597, // 151
    EC encode_rrs_rfc3597, // 152
    EC encode_rrs_rfc3597, // 153
    EC encode_rrs_rfc3597, // 154
    EC encode_rrs_rfc3597, // 155
    EC encode_rrs_rfc3597, // 156
    EC encode_rrs_rfc3597, // 157
    EC encode_rrs_rfc3597, // 158
    EC encode_rrs_rfc3597, // 159
    EC encode_rrs_rfc3597, // 160
    EC encode_rrs_rfc3597, // 161
    EC encode_rrs_rfc3597, // 162
    EC encode_rrs_rfc3597, // 163
    EC encode_rrs_rfc3597, // 164
    EC encode_rrs_rfc3597, // 165
    EC encode_rrs_rfc3597, // 166
    EC encode_rrs_rfc3597, // 167
    EC encode_rrs_rfc3597, // 168
    EC encode_rrs_rfc3597, // 169
    EC encode_rrs_rfc3597, // 170
    EC encode_rrs_rfc3597, // 171
    EC encode_rrs_rfc3597, // 172
    EC encode_rrs_rfc3597, // 173
    EC encode_rrs_rfc3597, // 174
    EC encode_rrs_rfc3597, // 175
    EC encode_rrs_rfc3597, // 176
    EC encode_rrs_rfc3597, // 177
    EC encode_rrs_rfc3597, // 178
    EC encode_rrs_rfc3597, // 179
    EC encode_rrs_rfc3597, // 180
    EC encode_rrs_rfc3597, // 181
    EC encode_rrs_rfc3597, // 182
    EC encode_rrs_rfc3597, // 183
    EC encode_rrs_rfc3597, // 184
    EC encode_rrs_rfc3597, // 185
    EC encode_rrs_rfc3597, // 186
    EC encode_rrs_rfc3597, // 187
    EC encode_rrs_rfc3597, // 188
    EC encode_rrs_rfc3597, // 189
    EC encode_rrs_rfc3597, // 190
    EC encode_rrs_rfc3597, // 191
    EC encode_rrs_rfc3597, // 192
    EC encode_rrs_rfc3597, // 193
    EC encode_rrs_rfc3597, // 194
    EC encode_rrs_rfc3597, // 195
    EC encode_rrs_rfc3597, // 196
    EC encode_rrs_rfc3597, // 197
    EC encode_rrs_rfc3597, // 198
    EC encode_rrs_rfc3597, // 199
    EC encode_rrs_rfc3597, // 200
    EC encode_rrs_rfc3597, // 201
    EC encode_rrs_rfc3597, // 202
    EC encode_rrs_rfc3597, // 203
    EC encode_rrs_rfc3597, // 204
    EC encode_rrs_rfc3597, // 205
    EC encode_rrs_rfc3597, // 206
    EC encode_rrs_rfc3597, // 207
    EC encode_rrs_rfc3597, // 208
    EC encode_rrs_rfc3597, // 209
    EC encode_rrs_rfc3597, // 210
    EC encode_rrs_rfc3597, // 211
    EC encode_rrs_rfc3597, // 212
    EC encode_rrs_rfc3597, // 213
    EC encode_rrs_rfc3597, // 214
    EC encode_rrs_rfc3597, // 215
    EC encode_rrs_rfc3597, // 216
    EC encode_rrs_rfc3597, // 217
    EC encode_rrs_rfc3597, // 218
    EC encode_rrs_rfc3597, // 219
    EC encode_rrs_rfc3597, // 220
    EC encode_rrs_rfc3597, // 221
    EC encode_rrs_rfc3597, // 222
    EC encode_rrs_rfc3597, // 223
    EC encode_rrs_rfc3597, // 224
    EC encode_rrs_rfc3597, // 225
    EC encode_rrs_rfc3597, // 226
    EC encode_rrs_rfc3597, // 227
    EC encode_rrs_rfc3597, // 228
    EC encode_rrs_rfc3597, // 229
    EC encode_rrs_rfc3597, // 230
    EC encode_rrs_rfc3597, // 231
    EC encode_rrs_rfc3597, // 232
    EC encode_rrs_rfc3597, // 233
    EC encode_rrs_rfc3597, // 234
    EC encode_rrs_rfc3597, // 235
    EC encode_rrs_rfc3597, // 236
    EC encode_rrs_rfc3597, // 237
    EC encode_rrs_rfc3597, // 238
    EC encode_rrs_rfc3597, // 239
    EC encode_rrs_rfc3597, // 240
    EC encode_rrs_rfc3597, // 241
    EC encode_rrs_rfc3597, // 242
    EC encode_rrs_rfc3597, // 243
    EC encode_rrs_rfc3597, // 244
    EC encode_rrs_rfc3597, // 245
    EC encode_rrs_rfc3597, // 246
    EC encode_rrs_rfc3597, // 247
    EC encode_rrs_rfc3597, // 248
    EC encode_rrs_rfc3597, // 249
    EC encode_rrs_rfc3597, // 250
    NULL,                  // 251 - IXFR
    NULL,                  // 252 - AXFR
    EC encode_rrs_rfc3597, // 253
    EC encode_rrs_rfc3597, // 254
    NULL,                  // 255 - ANY
};

F_NONNULLX(1)
static unsigned construct_normal_response(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_t* res_rrsets)
{
    if (ctx->qtype == DNS_TYPE_ANY) {
        offset = encode_rrs_any(ctx, offset, res_rrsets);
    } else if (res_rrsets) {
        const ltree_rrset_t* node_rrset = res_rrsets;
        unsigned etype = ctx->qtype;
        // rrset_addr is stored as type DNS_TYPE_A for both A and AAAA
        if (etype == DNS_TYPE_AAAA)
            etype = DNS_TYPE_A;
        while (node_rrset) {
            if (node_rrset->gen.type == etype) {
                if (unlikely(etype & 0xFF00))
                    offset = encode_rrs_rfc3597(ctx, offset, &node_rrset->rfc3597);
                else
                    offset = encode_funcptrs[ctx->qtype](ctx, offset, node_rrset);
                break;
            }
            node_rrset = node_rrset->gen.next;
        }
    }

    return offset;
}

// Find the start of the (uncompressed) auth zone name at auth_depth bytes into the name at qname_offset,
//  chasing compression pointers as necc.
// XXX - really, the necessity of this is sort of the last straw on the current scheme involving
//  the interactions of ctx->qname_comp, ctx->auth_comp, lqname, store_dname(), search_ltree(), and CNAME
//  processing.  It's too complex to understand easily and needs refactoring.
F_NONNULL F_PURE
static unsigned chase_auth_ptr(const uint8_t* packet, unsigned offset, unsigned auth_depth)
{
    gdnsd_assert(offset);
    gdnsd_assert(offset < 65536);
    gdnsd_assert(auth_depth < 256);

    unsigned llen = packet[offset];
    while (auth_depth || llen & 0xC0) {
        if (llen & 0xC0) { // compression pointer
            offset = ntohs(gdnsd_get_una16(&packet[offset])) & ~0xC000u;
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

F_NONNULL
static ltree_dname_status_t search_zone_for_dname(const uint8_t* dname, const zone_t* zone, const ltree_node_t** node_out, unsigned* auth_depth_p)
{
    gdnsd_assert(*dname != 0);
    gdnsd_assert(*dname != 2); // these are always illegal dnames
    gdnsd_assert(dname_isinzone(zone->dname, dname));

    ltree_dname_status_t rval = DNAME_AUTH;
    ltree_node_t* rv_node = NULL;
    uint8_t local_dname[256];
    gdnsd_dname_copy(local_dname, dname);
    gdnsd_dname_drop_zone(local_dname, zone->dname);

    // construct label ptr stack
    const uint8_t* lstack[127];
    unsigned lcount = dname_to_lstack(local_dname, lstack);

    ltree_node_t* current = zone->root;
    unsigned deleg_mod = 0;

    do {
    top_loop:
        if (current->flags & LTNFLAG_DELEG) {
            rval = DNAME_DELEG;
            *auth_depth_p -= deleg_mod;
            rv_node = current;
            break;
        }

        if (!lcount || !current->child_table) {
            if (!lcount)
                rv_node = current;
            break;
        }

        lcount--;
        const uint8_t* child_label = lstack[lcount];
        deleg_mod += *child_label;
        deleg_mod++;
        ltree_node_t* entry = current->child_table[ltree_hash(child_label, current->child_hash_mask)];

        while (entry) {
            if (!gdnsd_label_cmp(entry->label, child_label)) {
                current = entry;
                goto top_loop;
            }
            entry = entry->next;
        }
    } while (0);

    //  If in auth space with no match, and we still have a child_table, check for wildcard
    if (!rv_node && current->child_table) {
        gdnsd_assert(rval == DNAME_AUTH);
        static const uint8_t label_wild[2] =  { '\001', '*' };
        ltree_node_t* entry = current->child_table[ltree_hash(label_wild, current->child_hash_mask)];
        while (entry) {
            if (entry->label[0] == '\001' && entry->label[1] == '*') {
                rv_node = entry;
                break;
            }
            entry = entry->next;
        }
    }

    *node_out = rv_node;
    return rval;
}

// DYNC handling.  This translates a DYNC RR from the ltree into
//   a new rrset (possibly NULL) via the plugin, using context
//   storage.
F_NONNULL
static const ltree_rrset_t* process_dync(dnsp_ctx_t* ctx, const ltree_rrset_dync_t* rd)
{
    gdnsd_assert(!rd->gen.next); // DYNC does not co-exist with other rrsets

    const unsigned ttl = do_dyn_callback(ctx, rd->func, rd->resource, rd->gen.ttl, rd->ttl_min);
    dyn_result_t* dr = ctx->dyn;

    if (dr->is_cname) {
        gdnsd_assert(gdnsd_dname_status(dr->storage) == DNAME_VALID);
        dname_copy(ctx->dync_store, dr->storage);
        ctx->dync_synth_rrset.gen.type = DNS_TYPE_CNAME;
        ctx->dync_synth_rrset.gen.count = 1;
        ctx->dync_synth_rrset.gen.ttl = ttl;
        ctx->dync_synth_rrset.cname.dname = ctx->dync_store;
    } else if (dr->count_v4 + dr->count_v6) {
        // ^ If both counts are zero, must represent this as
        //  a missing rrset (NULL rv).  An actual rrset with zero
        //  counts is interpreted as a DYNA entry in the ltree.
        unsigned lv4 = rd->limit_v4;
        if (!lv4 || lv4 > dr->count_v4)
            lv4 = dr->count_v4;

        unsigned lv6 = rd->limit_v6;
        if (!lv6 || lv6 > dr->count_v6)
            lv6 = dr->count_v6;

        ctx->dync_synth_rrset.gen.type = DNS_TYPE_A;
        ctx->dync_synth_rrset.gen.ttl = ttl;
        ctx->dync_synth_rrset.addr.count_v6 = dr->count_v6;
        ctx->dync_synth_rrset.gen.count = dr->count_v4;
        if (!dr->count_v6 && dr->count_v4 <= LTREE_V4A_SIZE) {
            memcpy(ctx->dync_synth_rrset.addr.v4a, dr->v4, sizeof(*dr->v4) * dr->count_v4);
        } else {
            ctx->dync_synth_rrset.addr.addrs.v4 = dr->v4;
            ctx->dync_synth_rrset.addr.addrs.v6 = &dr->storage[result_v6_offset];
        }
        ctx->dync_synth_rrset.addr.limit_v4 = lv4;
        ctx->dync_synth_rrset.addr.limit_v6 = lv6;
    }

    return &ctx->dync_synth_rrset;
}

F_NONNULL
static unsigned answer_from_db(dnsp_ctx_t* ctx, unsigned offset)
{
    gdnsd_assert(offset);
    gdnsd_assert(ctx->stats);

    // Initial qname_comp set to original query
    ctx->qname_comp = sizeof(wire_dns_header_t);

    bool via_cname = false;
    const ltree_node_t* resdom = NULL;
    const ltree_node_t* resauth = NULL;
    const ltree_rrset_t* res_rrsets = NULL;
    wire_dns_header_t* res_hdr = (wire_dns_header_t*)ctx->packet;

    ltree_dname_status_t status = DNAME_NOAUTH;
    unsigned auth_depth = 0;

    const uint8_t* qname = ctx->lqname;

    rcu_read_lock();

    zone_t* query_zone = ztree_find_zone_for(qname, &auth_depth);

    if (query_zone) { // matches auth space somewhere
        resauth = query_zone->root;
        bool iterating_for_cname = false;
        do {
            status = search_zone_for_dname(qname, query_zone, &resdom, &auth_depth);
            gdnsd_assert(status == DNAME_AUTH || status == DNAME_DELEG);

            res_rrsets = resdom ? resdom->rrsets : NULL;
            if (res_rrsets && res_rrsets->gen.type == DNS_TYPE_DYNC)
                res_rrsets = process_dync(ctx, &res_rrsets->dync);

            // In the initial search, it's known that "qname" is in fact the real query name and therefore
            //  uncompressed, which is what makes the simplistic ctx->auth_comp calculation possible.
            if (!iterating_for_cname)
                ctx->auth_comp = ctx->qname_comp + auth_depth;
            else
                ctx->auth_comp = chase_auth_ptr(ctx->packet, ctx->qname_comp, auth_depth);

            iterating_for_cname = false;

            // If we have a CNAME without qtype=CNAME|ANY, we have to do recursive processing...
            if (res_rrsets && res_rrsets->gen.type == DNS_TYPE_CNAME
                    && ctx->qtype != DNS_TYPE_CNAME && ctx->qtype != DNS_TYPE_ANY) {

                gdnsd_assert(!res_rrsets->gen.next); // CNAME does not co-exist with other rrsets
                gdnsd_assert(status == DNAME_AUTH); // no CNAME inside deleg

                res_hdr->flags1 |= 4; // pre-set AA bit, in case we go out of auth space later
                via_cname = true; // avoid REFUSED if we go out of zone in the target

                const ltree_rrset_cname_t* cname = &res_rrsets->cname;
                offset = encode_rr_cname_chain(ctx, offset, cname);
                if (dname_isinzone(query_zone->dname, cname->dname)) {
                    // If the target is in-zone, we recurse through it,
                    // resetting various things that affect the behaviors from
                    // search_zone_for_dname() onwards
                    qname = cname->dname;
                    int len_diff = *qname - *query_zone->dname;
                    gdnsd_assert(len_diff >= 0);
                    auth_depth = (unsigned)len_diff;
                    iterating_for_cname = true;
                } else {
                    status = DNAME_NOAUTH;
                }
            } // CNAME-handling block
        } while (iterating_for_cname);
    } // if query_zone block

    if (status == DNAME_AUTH) {
        gdnsd_assert(resauth);
        res_hdr->flags1 |= 4; // AA bit
        if (likely(resdom))
            offset = construct_normal_response(ctx, offset, res_rrsets);

        // ACME DNS-01 data injection
        bool matched = false;
        if (ctx->qtype == DNS_TYPE_TXT || ctx->qtype == DNS_TYPE_ANY || !ctx->ancount)
            matched = chal_respond(ctx->qname_comp, ctx->qtype, qname, ctx->packet, &ctx->ancount, &offset);

        if (!ctx->ancount) {
            offset = encode_rr_soa(ctx, offset, ltree_node_get_rrset_soa(resauth));
            // Transfer the singleton SOA's count from answer to auth section.
            gdnsd_assert(ctx->ancount == 1 && !ctx->nscount);
            ctx->nscount = 1;
            ctx->ancount = 0;
            if (!resdom && !matched) {
                res_hdr->flags2 = DNS_RCODE_NXDOMAIN;
                stats_own_inc(&ctx->stats->nxdomain);
            }
        }
    } else if (status == DNAME_DELEG) {
        gdnsd_assert(resdom);
        const ltree_rrset_ns_t* ns = ltree_node_get_rrset_ns(resdom);
        gdnsd_assert(ns);
        offset = encode_rrs_ns_deleg(ctx, offset, ns);
    } else {
        gdnsd_assert(status == DNAME_NOAUTH);
        // Don't set REFUSED rcode if we walked out of authoritative space via CNAME
        if (!via_cname) {
            res_hdr->flags2 = DNS_RCODE_REFUSED;
            stats_own_inc(&ctx->stats->refused);
        }
    }

    rcu_read_unlock();

    return offset;
}

F_NONNULL
static unsigned answer_from_db_outer(dnsp_ctx_t* ctx, unsigned offset)
{
    gdnsd_assert(offset);
    gdnsd_assert(ctx->stats);

    const unsigned full_trunc_offset = offset;

    const bool any_udp = (ctx->qtype == DNS_TYPE_ANY && ctx->is_udp);
    if (!any_udp)
        offset = answer_from_db(ctx, offset);

    // Check for truncation (ANY-over-UDP truncation, or true overflow w/ just ans, auth, and glue)
    if (any_udp || unlikely(offset > ctx->this_max_response)) {
        offset = full_trunc_offset;
        ((wire_dns_header_t*)ctx->packet)->flags1 |= 0x2; // TC bit
        // avoid potential confusion over NXDOMAIN+TC (can only happen in CNAME-chaining case)
        ((wire_dns_header_t*)ctx->packet)->flags2 = DNS_RCODE_NOERROR;
        ctx->ancount = 0;
        ctx->nscount = 0;
        ctx->arcount = 0;
        ctx->cname_ancount = 0;
        if (ctx->use_edns)
            stats_own_inc(&ctx->stats->udp.edns_tc);
        else
            stats_own_inc(&ctx->stats->udp.tc);
    }

    return offset;
}

unsigned process_dns_query(void* ctx_asvoid, const gdnsd_anysin_t* asin, uint8_t* packet, const unsigned packet_len, const unsigned edns0_tcp_keepalive)
{
    dnsp_ctx_t* ctx = ctx_asvoid;
    reset_context(ctx);
    gdnsd_assert(ctx->stats);
    ctx->packet = packet;
    ctx->edns0_tcp_keepalive = edns0_tcp_keepalive;

    /*
        log_devdebug("Processing %sv%u DNS query of length %u from %s",
            (ctx->is_udp ? "UDP" : "TCP"),
            (asin->sa.sa_family == AF_INET6) ? 6 : 4,
            packet_len,
            logf_anysin(asin));
    */

    if (asin->sa.sa_family == AF_INET6)
        stats_own_inc(&ctx->stats->v6);

    unsigned question_len = 0;

    const rcode_rv_t status = decode_query(ctx, &question_len, packet_len, asin);

    if (status == DECODE_IGNORE) {
        stats_own_inc(&ctx->stats->dropped);
        return 0;
    }

    unsigned res_offset = sizeof(wire_dns_header_t);

    wire_dns_header_t* hdr = (wire_dns_header_t*)packet;
    hdr->flags1 &= 0x79; // Clears QR, TC, AA bits, preserves RD and Opcode
    hdr->flags1 |= 0x80; // Sets QR
    gdnsd_put_una16(0, &hdr->ancount);
    gdnsd_put_una16(0, &hdr->nscount);
    gdnsd_put_una16(0, &hdr->arcount);

    if (status == DECODE_NOTIMP) {
        gdnsd_put_una16(0, &hdr->qdcount);
        hdr->flags2 = DNS_RCODE_NOTIMP;
        stats_own_inc(&ctx->stats->notimp);
        return res_offset;
    }

    res_offset += question_len;

    if (likely(status == DECODE_OK)) {
        hdr->flags2 = DNS_RCODE_NOERROR;
        if (likely(!ctx->chaos)) {
            memcpy(&ctx->client_info.dns_source, asin, sizeof(*asin));
            res_offset = answer_from_db_outer(ctx, res_offset);
        } else {
            ctx->ancount = 1;
            memcpy(&packet[res_offset], gcfg->chaos, gcfg->chaos_len);
            res_offset += gcfg->chaos_len;
        }

        if (hdr->flags2 == DNS_RCODE_NOERROR)
            stats_own_inc(&ctx->stats->noerror);
    } else {
        if (status == DECODE_FORMERR) {
            hdr->flags2 = DNS_RCODE_FORMERR;
            stats_own_inc(&ctx->stats->formerr);
        } else {
            gdnsd_assert(status == DECODE_BADVERS);
            hdr->flags2 = DNS_RCODE_NOERROR;
            stats_own_inc(&ctx->stats->badvers);
        }
    }

    if (ctx->use_edns) {
        packet[res_offset++] = '\0'; // domainname part of OPT
        wire_dns_rr_opt_t* opt = (wire_dns_rr_opt_t*)&packet[res_offset];
        res_offset += sizeof_optrr;

        gdnsd_put_una16(htons(DNS_TYPE_OPT), &opt->type);
        gdnsd_put_una16(htons(DNS_EDNS0_SIZE), &opt->maxsize);
        gdnsd_put_una32((status == DECODE_BADVERS) ? htonl(0x01000000) : 0, &opt->extflags);
        gdnsd_put_una16(0, &opt->rdlen);

        // code below which tacks on options should increment this for the overall rdlen of the OPT RR
        unsigned rdlen = 0;

        if (ctx->respond_edns_client_subnet) {
            const unsigned src_mask = ctx->client_info.edns_client_mask;
            const unsigned scope_mask = src_mask ? ctx->edns_client_scope_mask : 0;
            const unsigned addr_bytes = (src_mask >> 3) + ((src_mask & 7) ? 1 : 0);
            rdlen += (8 + addr_bytes);
            gdnsd_put_una16(htons(EDNS_CLIENTSUB_OPTCODE), &packet[res_offset]);
            res_offset += 2;
            gdnsd_put_una16(htons(4 + addr_bytes), &packet[res_offset]);
            res_offset += 2;
            gdnsd_put_una16(htons(ctx->edns_client_family), &packet[res_offset]);
            res_offset += 2;
            packet[res_offset++] = src_mask;
            packet[res_offset++] = scope_mask;
            if (src_mask) {
                gdnsd_assert(addr_bytes);
                if (ctx->edns_client_family == 1U) { // IPv4
                    memcpy(&packet[res_offset], &ctx->client_info.edns_client.sin.sin_addr.s_addr, addr_bytes);
                } else {
                    gdnsd_assert(ctx->edns_client_family == 2U); // IPv6
                    memcpy(&packet[res_offset], ctx->client_info.edns_client.sin6.sin6_addr.s6_addr, addr_bytes);
                }
                res_offset += addr_bytes;
            }
        }

        // TCP keepalive is emitted for any TCP request which had an edns0 OPT RR
        if (!ctx->is_udp) {
            rdlen += 6U;
            gdnsd_put_una16(htons(EDNS_TCP_KEEPALIVE_OPTCODE), &packet[res_offset]);
            res_offset += 2;
            gdnsd_put_una16(htons(2), &packet[res_offset]);
            res_offset += 2;
            gdnsd_put_una16(htons(ctx->edns0_tcp_keepalive), &packet[res_offset]);
            res_offset += 2;
        }

        // NSID, if configured by user
        if (gcfg->nsid_len) {
            gdnsd_assert(gcfg->nsid);
            rdlen += (4U + gcfg->nsid_len);
            gdnsd_put_una16(htons(EDNS_NSID_OPTCODE), &packet[res_offset]);
            res_offset += 2;
            gdnsd_put_una16(htons(gcfg->nsid_len), &packet[res_offset]);
            res_offset += 2;
            memcpy(&packet[res_offset], gcfg->nsid, gcfg->nsid_len);
            res_offset += gcfg->nsid_len;
        }

        // Update OPT RR's rdlen for any options emitted above, and bump arcount for it
        gdnsd_put_una16(htons(rdlen), &opt->rdlen);
        ctx->arcount++;

        if (likely(ctx->is_udp)) {
            // We only do one kind of truncation: complete truncation.
            //  therefore if we're returning a >512 packet, it wasn't truncated
            if (res_offset > 512)
                stats_own_inc(&ctx->stats->udp.edns_big);
        }
    }

    gdnsd_put_una16(htons(ctx->ancount + ctx->cname_ancount), &hdr->ancount);
    gdnsd_put_una16(htons(ctx->nscount), &hdr->nscount);
    gdnsd_put_una16(htons(ctx->arcount), &hdr->arcount);

    gdnsd_assert(res_offset <= MAX_RESPONSE);

    return res_offset;
}
