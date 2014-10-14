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

#include "dnspacket.h"

#include <string.h>
#include <stddef.h>
#include <pthread.h>
#include <time.h>

#include "conf.h"
#include "dnswire.h"
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/misc.h>
#include <gdnsd/plugapi-priv.h>
#include <gdnsd/prcu-priv.h>
#include "ztree.h"

typedef struct {
    const uint8_t* original; // Alias to the original uncompressed dname's data (not the len byte)
    const uint8_t* comp_ptr; // where compression occurred on storage (could be off the end if uncompressed)
    unsigned stored_at; // offset this name was first stored to in the packet, possibly partially compressed
} comptarget_t;

typedef struct {
    const ltree_rrset_addr_t* rrset;
    unsigned prev_offset; // offset into c->addtl_store before this rrset was added
    unsigned prev_arcount; // c->arcount before this rrset was added
} addtl_rrset_t;

// per-thread packet context.
typedef struct {
    // whether the thread using this context is a udp or tcp thread
    bool is_udp;

    // Max response size for this individual request, as determined
    //  by protocol type and EDNS (or lack thereof)
    unsigned this_max_response;

    // These describe the question
    unsigned qtype;  // Same numeric values as RFC
    unsigned qname_comp; // compression pointer for the current query name, starts at 0x000C, changes when following CNAME chains
    unsigned auth_comp; // ditto, but points at an uncompressed version of the authority for the query name

    // Stores information about each additional rrset processed
    addtl_rrset_t* addtl_rrsets;

    // Compression offsets, these are one per domainname in the whole
    //  packet.  Fully compressed names are not added, so this is really
    //  the number of unique domainnames in a response packet, so 255
    //  should be plenty.
    comptarget_t* comptargets;

    // used to pseudo-randomly rotate some RRsets (A, AAAA, NS, PTR)
    gdnsd_rstate_t* rand_state;

    // Allocated at dnspacket startup, needs room for gconfig.max_cname_depth * 256
    uint8_t* dync_store;

    // This is sized the same as the main packet buffer (gconfig.max_response), and
    //  used as temporary space for building Additional section records
    uint8_t* addtl_store;

    // this is the packet buffer from the io code
    uint8_t* packet;

    // allocated at startup, memset to zero before each callback
    dyn_result_t* dyn;

// From this point (answer_addr_rrset) on, all of this gets reset to zero
//  at the start of each request...

    const ltree_rrset_addr_t* answer_addr_rrset;
    client_info_t client_info; // dns source IP + optional EDNS client subnet info for plugins
    unsigned comptarget_count; // unique domainnames stored to the packet, including the original question
    unsigned dync_count; // how many results have been stored to dync_store so far
    unsigned addtl_count; // count of addtl's in addtl_rrsets
    unsigned addtl_offset; // current offset writing into addtl_store

    unsigned ancount;
    unsigned nscount;
    unsigned arcount;
    unsigned cname_ancount;

    // synthetic rrsets for DYNC
    ltree_rrset_t dync_synth_rrset;

    // EDNS Client Subnet response mask.
    // Not valid/useful unless use_edns_client_subnet is true below.
    // For static responses, this is set to zero by dnspacket.c
    // For dynamic responses, this is set from .ans_dyn{a,cname}.edns_client_mask,
    //   which is in turn defaulted to zero.
    unsigned edns_client_scope_mask;

    // Whether additional section contains glue (can't be silently truncated)
    bool addtl_has_glue;

    // Whether this request had a valid EDNS0 optrr
    bool use_edns;

    // Client sent EDNS Client Subnet option, and we must respond with one
    bool use_edns_client_subnet;

    // If this is true, the query class was CH
    bool chaos;
} dnsp_ctx_t;

static pthread_mutex_t stats_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t stats_init_cond = PTHREAD_COND_INITIALIZER;
static unsigned stats_initialized = 0;
static unsigned result_v6_offset = 0;

dnspacket_stats_t** dnspacket_stats;

// Allocates the array of pointers to stats structures, one per I/O thread
// Called from main thread before I/O threads are spawned.
void dnspacket_global_setup(void) {
    dnspacket_stats = xcalloc(gconfig.num_dns_threads, sizeof(dnspacket_stats_t*));
    result_v6_offset = gdnsd_result_get_v6_offset();
}

// Called from main thread after starting all of the I/O threads,
//  ensures they all finish allocating their stats and storing the pointers
//  into dnspacket_stats before allowing the main thread to continue.
void dnspacket_wait_stats(void) {
    const unsigned waitfor = gconfig.num_dns_threads;
    pthread_mutex_lock(&stats_init_mutex);
    while(stats_initialized < waitfor)
        pthread_cond_wait(&stats_init_cond, &stats_init_mutex);
    pthread_mutex_unlock(&stats_init_mutex);
}

void* dnspacket_ctx_init(const bool is_udp) {
    dnsp_ctx_t* ctx = xcalloc(1, sizeof(dnsp_ctx_t));

    ctx->rand_state = gdnsd_rand_init();
    ctx->is_udp = is_udp;
    ctx->addtl_rrsets = xmalloc(gconfig.max_addtl_rrsets * sizeof(addtl_rrset_t));
    ctx->comptargets = xmalloc(COMPTARGETS_MAX * sizeof(comptarget_t));
    ctx->dync_store = xmalloc(gconfig.max_cname_depth * 256);
    ctx->addtl_store = xmalloc(gconfig.max_response);
    ctx->dyn = xmalloc(gdnsd_result_get_alloc());

    return ctx;
}

dnspacket_stats_t* dnspacket_stats_init(const unsigned this_threadnum, const bool is_udp) {

    pthread_mutex_lock(&stats_init_mutex);

    dnspacket_stats_t* stats = dnspacket_stats[this_threadnum] = xcalloc(1, sizeof(dnspacket_stats_t));
    stats->is_udp = is_udp;
    gdnsd_plugins_action_iothread_init(this_threadnum);
    stats_initialized++;

    pthread_cond_signal(&stats_init_cond);
    pthread_mutex_unlock(&stats_init_mutex);

    return stats;
}

static void reset_context(dnsp_ctx_t* ctx) {
    dmn_assert(ctx);
    memset(
        &ctx->answer_addr_rrset, 0,
        sizeof(dnsp_ctx_t) - offsetof(dnsp_ctx_t, answer_addr_rrset)
    );
}

// "buf" points to the question section of an input packet.
F_NONNULL
static unsigned parse_question(dnsp_ctx_t* ctx, uint8_t* lqname, const uint8_t* buf, const unsigned len) {
    dmn_assert(ctx); dmn_assert(lqname); dmn_assert(buf);

    uint8_t* lqname_ptr = lqname + 1;
    unsigned pos = 0;
    unsigned llen;
    while((llen = *lqname_ptr++ = buf[pos++])) {
        if(unlikely(llen & 0xC0)) {
            log_devdebug("Label compression detected in question, failing.");
            pos = 0;
            break;
        }

        if(unlikely(pos + llen >= len)) {
            log_devdebug("Query name truncated (runs off end of packet)");
            pos = 0;
            break;
        }

        if(unlikely(pos + llen > 254)) {
            log_devdebug("Query domain name too long");
            pos = 0;
            break;
        }

        while(llen--) {
            if(unlikely((buf[pos] < 0x5B) && (buf[pos] > 0x40)))
                *lqname_ptr++ = buf[pos++] | 0x20;
            else
                *lqname_ptr++ = buf[pos++];
        }
    }

    if(likely(pos)) {
        // Store the overall length of the lowercased name
        *lqname = pos;

        if(likely(pos + 4 <= len)) {
            ctx->qtype = ntohs(gdnsd_get_una16(&buf[pos]));
            pos += 2;

            if(ntohs(gdnsd_get_una16(&buf[pos])) == 3U)
               ctx->chaos = true;
            pos += 2;
        }
        else {
            log_devdebug("Packet length exhausted before parsing question type/class!");
            pos = 0;
        }
    }

    return pos;
}

// retval: true -> FORMERR, false -> OK
F_NONNULL
static bool handle_edns_client_subnet(dnsp_ctx_t* ctx, dnspacket_stats_t* stats, unsigned opt_len, const uint8_t* opt_data) {
    dmn_assert(ctx); dmn_assert(stats); dmn_assert(opt_data);

    bool rv = false;

    do {
        if(opt_len < 4) {
            log_devdebug("edns_client_subnet data too short (%u bytes)", opt_len);
            rv = true;
            break;
        }

        const unsigned family = ntohs(gdnsd_get_una16(opt_data));
        opt_data += 2;
        const unsigned src_mask = *opt_data;
        opt_data += 2;
        const unsigned addr_bytes = (src_mask >> 3) + ((src_mask & 7) ? 1 : 0);
        // Technically, edns-client-subnet specifies that opt_len should be
        //   *exactly* "4 + addr_bytes" here, but we'll accept it if they left
        //   additional trailing bytes on the end, since it doesn't hurt us.
        // We must have the correct amount at a minimum, though.
        if(opt_len < 4 + addr_bytes) {
            log_devdebug("edns_client_subnet: addr length %u too short for src_mask of %u", opt_len, src_mask);
            rv = true;
            break;
        }

        if(family == 1) { // IPv4
            if(src_mask > 32) {
                log_devdebug("edns_client_subnet: invalid src_mask of %u for IPv4", src_mask);
                rv = true;
                break;
            }
            ctx->client_info.edns_client.sa.sa_family = AF_INET;
            memcpy(&ctx->client_info.edns_client.sin.sin_addr.s_addr, opt_data, addr_bytes);
        }
        else if(family == 2) { // IPv6
            if(src_mask > 128) {
                log_devdebug("edns_client_subnet: invalid src_mask of %u for IPv6", src_mask);
                rv = true;
                break;
            }
            ctx->client_info.edns_client.sa.sa_family = AF_INET6;
            memcpy(ctx->client_info.edns_client.sin6.sin6_addr.s6_addr, opt_data, addr_bytes);
        }
        else {
            log_devdebug("edns_client_subnet has unknown family %u", family);
            rv = true;
            break;
        }

        ctx->this_max_response -= (8 + addr_bytes); // leave room for response option
        ctx->use_edns_client_subnet = true;
        ctx->client_info.edns_client_mask = src_mask;
    } while(0);

    stats_own_inc(&stats->edns_clientsub);
    return rv;
}

// retval: true -> FORMERR, false -> OK
F_NONNULL
static bool handle_edns_option(dnsp_ctx_t* ctx, dnspacket_stats_t* stats, unsigned opt_code, unsigned opt_len, const uint8_t* opt_data) {
    dmn_assert(ctx); dmn_assert(stats); dmn_assert(opt_data);

    bool rv = false;
    if((opt_code == EDNS_CLIENTSUB_OPTCODE) && gconfig.edns_client_subnet)
        rv = handle_edns_client_subnet(ctx, stats, opt_len, opt_data);
    else
        log_devdebug("Unknown EDNS option code: %x", opt_code);

    return rv;
}

// retval: true -> FORMERR, false -> OK
F_NONNULL
static bool handle_edns_options(dnsp_ctx_t* ctx, dnspacket_stats_t* stats, unsigned rdlen, const uint8_t* rdata) {
    dmn_assert(ctx); dmn_assert(stats); dmn_assert(rdlen); dmn_assert(rdata);

    bool rv = false;

    // minimum edns option length is 4 bytes (2 byte option code, 2 byte data len)
    while(rdlen) {
        if(rdlen < 4) {
            log_devdebug("EDNS option too short");
            rv = true;
            break;
        }
        unsigned opt_code = ntohs(gdnsd_get_una16(rdata)); rdata += 2;
        unsigned opt_dlen = ntohs(gdnsd_get_una16(rdata)); rdata += 2;
        rdlen -= 4;
        if(opt_dlen > rdlen) {
            log_devdebug("EDNS option too long");
            rv = true;
            break;
        }
        if(handle_edns_option(ctx, stats, opt_code, opt_dlen, rdata)) {
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
static rcode_rv_t parse_optrr(dnsp_ctx_t* ctx, dnspacket_stats_t* stats, const wire_dns_rr_opt_t* opt, const dmn_anysin_t* asin V_UNUSED, const unsigned packet_len, const unsigned offset) {
    dmn_assert(ctx); dmn_assert(stats); dmn_assert(opt); dmn_assert(asin);

    rcode_rv_t rcode = DECODE_OK;
    ctx->use_edns = true;            // send OPT RR with response
    stats_own_inc(&stats->edns);
    if(likely(DNS_OPTRR_GET_VERSION(opt) == 0)) {
        if(likely(ctx->is_udp)) {
            unsigned client_req = DNS_OPTRR_GET_MAXSIZE(opt);
            if(client_req < 512U)
                client_req = 512U;
            ctx->this_max_response = client_req < gconfig.max_edns_response
                ? client_req
                : gconfig.max_edns_response;
        }
        else { // TCP
            ctx->this_max_response = gconfig.max_response;
        }

        // ensure nothing goes wrong with implied limits above
        dmn_assert(ctx->this_max_response <= gconfig.max_response);
        // leave room for basic OPT RR (edns-client-subnet room is addressed elsewhere)
        ctx->this_max_response -= 11;

        unsigned rdlen = htons(gdnsd_get_una16(&opt->rdlen));
        if(rdlen) {
            if(packet_len < offset + sizeof_optrr + rdlen) {
                log_devdebug("Received EDNS OPT RR with options data longer than packet length from %s", dmn_logf_anysin(asin));
                rcode = DECODE_FORMERR;
            }
            else if(handle_edns_options(ctx, stats, rdlen, opt->rdata)) {
                rcode = DECODE_FORMERR;
            }
        }
    }
    else {
        log_devdebug("Received EDNS OPT RR with VERSION > 0 (BADVERSION) from %s", dmn_logf_anysin(asin));
        rcode = DECODE_BADVERS;
    }

    return rcode;
}

F_NONNULL
static rcode_rv_t decode_query(dnsp_ctx_t* ctx, dnspacket_stats_t* stats, uint8_t* lqname, unsigned* question_len_ptr, const unsigned packet_len, const dmn_anysin_t* asin) {
    dmn_assert(ctx); dmn_assert(stats); dmn_assert(ctx->packet); dmn_assert(lqname); dmn_assert(question_len_ptr); dmn_assert(asin);

    rcode_rv_t rcode = DECODE_OK;

    do {
        // 5 is the minimal question length (1 byte root, 2 bytes each type and class)
        if(unlikely(packet_len < (sizeof(wire_dns_header_t) + 5))) {
            log_devdebug("Ignoring short request from %s of length %u", dmn_logf_anysin(asin), packet_len);
            rcode = DECODE_IGNORE;
            break;
        }

        uint8_t* packet = ctx->packet;
        const wire_dns_header_t* hdr = (const wire_dns_header_t*)packet;

/*
    log_devdebug("Query header details: ID:%hu QR:%i OPCODE:%hhu AA:%i TC:%i RD:%i RA:%i AD:%i CD:%i RCODE:%hhu QDCOUNT:%hu ANCOUNT:%hu NSCOUNT:%hu ARCOUNT:%hu",
        DNSH_GET_ID(hdr), DNSH_GET_QR(hdr) ? 1 : 0,
        (DNSH_GET_OPCODE(hdr) >> 3), DNSH_GET_AA(hdr) ? 1 : 0,
        DNSH_GET_TC(hdr) ? 1 : 0, DNSH_GET_RD(hdr) ? 1 : 0,
        DNSH_GET_RA(hdr) ? 1 : 0, DNSH_GET_AD(hdr) ? 1 : 0,
        DNSH_GET_CD(hdr) ? 1 : 0, DNSH_GET_RCODE(hdr),
        DNSH_GET_QDCOUNT(hdr), DNSH_GET_ANCOUNT(hdr),
        DNSH_GET_NSCOUNT(hdr), DNSH_GET_ARCOUNT(hdr)
    );
*/

        if(unlikely(DNSH_GET_QDCOUNT(hdr) != 1)) {
            log_devdebug("Received request from %s with %hu questions, ignoring", dmn_logf_anysin(asin), DNSH_GET_QDCOUNT(hdr));
            rcode = DECODE_IGNORE;
            break;
        }

        if(unlikely(DNSH_GET_QR(hdr))) {
            log_devdebug("QR bit set in query from %s, ignoring", dmn_logf_anysin(asin));
            rcode = DECODE_IGNORE;
            break;
        }

        if(unlikely(DNSH_GET_TC(hdr))) {
            log_devdebug("TC bit set in query from %s, ignoring", dmn_logf_anysin(asin));
            rcode = DECODE_IGNORE;
            break;
        }

        unsigned offset = sizeof(wire_dns_header_t);
        if(unlikely(!(*question_len_ptr = parse_question(ctx, lqname, &packet[offset], packet_len - offset)))) {
            log_devdebug("Failed to parse question, ignoring %s", dmn_logf_anysin(asin));
            rcode = DECODE_IGNORE;
            break;
        }

        if(DNSH_GET_OPCODE(hdr)) {
            log_devdebug("Non-QUERY request (NOTIMP) from %s, opcode is %u", dmn_logf_anysin(asin), (DNSH_GET_OPCODE(hdr) >> 3U));
            rcode = DECODE_NOTIMP;
            break;
        }

        if(unlikely(ctx->qtype == DNS_TYPE_AXFR)) {
            log_devdebug("AXFR attempted (NOTIMP) from %s", dmn_logf_anysin(asin));
            rcode = DECODE_NOTIMP;
            break;
        }

        if(unlikely(ctx->qtype == DNS_TYPE_IXFR)) {
            log_devdebug("IXFR attempted (NOTIMP) from %s", dmn_logf_anysin(asin));
            rcode = DECODE_NOTIMP;
            break;
        }

        offset += *question_len_ptr;

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
        if(DNSH_GET_ARCOUNT(hdr)
            && likely(packet_len >= (offset + sizeof_optrr + 1))
            && likely(packet[offset] == '\0')
            && likely(DNS_OPTRR_GET_TYPE(opt) == DNS_TYPE_OPT)) {
            rcode = parse_optrr(ctx, stats, opt, asin, packet_len, offset + 1);
        }
        else if(likely(ctx->is_udp)) { // No valid EDNS OPT RR in request, UDP
            ctx->this_max_response = 512;
        }
        else { // No valid EDNS OPT RR in request, TCP
            ctx->this_max_response = gconfig.max_response;
        }
    } while (0);

    return rcode;
}

// is_addtl refers to where we're storing to
F_NONNULL
static unsigned store_dname_nocomp(dnsp_ctx_t* ctx, const unsigned pkt_dname_offset, const uint8_t* dn) {
    dmn_assert(ctx); dmn_assert(pkt_dname_offset); dmn_assert(dn);

    if(*dn != 1 && likely(pkt_dname_offset < 16384) && likely(ctx->comptarget_count < COMPTARGETS_MAX)) {
        comptarget_t* new_ctarg = &(ctx->comptargets[ctx->comptarget_count++]);
        new_ctarg->original = dn;
        new_ctarg->stored_at = pkt_dname_offset;
        new_ctarg->comp_ptr = dn + 255;
    }

    const unsigned final_size = *dn;
    memcpy(&ctx->packet[pkt_dname_offset], dn + 1, final_size);

    return final_size;
}

// is_addtl refers to where we're storing to
F_NONNULL
static unsigned store_dname(dnsp_ctx_t* ctx, const unsigned pkt_dname_offset, const uint8_t* dn, const bool is_addtl) {
    dmn_assert(ctx); dmn_assert(dn);

    uint8_t* packet = is_addtl ? ctx->addtl_store : ctx->packet;

    // Deal with the root case, which should never be compressed, or compressed against
    if(*dn == 1) {
       dmn_assert(dn[1] == '\0');
       packet[pkt_dname_offset] = '\0';
       return 1;
    }

    dmn_assert(*dn > 2);
    const uint8_t* dn_last = dn + *dn;
    const unsigned dn_len = *dn++;

    unsigned best_offset = 0;
    const uint8_t* best_matched_at = dn + 255;

    const comptarget_t* ctarg = ctx->comptargets;

    for(unsigned x = ctx->comptarget_count; x--; ) {
        const uint8_t* dn_current = dn;
        const uint8_t* cand = ctarg->original;
        const uint8_t* cand_comp = ctarg->comp_ptr;

        dmn_assert(cand); dmn_assert(*cand > 2);

        const unsigned cand_len = *cand;
        const uint8_t* cand_last = cand++ + cand_len;
        const uint8_t* cand_current = cand;

        unsigned dn_remain = dn_last - dn;
        unsigned cand_remain = cand_last - cand;

        do {
            const int lcmp = dn_remain - cand_remain;
            if(lcmp == 0 && !memcmp(dn_current, cand_current, dn_remain)) {
                best_offset = ctarg->stored_at + (cand_current - cand);
                best_matched_at = dn_current;
                break;
            }
            if(lcmp >= 0) {
                dn_current += *dn_current;
                dn_current++;
                if(dn_current >= best_matched_at) break;
                if(!(dn_remain = dn_last - dn_current)) break;
            }
            if(lcmp <= 0) {
                cand_current += *cand_current;
                cand_current++;
                if(cand_current >= cand_comp) break;
                if(!(cand_remain = cand_last - cand_current)) break;
            }
        } while(1);
        if(best_matched_at == dn) break;
        ctarg++;
    } // foreach candidate

    // If we didn't fully compress (either partially, or not at all)
    //  store this as a compression target for future use.
    if(best_matched_at != dn) {
        if(!is_addtl && likely(pkt_dname_offset < 16384) && likely(ctx->comptarget_count < COMPTARGETS_MAX)) {
            comptarget_t* new_ctarg = &(ctx->comptargets[ctx->comptarget_count++]);
            new_ctarg->original = dn - 1;
            new_ctarg->stored_at = pkt_dname_offset;
            new_ctarg->comp_ptr = best_matched_at;
        }
    }

    if(best_offset) {
        const unsigned final_size = best_matched_at - dn + 2;
        const unsigned tocopy = final_size - 2;
        memcpy(&packet[pkt_dname_offset], dn, tocopy);
        gdnsd_put_una16(htons(0xC000 | best_offset), &packet[pkt_dname_offset + tocopy]);
        return final_size;
    }
    else {
        memcpy(&packet[pkt_dname_offset], dn, dn_len);
        return dn_len;
    }
}

F_NONNULL
static void dname_from_raw(uint8_t* restrict dname, const uint8_t* restrict raw) {
    unsigned offset = 0;
    unsigned llen;
    while((llen = raw[offset])) {
        llen++; // include len byte itself
        dmn_assert(offset + llen <= 254);
        memcpy(&dname[offset + 1], &raw[offset], llen);
        offset += llen;
    }
    dname[++offset] = 0;
    dname[0] = offset;
}

// We know a given name was stored at packet+orig_offset already.  We
//  want to repeat it at (packet|addtl_store)+store_at_offset, using
//  compression if possible and warranted, but not pointer-to-pointer.
// The rules:
//  is_addtl indicates whether we're storing to additional section or not.
//  regardless, orig_offset is from main storage (answer/auth sections)
//  if !is_addtl, orig_offset must be one of ctx->qname_comp or ctx->auth_comp,
//    both of which are gauranteed <16K offset.
F_NONNULL
static unsigned repeat_name(dnsp_ctx_t* ctx, unsigned store_at_offset, unsigned orig_offset, const bool is_addtl) {
    dmn_assert(ctx); dmn_assert(ctx->packet);
    if(!is_addtl) {
        dmn_assert(orig_offset < 16384);
        dmn_assert(orig_offset == ctx->qname_comp || orig_offset == ctx->auth_comp);
    }

    const uint8_t* inpkt = ctx->packet;
    uint8_t* outpkt = is_addtl ? ctx->addtl_store : ctx->packet;

    unsigned rv = 0;

    if(inpkt[orig_offset]) {
        // if orig is a compression pointer, copy it
        if(inpkt[orig_offset] & 0xC0) {
            gdnsd_put_una16(gdnsd_get_una16(&inpkt[orig_offset]), &outpkt[store_at_offset]);
            rv = 2;
        }
        else {
            if(likely(orig_offset < 16384)) {
                // compress by pointing at it if in range
                gdnsd_put_una16(htons(0xC000 | orig_offset), &outpkt[store_at_offset]);
                rv = 2;
            }
            else {
                // else fall back to a full dname_store with comptarget searching
                //  This case will only happen for LHS of additional-section addresses
                //  where the original was >16K, was not the root name, and was
                //  not fully-compressed.
                dmn_assert(is_addtl);
                uint8_t dntmp[256];
                dname_from_raw(dntmp, &inpkt[orig_offset]);
                rv = store_dname(ctx, store_at_offset, dntmp, true);
            }
        }
    }
    else {
        // If orig is the root of DNS, no point compressing
        outpkt[store_at_offset] = 0;
        rv = 1;
    }

    dmn_assert(rv);
    return rv;
}

// These macros define a common pattern around the body of a loop encoding
//  an rrset.  They behave like a for-loop specified as...
//    for(unsigned i = 0; i < _limit; i++) { ... }
//  ... with the exception that they start at a pseudo-random "i" value
//  from the sequence 0->(_total-1), and "i" will wrap-around to zero
//  as appropriate to stay within the _total while iterating _limit times.

#define OFFSET_LOOP_START(_total, _limit) \
    {\
        const unsigned _tot = (_total);\
        unsigned _x_count = (_limit);\
        unsigned i = gdnsd_rand_get32(ctx->rand_state) % _tot;\
        while(_x_count--) {\

            // Your code using "i" as an rrset index goes here
#define OFFSET_LOOP_END \
            if(++i == _tot)\
              i = 0;\
        }\
    }

F_NONNULL
static unsigned enc_a_static(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_addr_t* rrset, const unsigned nameptr, const bool is_addtl) {
    dmn_assert(ctx); dmn_assert(rrset);
    dmn_assert(rrset->gen.count);

    uint8_t* packet = is_addtl ? ctx->addtl_store : ctx->packet;

    if(is_addtl)
        ctx->arcount += rrset->limit_v4;
    else
        ctx->ancount += rrset->limit_v4;

    const uint32_t* addr_ptr = (!rrset->count_v6 && rrset->gen.count <= LTREE_V4A_SIZE)
        ? &rrset->v4a[0]
        : rrset->addrs.v4;
    OFFSET_LOOP_START(rrset->gen.count, rrset->limit_v4)
        offset += repeat_name(ctx, offset, nameptr, is_addtl);
        gdnsd_put_una32(DNS_RRFIXED_A, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 4;
        gdnsd_put_una16(htons(4), &packet[offset]);
        offset += 2;
        gdnsd_put_una32(addr_ptr[i], &packet[offset]);
        offset += 4;
    OFFSET_LOOP_END
    return offset;
}

F_NONNULL
static unsigned enc_aaaa_static(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_addr_t* rrset, const unsigned nameptr, const bool is_addtl) {
    dmn_assert(ctx); dmn_assert(rrset);
    dmn_assert(rrset->count_v6);

    uint8_t* packet = is_addtl ? ctx->addtl_store : ctx->packet;

    if(is_addtl)
        ctx->arcount += rrset->limit_v6;
    else
        ctx->ancount += rrset->limit_v6;

    OFFSET_LOOP_START(rrset->count_v6, rrset->limit_v6)
        offset += repeat_name(ctx, offset, nameptr, is_addtl);
        gdnsd_put_una32(DNS_RRFIXED_AAAA, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 4;
        gdnsd_put_una16(htons(16), &packet[offset]);
        offset += 2;
        memcpy(&packet[offset], rrset->addrs.v6 + (i << 4), 16);
        offset += 16;
    OFFSET_LOOP_END
    return offset;
}

F_NONNULL
static unsigned enc_a_dynamic(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_addr_t* rrset, const unsigned nameptr, const bool is_addtl, const unsigned ttl) {
    dmn_assert(ctx); dmn_assert(ctx->packet);

    uint8_t* packet = is_addtl ? ctx->addtl_store : ctx->packet;
    const dyn_result_t* dr = ctx->dyn;
    dmn_assert(!dr->is_cname);
    dmn_assert(dr->count_v4);

    const unsigned limit_v4 = rrset->limit_v4 && rrset->limit_v4 < dr->count_v4
        ? rrset->limit_v4
        : dr->count_v4;

    if(is_addtl)
        ctx->arcount += limit_v4;
    else
        ctx->ancount += limit_v4;

    OFFSET_LOOP_START(dr->count_v4, limit_v4)
        offset += repeat_name(ctx, offset, nameptr, is_addtl);
        gdnsd_put_una32(DNS_RRFIXED_A, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(ttl, &packet[offset]);
        offset += 4;
        gdnsd_put_una16(htons(4), &packet[offset]);
        offset += 2;
        gdnsd_put_una32(dr->v4[i], &packet[offset]);
        offset += 4;
    OFFSET_LOOP_END
    return offset;
}

F_NONNULL
static unsigned enc_aaaa_dynamic(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_addr_t* rrset, const unsigned nameptr, const bool is_addtl, const unsigned ttl) {
    dmn_assert(ctx); dmn_assert(ctx->packet);

    uint8_t* packet = is_addtl ? ctx->addtl_store : ctx->packet;
    const dyn_result_t* dr = ctx->dyn;
    dmn_assert(!dr->is_cname);
    dmn_assert(dr->count_v6);

    const unsigned limit_v6 = rrset->limit_v6 && rrset->limit_v6 < dr->count_v6
        ? rrset->limit_v6
        : dr->count_v6;

    if(is_addtl)
        ctx->arcount += limit_v6;
    else
        ctx->ancount += limit_v6;

    const uint8_t* v6 = &dr->storage[result_v6_offset];
    OFFSET_LOOP_START(dr->count_v6, limit_v6)
        offset += repeat_name(ctx, offset, nameptr, is_addtl);
        gdnsd_put_una32(DNS_RRFIXED_AAAA, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(ttl, &packet[offset]);
        offset += 4;
        gdnsd_put_una16(htons(16), &packet[offset]);
        offset += 2;
        memcpy(&packet[offset], &v6[i << 4], 16);
        offset += 16;
    OFFSET_LOOP_END
    return offset;
}

// Invoke dyna callback for DYN[AC], taking care of zeroing
//   out ctx->dyn and cleaning up the ttl + scope_mask issues,
//   returning the TTL to actually use, in network order.
F_NONNULLX(1,2)
static unsigned do_dyn_callback(dnsp_ctx_t* ctx, gdnsd_resolve_cb_t func, const uint8_t* origin, const unsigned res, const unsigned ttl_max_net, const unsigned ttl_min) {
    dmn_assert(ctx); dmn_assert(func);

    dyn_result_t* dr = ctx->dyn;
    memset(dr, 0, sizeof(dyn_result_t));
    const gdnsd_sttl_t sttl = func(res, origin, &ctx->client_info, dr);
    if(dr->edns_scope_mask > ctx->edns_client_scope_mask)
        ctx->edns_client_scope_mask = dr->edns_scope_mask;
    assert_valid_sttl(sttl);
    unsigned ttl = sttl & GDNSD_STTL_TTL_MASK;
    if(ttl > ntohl(ttl_max_net))
        ttl = ttl_max_net;
    else if(ttl < ttl_min)
        ttl = htonl(ttl_min);
    else
        ttl = htonl(ttl);
    return ttl;
}

F_NONNULL
static unsigned encode_rrs_anyaddr(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_addr_t* rrset, const unsigned nameptr, const bool is_addtl) {
    dmn_assert(ctx); dmn_assert(rrset);

    // This is to prevent duplicating the answer AAAA+A
    // rrset in the addtl section
    if(!is_addtl)
        ctx->answer_addr_rrset = rrset;

    if(rrset->gen.count | rrset->count_v6) {
        if(rrset->gen.count)
            offset = enc_a_static(ctx, offset, rrset, nameptr, is_addtl);
        if(rrset->count_v6)
            offset = enc_aaaa_static(ctx, offset, rrset, nameptr, is_addtl);
    }
    else {
        const unsigned ttl = do_dyn_callback(ctx, rrset->dyn.func, NULL, rrset->dyn.resource, rrset->gen.ttl, rrset->dyn.ttl_min);
        dmn_assert(!ctx->dyn->is_cname);
        if(ctx->dyn->count_v4)
            offset = enc_a_dynamic(ctx, offset, rrset, nameptr, is_addtl, ttl);
        if(ctx->dyn->count_v6)
            offset = enc_aaaa_dynamic(ctx, offset, rrset, nameptr, is_addtl, ttl);
    }

    return offset;
}

// retval indicates whether to actually add it or not
F_NONNULL
static bool add_addtl_rrset_check(dnsp_ctx_t* ctx, const ltree_rrset_addr_t* rrset) {
    dmn_assert(ctx); dmn_assert(rrset);

    bool rv = true;

    // gconfig.max_addtl_rrsets unique addtl rrsets
    if(unlikely(ctx->addtl_count == gconfig.max_addtl_rrsets)) {
        rv = false;
    }
    else {
        for(unsigned i = 0; i < ctx->addtl_count; i++) {
            if(unlikely(ctx->addtl_rrsets[i].rrset == rrset)) {
                rv = false;
                break;
            }
        }
    }

    return rv;
}

F_NONNULL
static void track_addtl_rrset_unwind(dnsp_ctx_t* ctx, const ltree_rrset_addr_t* rrset) {
    dmn_assert(ctx); dmn_assert(rrset);

    // arcount and addtl_offset should be zero when first additional is added...
    dmn_assert(ctx->addtl_count || !ctx->addtl_offset);
    dmn_assert(ctx->addtl_count || !ctx->arcount);

    // store info for unwinding if we run out of space for additionals
    addtl_rrset_t* arrset = &ctx->addtl_rrsets[ctx->addtl_count++];
    arrset->rrset = rrset;
    arrset->prev_offset = ctx->addtl_offset;
    arrset->prev_arcount = ctx->arcount;
}

F_NONNULL
static void add_addtl_rrset(dnsp_ctx_t* ctx, const ltree_rrset_addr_t* rrset, const unsigned nameptr) {
    dmn_assert(ctx); dmn_assert(rrset);

    if(rrset != ctx->answer_addr_rrset && add_addtl_rrset_check(ctx, rrset)) {
        track_addtl_rrset_unwind(ctx, rrset);
        ctx->addtl_offset = encode_rrs_anyaddr(ctx, ctx->addtl_offset, rrset, nameptr, true);
    }
}

// Note we track_addtl_rrset_unwind() in encode_rrs_a/aaaa, but
//  do not do the add_addtl_rrset_check() first.  These functions
//  are asserted to only be called for direct A/AAAA queries, so
//  it's impossible for the check to fail.
F_NONNULL
static unsigned encode_rrs_a(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_addr_t* rrset, const bool answer V_UNUSED) {
    dmn_assert(ctx); dmn_assert(offset); dmn_assert(rrset);
    dmn_assert(ctx->qtype == DNS_TYPE_A);

    // This is to prevent duplicating the answer AAAA+A
    // rrset in the addtl section
    ctx->answer_addr_rrset = rrset;

    if(rrset->gen.count | rrset->count_v6) {
        if(rrset->gen.count)
            offset = enc_a_static(ctx, offset, rrset, ctx->qname_comp, false);
        if(rrset->count_v6) {
            track_addtl_rrset_unwind(ctx, rrset);
            ctx->addtl_offset = enc_aaaa_static(ctx, ctx->addtl_offset, rrset, ctx->qname_comp, true);
        }
    }
    else {
        const unsigned ttl = do_dyn_callback(ctx, rrset->dyn.func, NULL, rrset->dyn.resource, rrset->gen.ttl, rrset->dyn.ttl_min);
        dmn_assert(!ctx->dyn->is_cname);
        if(ctx->dyn->count_v4)
            offset = enc_a_dynamic(ctx, offset, rrset, ctx->qname_comp, false, ttl);
        if(ctx->dyn->count_v6) {
            track_addtl_rrset_unwind(ctx, rrset);
            ctx->addtl_offset = enc_aaaa_dynamic(ctx, ctx->addtl_offset, rrset, ctx->qname_comp, true, ttl);
        }
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_aaaa(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_addr_t* rrset, const bool answer V_UNUSED) {
    dmn_assert(ctx); dmn_assert(offset); dmn_assert(rrset);
    dmn_assert(ctx->qtype == DNS_TYPE_AAAA);

    // This is to prevent duplicating the answer AAAA+A
    // rrset in the addtl section
    ctx->answer_addr_rrset = rrset;

    if(rrset->gen.count | rrset->count_v6) {
        if(rrset->count_v6)
            offset = enc_aaaa_static(ctx, offset, rrset, ctx->qname_comp, false);
        if(rrset->gen.count) {
            track_addtl_rrset_unwind(ctx, rrset);
            ctx->addtl_offset = enc_a_static(ctx, ctx->addtl_offset, rrset, ctx->qname_comp, true);
        }
    }
    else {
        const unsigned ttl = do_dyn_callback(ctx, rrset->dyn.func, NULL, rrset->dyn.resource, rrset->gen.ttl, rrset->dyn.ttl_min);
        dmn_assert(!ctx->dyn->is_cname);
        if(ctx->dyn->count_v6)
            offset = enc_aaaa_dynamic(ctx, offset, rrset, ctx->qname_comp, false, ttl);
        if(ctx->dyn->count_v4) {
            track_addtl_rrset_unwind(ctx, rrset);
            ctx->addtl_offset = enc_a_dynamic(ctx, ctx->addtl_offset, rrset, ctx->qname_comp, true, ttl);
        }
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_ns(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_ns_t* rrset, const bool answer) {
    dmn_assert(ctx); dmn_assert(ctx->packet); dmn_assert(offset); dmn_assert(rrset);
    dmn_assert(rrset->gen.count); // we never call encode_rrs_ns without an NS record present

    uint8_t* packet = ctx->packet;

    OFFSET_LOOP_START(rrset->gen.count, rrset->gen.count)
        offset += repeat_name(ctx, offset, ctx->auth_comp, false);
        gdnsd_put_una32(DNS_RRFIXED_NS, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;
        const unsigned newlen = store_dname(ctx, offset, rrset->rdata[i].dname, false);
        gdnsd_put_una16(htons(newlen), &packet[offset - 2]);
        if(rrset->rdata[i].ad) {
            if(AD_IS_GLUE(rrset->rdata[i].ad)) {
                ctx->addtl_has_glue = true;
                add_addtl_rrset(ctx, AD_GET_PTR(rrset->rdata[i].ad), offset);
            }
            else {
                add_addtl_rrset(ctx, rrset->rdata[i].ad, offset);
            }
        }
        offset += newlen;
    OFFSET_LOOP_END

    if(answer)
        ctx->ancount += rrset->gen.count;
    else
        ctx->nscount += rrset->gen.count;

    return offset;
}

F_NONNULL
static unsigned encode_rrs_ptr(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_ptr_t* rrset, const bool answer V_UNUSED) {
    dmn_assert(ctx); dmn_assert(ctx->packet); dmn_assert(offset); dmn_assert(rrset);

    uint8_t* packet = ctx->packet;

    const unsigned rrct = rrset->gen.count;
    ctx->ancount += rrct;
    for(unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(ctx, offset, ctx->qname_comp, false);
        gdnsd_put_una32(DNS_RRFIXED_PTR, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;
        const unsigned newlen = store_dname(ctx, offset, rrset->rdata[i].dname, false);
        gdnsd_put_una16(htons(newlen), &packet[offset - 2]);
        offset += newlen;
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_mx(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_mx_t* rrset, const bool answer V_UNUSED) {
    dmn_assert(ctx); dmn_assert(ctx->packet); dmn_assert(offset); dmn_assert(rrset);

    uint8_t* packet = ctx->packet;

    const unsigned rrct = rrset->gen.count;
    ctx->ancount += rrct;
    for(unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(ctx, offset, ctx->qname_comp, false);
        gdnsd_put_una32(DNS_RRFIXED_MX, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;
        const ltree_rdata_mx_t* rd = &rrset->rdata[i];
        gdnsd_put_una16(rd->pref, &packet[offset]);
        offset += 2;
        const unsigned newlen = store_dname(ctx, offset, rd->dname, false);
        gdnsd_put_una16(htons(newlen + 2), &packet[offset - 4]);
        if(rd->ad)
            add_addtl_rrset(ctx, rd->ad, offset);
        offset += newlen;
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_srv(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_srv_t* rrset, const bool answer V_UNUSED) {
    dmn_assert(ctx); dmn_assert(ctx->packet); dmn_assert(rrset);

    uint8_t* packet = ctx->packet;

    const unsigned rrct = rrset->gen.count;
    ctx->ancount += rrct;
    for(unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(ctx, offset, ctx->qname_comp, false);
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
        const unsigned newlen = store_dname_nocomp(ctx, offset, rd->dname);
        gdnsd_put_una16(htons(newlen + 6), &packet[offset - 8]);
        if(rd->ad)
            add_addtl_rrset(ctx, rd->ad, offset);
        offset += newlen;
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_naptr(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_naptr_t* rrset, const bool answer V_UNUSED) {
    dmn_assert(ctx); dmn_assert(ctx->packet); dmn_assert(offset); dmn_assert(rrset);

    uint8_t* packet = ctx->packet;

    const unsigned rrct = rrset->gen.count;
    ctx->ancount += rrct;
    for(unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(ctx, offset, ctx->qname_comp, false);
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

        // flags, services, regexp
        for(unsigned j = 0; j < 3; j++) {
            const uint8_t* this_txt = rd->texts[j];
            const unsigned oal = *this_txt + 1; // oal is the encoded len value + 1 for the len byte itself
            memcpy(&packet[offset], this_txt, oal);
            offset += oal;
        }

        // NAPTR target can't be compressed
        const unsigned newlen = store_dname_nocomp(ctx, offset, rd->dname);
        gdnsd_put_una16(htons(offset - rdata_offset + newlen), &packet[rdata_offset - 2]);
        if(rd->ad)
            add_addtl_rrset(ctx, rd->ad, offset);
        offset += newlen;
    }

    return offset;
}

F_NONNULL
static unsigned encode_rrs_txt(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_txt_t* rrset, const bool answer V_UNUSED) {
    dmn_assert(ctx); dmn_assert(ctx->packet); dmn_assert(offset); dmn_assert(rrset);

    uint8_t* packet = ctx->packet;

    const unsigned rrct = rrset->gen.count;
    ctx->ancount += rrct;
    for(unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(ctx, offset, ctx->qname_comp, false);
        gdnsd_put_una32(DNS_RRFIXED_TXT, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;

        const unsigned rdata_offset = offset;
        unsigned rdata_len = 0;
        const uint8_t* restrict bs;
        unsigned j = 0;
        const ltree_rdata_txt_t rd = rrset->rdata[i];
        while((bs = rd[j++])) {
            const unsigned oal = *bs + 1; // oal is the encoded len value + 1 for the len byte itself
            memcpy(&packet[offset], bs, oal);
            offset += oal;
            rdata_len += oal;
        }
        gdnsd_put_una16(htons(rdata_len), &packet[rdata_offset - 2]);
    }

    return offset;
}

// "answer" here is overloaded from its original meaning for the other RRs.
//   normally it means 'this record's going into the answer section as opposed to auth/additional'
//   here it means true: 'direct CNAME query', false: 'chaining through for a non-CNAME query'
//    (and in either case, it's going into the answer section)
F_NONNULL
static unsigned encode_rr_cname(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_cname_t* rd, const bool answer) {
    dmn_assert(ctx); dmn_assert(ctx->packet); dmn_assert(offset); dmn_assert(rd);

    uint8_t* packet = ctx->packet;

    // start formulating response
    offset += repeat_name(ctx, offset, ctx->qname_comp, false);
    gdnsd_put_una32(DNS_RRFIXED_CNAME, &packet[offset]);
    offset += 4;

    gdnsd_put_una32(rd->gen.ttl, &packet[offset]);
    offset += 6;

    const unsigned rdata_offset = offset;
    offset += store_dname(ctx, offset, rd->dname, false);

    // set rdata_len
    gdnsd_put_una16(htons(offset - rdata_offset), &packet[rdata_offset - 2]);

    if(answer) {
        ctx->ancount++;
    }
    else {
        ctx->qname_comp = rdata_offset;
        ctx->cname_ancount++;
    }

    return offset;
}

F_NONNULL
static unsigned encode_rr_soa_common(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_soa_t* rdata, const bool answer, const bool negative) {
    dmn_assert(ctx); dmn_assert(ctx->packet); dmn_assert(offset); dmn_assert(rdata);

    uint8_t* packet = ctx->packet;

    offset += repeat_name(ctx, offset, ctx->auth_comp, false);
    gdnsd_put_una32(DNS_RRFIXED_SOA, &packet[offset]);
    offset += 4;
    gdnsd_put_una32(negative ? rdata->neg_ttl : rdata->gen.ttl, &packet[offset]);
    offset += 6;

    // fill in the rdata
    const unsigned rdata_offset = offset;
    offset += store_dname(ctx, offset, rdata->master, false);
    offset += store_dname(ctx, offset, rdata->email, false);
    memcpy(&packet[offset], &rdata->times, 20);
    offset += 20; // 5x 32-bits

    // set rdata_len
    gdnsd_put_una16(htons(offset - rdata_offset), &packet[rdata_offset - 2]);

    if(answer)
        ctx->ancount++;
    else
        ctx->nscount++;

    return offset;
}

F_NONNULL
static unsigned encode_rr_soa(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_soa_t* rdata, const bool answer) {
    return encode_rr_soa_common(ctx, offset, rdata, answer, false);
}

F_NONNULL
static unsigned encode_rr_soa_negative(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_soa_t* rdata) {
    return encode_rr_soa_common(ctx, offset, rdata, false, true);
}

static unsigned encode_rrs_rfc3597(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_rfc3597_t* rrset, const bool answer V_UNUSED) {
    dmn_assert(ctx); dmn_assert(ctx->packet); dmn_assert(offset); dmn_assert(rrset);

    // assert that DYNC (which is technically in the range
    //  served exclusively by this function, but which we
    //  should be translating earlier and never serving on
    //  the wire) never appears here.
    dmn_assert(rrset->gen.type != DNS_TYPE_DYNC);

    uint8_t* packet = ctx->packet;

    const unsigned rrct = rrset->gen.count;
    ctx->ancount += rrct;
    for(unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(ctx, offset, ctx->qname_comp, false);
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

static unsigned encode_rrs_any(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_t* res_rrsets) {
    dmn_assert(ctx);

    // Address rrsets have to be processed first outside of the main loop,
    //   so that ctx->answer_addr_rrset gets set before any other RR-types
    //   try to add duplicate addr records to the addtl section
    const ltree_rrset_t* rrset = res_rrsets;
    while(rrset) {
        if(rrset->gen.type == DNS_TYPE_A)
            offset = encode_rrs_anyaddr(ctx, offset, &rrset->addr, ctx->qname_comp, false);
        rrset = rrset->gen.next;
    }

    rrset = res_rrsets;
    while(rrset) {
        switch(rrset->gen.type) {
            case DNS_TYPE_A:
                // handled above
                break;
            case DNS_TYPE_SOA:
                offset = encode_rr_soa(ctx, offset, &rrset->soa, true);
                break;
            case DNS_TYPE_CNAME:
                offset = encode_rr_cname(ctx, offset, &rrset->cname, true);
                break;
            case DNS_TYPE_NS:
                offset = encode_rrs_ns(ctx, offset, &rrset->ns, true);
                break;
            case DNS_TYPE_PTR:
                offset = encode_rrs_ptr(ctx, offset, &rrset->ptr, true);
                break;
            case DNS_TYPE_MX:
                offset = encode_rrs_mx(ctx, offset, &rrset->mx, true);
                break;
            case DNS_TYPE_SRV:
                offset = encode_rrs_srv(ctx, offset, &rrset->srv, true);
                break;
            case DNS_TYPE_NAPTR:
                offset = encode_rrs_naptr(ctx, offset, &rrset->naptr, true);
                break;
            case DNS_TYPE_TXT:
                offset = encode_rrs_txt(ctx, offset, &rrset->txt, true);
                break;
            case DNS_TYPE_DYNC:;
                dmn_assert(0); // DYNC should never make it to here
            default:
                offset = encode_rrs_rfc3597(ctx, offset, &rrset->rfc3597, true);
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
    dmn_assert(node);\
    const ltree_rrset_t* rrsets = node->rrsets;\
    dmn_assert(rrsets);\
    while(rrsets->gen.type != _dtyp) {\
        rrsets = rrsets->gen.next;\
        dmn_assert(rrsets);\
    }\
    return &rrsets-> _typ;\
}
MK_RRSET_GET(soa, soa, DNS_TYPE_SOA)
MK_RRSET_GET(ns, ns, DNS_TYPE_NS)

// typecast for the encode funcs in the funcptr table
#define EC (unsigned(*)(dnsp_ctx_t*, unsigned, const void*, const bool))

static unsigned (*encode_funcptrs[256])(dnsp_ctx_t*, unsigned, const void*, const bool) = {
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

F_NONNULLX(1,4)
static unsigned construct_normal_response(dnsp_ctx_t* ctx, unsigned offset, const ltree_rrset_t* res_rrsets, const ltree_node_t* authdom, const bool res_is_auth) {
    dmn_assert(ctx); dmn_assert(authdom);

    if(ctx->qtype == DNS_TYPE_ANY) {
        offset = encode_rrs_any(ctx, offset, res_rrsets);
    }
    else if(res_rrsets) {
        const ltree_rrset_t* node_rrset = res_rrsets;
        unsigned etype = ctx->qtype;
        // rrset_addr is stored as type DNS_TYPE_A for both A and AAAA
        if(etype == DNS_TYPE_AAAA) etype = DNS_TYPE_A;
        while(node_rrset) {
            if(node_rrset->gen.type == etype) {
                if(unlikely(etype & 0xFF00))
                    offset = encode_rrs_rfc3597(ctx, offset, &node_rrset->rfc3597, true);
                else
                    offset = encode_funcptrs[ctx->qtype](ctx, offset, node_rrset, true);
                break;
            }
            node_rrset = node_rrset->gen.next;
        }
    }

    if(!ctx->ancount)
        offset = encode_rr_soa_negative(ctx, offset, ltree_node_get_rrset_soa(authdom));
    else if(gconfig.include_optional_ns && ctx->qtype != DNS_TYPE_NS
        && (ctx->qtype != DNS_TYPE_ANY || !res_is_auth))
            offset = encode_rrs_ns(ctx, offset, ltree_node_get_rrset_ns(authdom), false);

    return offset;
}

// Find the start of the (uncompressed) auth zone name at auth_depth bytes into the name at qname_offset,
//  chasing compression pointers as necc.
// XXX - really, the necessity of this is sort of the last straw on the current scheme involving
//  the interactions of ctx->qname_comp, ctx->auth_comp, lqname, store_dname(), search_ltree(), and CNAME
//  processing.  It's too complex to understand easily and needs refactoring.
F_NONNULL F_PURE
static unsigned chase_auth_ptr(const uint8_t* packet, unsigned offset, unsigned auth_depth) {
    dmn_assert(packet); dmn_assert(offset);
    dmn_assert(offset < 65536);
    dmn_assert(auth_depth < 256);

    while(auth_depth) {
        unsigned llen = packet[offset];
        if(llen & 0xC0) { // compression pointer
            offset = ntohs(gdnsd_get_una16(&packet[offset])) & ~0xC000;
            dmn_assert(offset < 16384);
        }
        else {
            const unsigned move = llen + 1;
            dmn_assert(auth_depth >= move);
            offset += move;
            auth_depth -= move;
        }
    }

    return offset;
}

F_NONNULL
static ltree_dname_status_t search_zone_for_dname(const uint8_t* dname, const zone_t* zone, const ltree_node_t** node_out, unsigned* auth_deleg_mod) {
    dmn_assert(dname); dmn_assert(zone); dmn_assert(node_out);
    dmn_assert(*dname != 0); dmn_assert(*dname != 2); // these are always illegal dnames
    dmn_assert(dname_isinzone(zone->dname, dname));

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
        top_loop:;
        if(current->flags & LTNFLAG_DELEG) {
            rval = DNAME_DELEG;
            *auth_deleg_mod -= deleg_mod;
            rv_node = current;
            break;
        }

        if(!lcount || !current->child_table) {
            if(!lcount) rv_node = current;
            break;
        }

        lcount--;
        const uint8_t* child_label = lstack[lcount];
        deleg_mod += *child_label;
        deleg_mod++;
        ltree_node_t* entry = current->child_table[label_djb_hash(child_label, current->child_hash_mask)];

        while(entry) {
            if(!gdnsd_label_cmp(entry->label, child_label)) {
                current = entry;
                goto top_loop;
            }
            entry = entry->next;
        }
    } while(0);

    //  If in auth space with no match, and we still have a child_table, check for wildcard
    if(!rv_node && current->child_table) {
        dmn_assert(rval == DNAME_AUTH);
        static const uint8_t label_wild[2] =  { '\001', '*' };
        ltree_node_t* entry = current->child_table[label_djb_hash(label_wild, current->child_hash_mask)];
        while(entry) {
            if(entry->label[0] == '\001' && entry->label[1] == '*') {
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
static const ltree_rrset_t* process_dync(dnsp_ctx_t* ctx, const ltree_rrset_dync_t* rd) {
    dmn_assert(rd);
    dmn_assert(!rd->gen.next); // DYNC does not co-exist with other rrsets

    const unsigned ttl = do_dyn_callback(ctx, rd->func, rd->origin, rd->resource, rd->gen.ttl, rd->ttl_min);
    dyn_result_t* dr = ctx->dyn;

    if(dr->is_cname) {
        dmn_assert(gdnsd_dname_status(dr->storage) == DNAME_VALID);
        dmn_assert(ctx->dync_count < gconfig.max_cname_depth);
        uint8_t* cn_store = &ctx->dync_store[ctx->dync_count++ * 256];
        dname_copy(cn_store, dr->storage);
        ctx->dync_synth_rrset.gen.type = DNS_TYPE_CNAME;
        ctx->dync_synth_rrset.gen.count = 1;
        ctx->dync_synth_rrset.gen.ttl = ttl;
        ctx->dync_synth_rrset.cname.dname = cn_store;
    }
    else if(dr->count_v4 + dr->count_v6) {
        // ^ If both counts are zero, must represent this as
        //  a missing rrset (NULL rv).  An actual rrset with zero
        //  counts is interpreted as a DYNA entry in the ltree.
        unsigned lv4 = rd->limit_v4;
        if(!lv4 || lv4 > dr->count_v4)
            lv4 = dr->count_v4;

        unsigned lv6 = rd->limit_v6;
        if(!lv6 || lv6 > dr->count_v6)
            lv6 = dr->count_v6;

        ctx->dync_synth_rrset.gen.type = DNS_TYPE_A;
        ctx->dync_synth_rrset.gen.ttl = ttl;
        ctx->dync_synth_rrset.addr.count_v6 = dr->count_v6;
        ctx->dync_synth_rrset.gen.count = dr->count_v4;
        if(!dr->count_v6 && dr->count_v4 <= LTREE_V4A_SIZE) {
            memcpy(ctx->dync_synth_rrset.addr.v4a, dr->v4, sizeof(uint32_t) * dr->count_v4);
        }
        else {
            ctx->dync_synth_rrset.addr.addrs.v4 = dr->v4;
            ctx->dync_synth_rrset.addr.addrs.v6 = &dr->storage[result_v6_offset];
        }
        ctx->dync_synth_rrset.addr.limit_v4 = lv4;
        ctx->dync_synth_rrset.addr.limit_v6 = lv6;
    }

    return &ctx->dync_synth_rrset;
}

F_NONNULL
static unsigned answer_from_db(dnsp_ctx_t* ctx, dnspacket_stats_t* stats, const uint8_t* qname, unsigned offset) {
    dmn_assert(ctx); dmn_assert(stats); dmn_assert(qname); dmn_assert(offset);

    const unsigned first_offset = offset;
    bool via_cname = false;
    const ltree_node_t* resdom = NULL;
    const ltree_node_t* resauth = NULL;
    const ltree_rrset_t* res_rrsets = NULL;
    wire_dns_header_t* res_hdr = (wire_dns_header_t*)ctx->packet;

    ltree_dname_status_t status = DNAME_NOAUTH;
    unsigned auth_depth;

    gdnsd_prcu_rdr_lock();

    zone_t* query_zone = ztree_find_zone_for(qname, &auth_depth);

    if(query_zone) { // matches auth space somewhere
        resauth = query_zone->root;

        unsigned cname_depth = 0;
        bool iterating_for_cname = false;

        do { // This do/while loop handles CNAME chains...
            status = search_zone_for_dname(qname, query_zone, &resdom, &auth_depth);
            dmn_assert(status == DNAME_AUTH || status == DNAME_DELEG);

            if(!iterating_for_cname) {
                // In the initial search, it's known that "qname" is in fact the real query name and therefore
                //  uncompressed, which is what makes the simplistic ctx->auth_comp calculation possible.
                ctx->auth_comp = ctx->qname_comp + auth_depth;
            }
            else {
                ctx->auth_comp = chase_auth_ptr(ctx->packet, ctx->qname_comp, auth_depth);
            }

            iterating_for_cname = false;

            res_rrsets = resdom ? resdom->rrsets : NULL;
            if(res_rrsets && res_rrsets->gen.type == DNS_TYPE_DYNC)
                res_rrsets = process_dync(ctx, &res_rrsets->dync);

            // Indirect-CNAME-lookup (CNAME data for a non-CNAME(/ANY) query):
            // Fills in 1+ CNAME RRs and then alters status/resdom/via_cname
            //  for the normal response handling code below.  The explicit check of the first
            //  rrsets entry works because if CNAME exists at all, by definition it is the only
            //  type of rrset at this node.
            if(res_rrsets && res_rrsets->gen.type == DNS_TYPE_CNAME
                && ctx->qtype != DNS_TYPE_CNAME
                && ctx->qtype != DNS_TYPE_ANY) {

                dmn_assert(!res_rrsets->gen.next); // CNAME does not co-exist with other rrsets
                dmn_assert(status == DNAME_AUTH);

                res_hdr->flags1 |= 4; // AA bit
                via_cname = true;

                if(++cname_depth > gconfig.max_cname_depth) {
                    log_err("Query for '%s' leads to a CNAME chain longer than %u (max_cname_depth)! This is a DYNC plugin configuration problem, and gdnsd will respond with NXDOMAIN protect against infinite client<->server CNAME-chasing loops!", logf_dname(qname), gconfig.max_cname_depth);
                    // wipe state back to an empty NXDOMAIN response
                    resdom = NULL;
                    res_rrsets = NULL;
                    offset = first_offset;
                    ctx->ancount = 0;
                    ctx->cname_ancount = 0;
                    break;
                }

                const ltree_rrset_cname_t* cname = &res_rrsets->cname;
                offset = encode_rr_cname(ctx, offset, cname, false);

                if(dname_isinzone(query_zone->dname, cname->dname)) {
                    // if the RHS of the CNAME is still in-zone, we're going
                    //   to reset some initial parameters (qname, auth_depth)
                    //   and loop back up via the do/while...
                    qname = cname->dname;
                    auth_depth = *qname - *query_zone->dname;
                    iterating_for_cname = true;
                }
                else {
                    status = DNAME_NOAUTH;
                }
            } // indirect-CNAME-lookup block
        } while(iterating_for_cname); // recurse into CNAME chain
    } // end if(query_zone) block

    if(status == DNAME_AUTH) {
        dmn_assert(resauth);
        res_hdr->flags1 |= 4; // AA bit
        if(likely(resdom)) {
            offset = construct_normal_response(ctx, offset, res_rrsets, resauth, (resdom == resauth));
        }
        else {
            const ltree_rrset_soa_t* soa = ltree_node_get_rrset_soa(resauth);
            dmn_assert(soa);
            res_hdr->flags2 = DNS_RCODE_NXDOMAIN;
            offset = encode_rr_soa_negative(ctx, offset, soa);
            stats_own_inc(&stats->nxdomain);
        }
    }
    else if(status == DNAME_DELEG) {
        dmn_assert(resdom);
        const ltree_rrset_ns_t* ns = ltree_node_get_rrset_ns(resdom);
        dmn_assert(ns);
        offset = encode_rrs_ns(ctx, offset, ns, false);
    }
    else {
        dmn_assert(status == DNAME_NOAUTH);
        if(!via_cname) {
            res_hdr->flags2 = DNS_RCODE_REFUSED;
            stats_own_inc(&stats->refused);
        }
    }

    gdnsd_prcu_rdr_unlock();

    return offset;
}

F_NONNULL
static unsigned answer_from_db_outer(dnsp_ctx_t* ctx, dnspacket_stats_t* stats, uint8_t* qname, unsigned offset) {
    dmn_assert(ctx); dmn_assert(stats); dmn_assert(qname); dmn_assert(offset);

    const unsigned full_trunc_offset = offset;

    wire_dns_header_t* res_hdr = (wire_dns_header_t*)ctx->packet;
    offset = answer_from_db(ctx, stats, qname, offset);

    // Check for TC-bit (overflow w/ just ans, auth, and glue)
    if(unlikely(offset + (ctx->addtl_has_glue ? ctx->addtl_offset : 0) > ctx->this_max_response)) {
        ctx->ancount = 0;
        ctx->nscount = 0;
        ctx->arcount = 0;
        res_hdr->flags1 |= 0x2; // TC bit
        if(ctx->use_edns) {
            stats_own_inc(&stats->udp.edns_tc);
        }
        else {
            stats_own_inc(&stats->udp.tc);
        }
        return full_trunc_offset;
    }

    // Trim back the additional section by whole rrsets as necc to fit
    while(unlikely(ctx->addtl_offset > ctx->this_max_response - offset)) {
        const addtl_rrset_t* arrset = &ctx->addtl_rrsets[--ctx->addtl_count];
        ctx->addtl_offset = arrset->prev_offset;
        ctx->arcount = arrset->prev_arcount;
    }

    // Copy additional section (if any)
    memcpy(&ctx->packet[offset], ctx->addtl_store, ctx->addtl_offset);
    offset += ctx->addtl_offset;

    return offset;
}

unsigned process_dns_query(void* ctx_asvoid, dnspacket_stats_t* stats, const dmn_anysin_t* asin, uint8_t* packet, const unsigned packet_len) {
    dmn_assert(ctx_asvoid); dmn_assert(stats); dmn_assert(asin); dmn_assert(packet);

    dnsp_ctx_t* ctx = ctx_asvoid;
    reset_context(ctx);
    ctx->packet = packet;

/*
    log_devdebug("Processing %sv%u DNS query of length %u from %s",
        (ctx->is_udp ? "UDP" : "TCP"),
        (asin->sa.sa_family == AF_INET6) ? 6 : 4,
        packet_len,
        dmn_logf_anysin(asin));
*/

    if(asin->sa.sa_family == AF_INET6)
        stats_own_inc(&stats->v6);

    uint8_t lqname[256];
    unsigned question_len = 0;

    const rcode_rv_t status = decode_query(ctx, stats, lqname, &question_len, packet_len, asin);

    if(status == DECODE_IGNORE) {
        stats_own_inc(&stats->dropped);
        return 0;
    }

    unsigned res_offset = sizeof(wire_dns_header_t);

    wire_dns_header_t* hdr = (wire_dns_header_t*)packet;
    hdr->flags1 &= 0x79;
    hdr->flags1 |= 0x80;
    gdnsd_put_una16(0, &hdr->ancount);
    gdnsd_put_una16(0, &hdr->nscount);
    gdnsd_put_una16(0, &hdr->arcount);

    if(status == DECODE_NOTIMP) {
        gdnsd_put_una16(0, &hdr->qdcount);
        hdr->flags2 = DNS_RCODE_NOTIMP;
        stats_own_inc(&stats->notimp);
        return res_offset;
    }

    res_offset += question_len;

    if(likely(status == DECODE_OK)) {
        hdr->flags2 = DNS_RCODE_NOERROR;
        if(*lqname != 1) {
            ctx->comptarget_count = 1;
            ctx->comptargets[0].original = lqname;
            ctx->comptargets[0].comp_ptr = lqname + 255;
            ctx->comptargets[0].stored_at = sizeof(wire_dns_header_t);
        }
        ctx->qname_comp = 0x0C;

        if(likely(!ctx->chaos)) {
            memcpy(&ctx->client_info.dns_source, asin, sizeof(dmn_anysin_t));
            res_offset = answer_from_db_outer(ctx, stats, lqname, res_offset);
        }
        else {
            ctx->ancount = 1;
            memcpy(&packet[res_offset], gconfig.chaos, gconfig.chaos_len);
            res_offset += gconfig.chaos_len;
        }

        if(hdr->flags2 == DNS_RCODE_NOERROR) stats_own_inc(&stats->noerror);
    }
    else {
        if(status == DECODE_FORMERR) {
            hdr->flags2 = DNS_RCODE_FORMERR;
            stats_own_inc(&stats->formerr);
        }
        else {
            dmn_assert(status == DECODE_BADVERS);
            hdr->flags2 = DNS_RCODE_NOERROR;
            stats_own_inc(&stats->badvers);
        }
    }

    if(ctx->use_edns) {
        packet[res_offset++] = '\0'; // domainname part of OPT
        wire_dns_rr_opt_t* opt = (wire_dns_rr_opt_t*)&packet[res_offset];
        res_offset += sizeof_optrr;

        gdnsd_put_una16(htons(DNS_TYPE_OPT), &opt->type);
        gdnsd_put_una16(htons(DNS_EDNS0_SIZE), &opt->maxsize);
        gdnsd_put_una32((status == DECODE_BADVERS) ? htonl(0x01000000) : 0, &opt->extflags);
        gdnsd_put_una16(0, &opt->rdlen);

        if(ctx->use_edns_client_subnet) {
            gdnsd_put_una16(htons(EDNS_CLIENTSUB_OPTCODE), &packet[res_offset]);
            res_offset += 2;
            const unsigned src_mask = ctx->client_info.edns_client_mask;
            const unsigned addr_bytes = (src_mask >> 3) + ((src_mask & 7) ? 1 : 0);
            gdnsd_put_una16(htons(8 + addr_bytes), &opt->rdlen);
            gdnsd_put_una16(htons(4 + addr_bytes), &packet[res_offset]);
            res_offset += 2;
            if(ctx->client_info.edns_client.sa.sa_family == AF_INET) {
                gdnsd_put_una16(htons(1), &packet[res_offset]); // family IPv4
                res_offset += 2;
                packet[res_offset++] = src_mask;
                packet[res_offset++] = ctx->edns_client_scope_mask;
                memcpy(&packet[res_offset], &ctx->client_info.edns_client.sin.sin_addr.s_addr, addr_bytes);
                res_offset += addr_bytes;
            }
            else {
                dmn_assert(ctx->client_info.edns_client.sa.sa_family == AF_INET6);
                gdnsd_put_una16(htons(2), &packet[res_offset]); // family IPv6
                res_offset += 2;
                packet[res_offset++] = src_mask;
                packet[res_offset++] = ctx->edns_client_scope_mask;
                memcpy(&packet[res_offset], ctx->client_info.edns_client.sin6.sin6_addr.s6_addr, addr_bytes);
                res_offset += addr_bytes;
            }
        }

        ctx->arcount++;
        if(likely(ctx->is_udp)) {
            // We only do one kind of truncation: complete truncation.
            //  therefore if we're returning a >512 packet, it wasn't truncated
            if(res_offset > 512) stats_own_inc(&stats->udp.edns_big);
        }
    }

    gdnsd_put_una16(htons(ctx->cname_ancount + ctx->ancount), &hdr->ancount);
    gdnsd_put_una16(htons(ctx->nscount), &hdr->nscount);
    gdnsd_put_una16(htons(ctx->arcount), &hdr->arcount);

    return res_offset;
}
