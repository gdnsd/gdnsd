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
#include "gdnsd/log.h"
#include "gdnsd/misc.h"
#include "gdnsd/plugapi-priv.h"
#include "gdnsd/prcu-priv.h"
#include "ztree.h"

static pthread_mutex_t stats_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t stats_init_cond = PTHREAD_COND_INITIALIZER;
static unsigned stats_initialized = 0;

dnspacket_stats_t** dnspacket_stats;

// Allocates the array of pointers to stats structures, one per I/O thread
// Called from main thread before I/O threads are spawned
void dnspacket_global_setup(void) {
    dnspacket_stats = calloc(gconfig.num_io_threads, sizeof(dnspacket_stats_t*));
}

// Called from main thread after starting all of the I/O threads,
//  ensures they all finish allocating their stats and storing the pointers
//  into dnspacket_stats before allowing the main thread to continue.
void dnspacket_wait_stats(void) {
    const unsigned waitfor = gconfig.num_io_threads;
    pthread_mutex_lock(&stats_init_mutex);
    while(stats_initialized < waitfor)
        pthread_cond_wait(&stats_init_cond, &stats_init_mutex);
    pthread_mutex_unlock(&stats_init_mutex);
}

// Called (indirectly via dnspacket_context_new) by each I/O thread to init
//  its own stats structure, signals the above.  Also invokes the plugins'
//  iothread_init callbacks.
static dnspacket_stats_t* dnspacket_init_stats(unsigned int this_threadnum, const bool is_udp) {
    pthread_mutex_lock(&stats_init_mutex);
    dnspacket_stats_t* retval = dnspacket_stats[this_threadnum]
        = calloc(1, sizeof(dnspacket_stats_t));

    retval->is_udp = is_udp;

    gdnsd_plugins_action_iothread_init(this_threadnum);

    stats_initialized++;
    pthread_cond_signal(&stats_init_cond);
    pthread_mutex_unlock(&stats_init_mutex);

    return retval;
}

dnspacket_context_t* dnspacket_context_new(const unsigned int this_threadnum, const bool is_udp) {
    dnspacket_context_t* retval = calloc(1, sizeof(dnspacket_context_t));

    retval->rand_state = gdnsd_rand_init();
    retval->stats = dnspacket_init_stats(this_threadnum, is_udp);
    retval->is_udp = is_udp;
    retval->threadnum = this_threadnum;
    retval->addtl_rrsets = malloc(gconfig.max_addtl_rrsets * sizeof(addtl_rrset_t));
    retval->comptargets = malloc(COMPTARGETS_MAX * sizeof(comptarget_t));
    retval->dync_store = malloc(gconfig.max_cname_depth * 256);
    retval->addtl_store = malloc(gconfig.max_response);
    retval->dynaddr = malloc(sizeof(dynaddr_result_t));

    return retval;
}

F_NONNULL
static void reset_context(dnspacket_context_t* c) {
    dmn_assert(c);
    memset(
        &c->answer_addr_rrset, 0,
        sizeof(dnspacket_context_t) - offsetof(dnspacket_context_t, answer_addr_rrset)
    );
}

// "buf" points to the question section of an input packet.
F_NONNULL
static unsigned int parse_question(dnspacket_context_t* c, uint8_t* lqname, const uint8_t* buf, const unsigned int len) {
    dmn_assert(c); dmn_assert(lqname); dmn_assert(buf);

    uint8_t* lqname_ptr = lqname + 1;
    unsigned pos = 0;
    unsigned llen;
    while((llen = *lqname_ptr++ = buf[pos++])) {
        if(unlikely(llen & 0xC0)) {
            log_debug("Label compression detected in question, failing.");
            pos = 0;
            break;
        }

        if(unlikely(pos + llen >= len)) {
            log_debug("Query name truncated (runs off end of packet)");
            pos = 0;
            break;
        }

        if(unlikely(pos + llen > 254)) {
            log_debug("Query domain name too long");
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
            c->qtype = ntohs(gdnsd_get_una16(&buf[pos]));
            pos += 2;

            if(ntohs(gdnsd_get_una16(&buf[pos])) == 3U)
               c->chaos = true;
            pos += 2;
        }
        else {
            log_debug("Packet length exhausted before parsing question type/class!");
            pos = 0;
        }
    }

    return pos;
}

// retval: true -> FORMERR, false -> OK
F_NONNULL
static bool handle_edns_client_subnet(dnspacket_context_t* c, const unsigned opt_code, unsigned opt_len, const uint8_t* opt_data) {
    dmn_assert(c); dmn_assert(opt_data);

    bool rv = false;

    do {
        if(opt_len < 4) {
            log_debug("edns_client_subnet data too short (%u bytes)", opt_len);
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
            log_debug("edns_client_subnet: addr length %u too short for src_mask of %u", opt_len, src_mask);
            rv = true;
            break;
        }

        if(family == 1) { // IPv4
            if(src_mask > 32) {
                log_debug("edns_client_subnet: invalid src_mask of %u for IPv4", src_mask);
                rv = true;
                break;
            }
            c->client_info.edns_client.sa.sa_family = AF_INET;
            memcpy(&c->client_info.edns_client.sin.sin_addr.s_addr, opt_data, addr_bytes);
        }
        else if(family == 2) { // IPv6
            if(src_mask > 128) {
                log_debug("edns_client_subnet: invalid src_mask of %u for IPv6", src_mask);
                rv = true;
                break;
            }
            c->client_info.edns_client.sa.sa_family = AF_INET6;
            memcpy(c->client_info.edns_client.sin6.sin6_addr.s6_addr, opt_data, addr_bytes);
        }
        else {
            log_debug("edns_client_subnet has unknown family %u", family);
            rv = true;
            break;
        }

        c->this_max_response -= (8 + addr_bytes); // leave room for response option
        c->use_edns_client_subnet = true;
        c->clientsub_opt_code = opt_code;
        c->client_info.edns_client_mask = src_mask;
    } while(0);

    stats_own_inc(&c->stats->edns_clientsub);
    return rv;
}

// retval: true -> FORMERR, false -> OK
F_NONNULL
static bool handle_edns_option(dnspacket_context_t* c, unsigned opt_code, unsigned opt_len, const uint8_t* opt_data) {
    dmn_assert(c); dmn_assert(opt_data);

    bool rv = false;
    if((opt_code == EDNS_CLIENTSUB_OPTCODE_IANA
      || opt_code == EDNS_CLIENTSUB_OPTCODE_DEPRECATED)
      && gconfig.edns_client_subnet)
        rv = handle_edns_client_subnet(c, opt_code, opt_len, opt_data);
    else
        log_debug("Unknown EDNS option code: %x", opt_code);

    return rv;
}

// retval: true -> FORMERR, false -> OK
F_NONNULL
static bool handle_edns_options(dnspacket_context_t* c, unsigned rdlen, const uint8_t* rdata) {
    dmn_assert(c); dmn_assert(rdlen); dmn_assert(rdata);

    bool rv = false;

    // minimum edns option length is 4 bytes (2 byte option code, 2 byte data len)
    while(rdlen) {
        if(rdlen < 4) {
            log_debug("EDNS option too short");
            rv = true;
            break;
        }
        unsigned opt_code = ntohs(gdnsd_get_una16(rdata)); rdata += 2;
        unsigned opt_dlen = ntohs(gdnsd_get_una16(rdata)); rdata += 2;
        rdlen -= 4;
        if(opt_dlen > rdlen) {
            log_debug("EDNS option too long");
            rv = true;
            break;
        }
        if(handle_edns_option(c, opt_code, opt_dlen, rdata)) {
            rv = true; // option handler indicated FORMERR
            break;
        }
        rdlen -= opt_dlen;
        rdata += opt_dlen;
    }

    return rv;
}

F_CONST static inline unsigned max_unsigned(const unsigned int a, const unsigned int b) { return a > b ? a : b; }
F_CONST static inline unsigned min_unsigned(const unsigned int a, const unsigned int b) { return a < b ? a : b; }

typedef enum {
    DECODE_IGNORE  = -4, // totally invalid packet (len < header len or unparseable question, and we do not respond)
    DECODE_FORMERR = -3, // slightly better but still invalid input, we return FORMERR
    DECODE_BADVERS = -2, // EDNS version higher than ours (0)
    DECODE_NOTIMP  = -1, // non-QUERY opcode or [AI]XFER, we return NOTIMP
    DECODE_OK      =  0, // normal and valid
} rcode_rv_t;

F_NONNULL
static rcode_rv_t parse_optrr(dnspacket_context_t* c, const wire_dns_rr_opt_t* opt, const anysin_t* asin V_UNUSED, const unsigned packet_len, const unsigned offset) {
    dmn_assert(c); dmn_assert(opt); dmn_assert(asin);

    rcode_rv_t rcode = DECODE_OK;
    c->use_edns = true;            // send OPT RR with response
    stats_own_inc(&c->stats->edns);
    if(likely(DNS_OPTRR_GET_VERSION(opt) == 0)) {
        if(likely(c->is_udp)) {
            // The "512" here is us not allowing them to specify a size smaller than 512
            c->this_max_response = min_unsigned(max_unsigned(DNS_OPTRR_GET_MAXSIZE(opt), 512U), gconfig.max_response) - 11;
        }
        else {
            c->this_max_response = gconfig.max_response - 11;
        }

        unsigned rdlen = htons(gdnsd_get_una16(&opt->rdlen));
        if(rdlen) {
            if(packet_len < offset + sizeof_optrr + rdlen) {
                log_debug("Received EDNS OPT RR with options data longer than packet length from %s", logf_anysin(asin));
                rcode = DECODE_FORMERR;
            }
            else if(handle_edns_options(c, rdlen, opt->rdata)) {
                rcode = DECODE_FORMERR;
            }
        }
    }
    else {
        log_debug("Received EDNS OPT RR with VERSION > 0 (BADVERSION) from %s", logf_anysin(asin));
        rcode = DECODE_BADVERS;
    }

    return rcode;
}

F_NONNULL
static rcode_rv_t decode_query(dnspacket_context_t* c, uint8_t* lqname, unsigned* question_len_ptr, const unsigned int packet_len, const anysin_t* asin) {
    dmn_assert(c); dmn_assert(c->packet); dmn_assert(lqname); dmn_assert(question_len_ptr); dmn_assert(asin);

    rcode_rv_t rcode = DECODE_OK;

    do {
        // 5 is the minimal question length (1 byte root, 2 bytes each type and class)
        if(unlikely(packet_len < (sizeof(wire_dns_header_t) + 5))) {
            log_debug("Ignoring short request from %s of length %u", logf_anysin(asin), packet_len);
            rcode = DECODE_IGNORE;
        }

        uint8_t* packet = c->packet;
        const wire_dns_header_t* hdr = (const wire_dns_header_t*)packet;

/*
    log_debug("Query header details: ID:%hu QR:%i OPCODE:%hhu AA:%i TC:%i RD:%i RA:%i AD:%i CD:%i RCODE:%hhu QDCOUNT:%hu ANCOUNT:%hu NSCOUNT:%hu ARCOUNT:%hu",
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
            log_debug("Received request from %s with %hu questions, ignoring", logf_anysin(asin), DNSH_GET_QDCOUNT(hdr));
            rcode = DECODE_IGNORE;
            break;
        }

        if(unlikely(DNSH_GET_QR(hdr))) {
            log_debug("QR bit set in query from %s, ignoring", logf_anysin(asin));
            rcode = DECODE_IGNORE;
            break;
        }

        if(unlikely(DNSH_GET_TC(hdr))) {
            log_debug("TC bit set in query from %s, ignoring", logf_anysin(asin));
            rcode = DECODE_IGNORE;
            break;
        }

        unsigned int offset = sizeof(wire_dns_header_t);
        if(unlikely(!(*question_len_ptr = parse_question(c, lqname, &packet[offset], packet_len - offset)))) {
            log_debug("Failed to parse question, ignoring %s", logf_anysin(asin));
            rcode = DECODE_IGNORE;
            break;
        }

        if(DNSH_GET_OPCODE(hdr)) {
            log_debug("Non-QUERY request (NOTIMP) from %s, opcode is %u", logf_anysin(asin), (DNSH_GET_OPCODE(hdr) >> 3U));
            rcode = DECODE_NOTIMP;
            break;
        }

        if(unlikely(c->qtype == DNS_TYPE_AXFR)) {
            log_debug("AXFR attempted (NOTIMP) from %s", logf_anysin(asin));
            rcode = DECODE_NOTIMP;
            break;
        }

        if(unlikely(c->qtype == DNS_TYPE_IXFR)) {
            log_debug("IXFR attempted (NOTIMP) from %s", logf_anysin(asin));
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
            rcode = parse_optrr(c, opt, asin, packet_len, offset + 1);
        }
        else if(likely(c->is_udp)) { // No valid EDNS OPT RR in request, UDP
            c->this_max_response = 512;
        }
        else { // No valid EDNS OPT RR in request, TCP
            c->this_max_response = gconfig.max_response;
        }
    } while (0);

    return rcode;
}

// is_addtl refers to where we're storing to
F_NONNULL
static unsigned int store_dname_nocomp(dnspacket_context_t* c, const unsigned int pkt_dname_offset, const uint8_t* dn) {
    dmn_assert(c); dmn_assert(pkt_dname_offset); dmn_assert(dn);

    if(*dn != 1 && likely(pkt_dname_offset < 16384) && likely(c->comptarget_count < COMPTARGETS_MAX)) {
        comptarget_t* new_ctarg = &(c->comptargets[c->comptarget_count++]);
        new_ctarg->original = dn;
        new_ctarg->stored_at = pkt_dname_offset;
        new_ctarg->comp_ptr = dn + 255;
    }

    const unsigned int final_size = *dn;
    memcpy(&c->packet[pkt_dname_offset], dn + 1, final_size);

    return final_size;
}

// is_addtl refers to where we're storing to
F_NONNULL
static unsigned int store_dname(dnspacket_context_t* c, const unsigned int pkt_dname_offset, const uint8_t* dn, const bool is_addtl) {
    dmn_assert(c); dmn_assert(dn);

    uint8_t* packet = is_addtl ? c->addtl_store : c->packet;

    // Deal with the root case, which should never be compressed, or compressed against
    if(*dn == 1) {
       dmn_assert(dn[1] == '\0');
       packet[pkt_dname_offset] = '\0';
       return 1;
    }

    dmn_assert(*dn > 2);
    const uint8_t* dn_last = dn + *dn;
    const unsigned dn_len = *dn++;

    unsigned int best_offset = 0;
    const uint8_t* best_matched_at = dn + 255;

    const comptarget_t* ctarg = c->comptargets;

    for(unsigned x = c->comptarget_count; x--; ) {
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
        if(!is_addtl && likely(pkt_dname_offset < 16384) && likely(c->comptarget_count < COMPTARGETS_MAX)) {
            comptarget_t* new_ctarg = &(c->comptargets[c->comptarget_count++]);
            new_ctarg->original = dn - 1;
            new_ctarg->stored_at = pkt_dname_offset;
            new_ctarg->comp_ptr = best_matched_at;
        }
    }

    if(best_offset) {
        const unsigned int final_size = best_matched_at - dn + 2;
        const unsigned int tocopy = final_size - 2;
        memcpy(&packet[pkt_dname_offset], dn, tocopy);
        gdnsd_put_una16(htons(0xC000 | best_offset), &packet[pkt_dname_offset + tocopy]);
        return final_size;
    }
    else {
        memcpy(&packet[pkt_dname_offset], dn, dn_len);
        return dn_len;
    }
}

// We know a given name was stored at packet+orig_offset already.  We
//  want to repeat it at (packet|addtl_store)+store_at_offset, using
//  compression if possible and warranted, but not pointer-to-pointer.
// The rules:
//  is_addtl indicates whether we're storing to additional section or not.
//  regardless, orig_offset is from main storage (answer/auth sections)
//  if !is_addtl, orig_offset must be one of c->qname_comp or c->auth_comp,
//    both of which are gauranteed <16K offset.
F_NONNULL
static unsigned int repeat_name(dnspacket_context_t* c, unsigned int store_at_offset, unsigned int orig_offset, const bool is_addtl) {
    dmn_assert(c); dmn_assert(c->packet);
    if(!is_addtl) {
        dmn_assert(orig_offset < 16384);
        dmn_assert(orig_offset == c->qname_comp || orig_offset == c->auth_comp);
    }

    const uint8_t* inpkt = c->packet;
    uint8_t* outpkt = is_addtl ? c->addtl_store : c->packet;

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
                dname_status_t dnstat V_UNUSED
                    = gdnsd_dname_from_raw(dntmp, &inpkt[orig_offset]);
                dmn_assert(dnstat == DNAME_VALID);
                rv = store_dname(c, store_at_offset, dntmp, true);
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
        unsigned i = gdnsd_rand_get32(c->rand_state) % _tot;\
        while(_x_count--) {\

            // Your code using "i" as an rrset index goes here
#define OFFSET_LOOP_END \
            if(++i == _tot)\
              i = 0;\
        }\
    }

F_NONNULL
static unsigned int enc_a_static(dnspacket_context_t* c, unsigned int offset, const ltree_rrset_addr_t* rrset, const unsigned int nameptr, const bool is_addtl) {
    dmn_assert(c); dmn_assert(rrset);
    dmn_assert(rrset->gen.count_v4);

    uint8_t* packet = is_addtl ? c->addtl_store : c->packet;

    if(is_addtl)
        c->arcount += rrset->limit_v4;
    else
        c->ancount += rrset->limit_v4;

    OFFSET_LOOP_START(rrset->gen.count_v4, rrset->limit_v4)
        offset += repeat_name(c, offset, nameptr, is_addtl);
        gdnsd_put_una32(DNS_RRFIXED_A, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 4;
        gdnsd_put_una16(htons(4), &packet[offset]);
        offset += 2;
        gdnsd_put_una32(rrset->addrs.v4[i], &packet[offset]);
        offset += 4;
    OFFSET_LOOP_END
    return offset;
}

F_NONNULL
static unsigned int enc_aaaa_static(dnspacket_context_t* c, unsigned int offset, const ltree_rrset_addr_t* rrset, const unsigned int nameptr, const bool is_addtl) {
    dmn_assert(c); dmn_assert(rrset);
    dmn_assert(rrset->gen.count_v6);

    uint8_t* packet = is_addtl ? c->addtl_store : c->packet;

    if(is_addtl)
        c->arcount += rrset->limit_v6;
    else
        c->ancount += rrset->limit_v6;

    OFFSET_LOOP_START(rrset->gen.count_v6, rrset->limit_v6)
        offset += repeat_name(c, offset, nameptr, is_addtl);
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
static unsigned int enc_a_dynamic(dnspacket_context_t* c, unsigned int offset, const ltree_rrset_addr_t* rrset, const unsigned int nameptr, const bool is_addtl) {
    dmn_assert(c); dmn_assert(c->packet);

    uint8_t* packet = is_addtl ? c->addtl_store : c->packet;
    const dynaddr_result_t* dr = c->dynaddr;
    dmn_assert(dr->count_v4);

    const unsigned limit_v4 = rrset->limit_v4 && rrset->limit_v4 < dr->count_v4
        ? rrset->limit_v4
        : dr->count_v4;

    if(is_addtl)
        c->arcount += limit_v4;
    else
        c->ancount += limit_v4;

    OFFSET_LOOP_START(dr->count_v4, limit_v4)
        offset += repeat_name(c, offset, nameptr, is_addtl);
        gdnsd_put_una32(DNS_RRFIXED_A, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(htonl(dr->ttl), &packet[offset]);
        offset += 4;
        gdnsd_put_una16(htons(4), &packet[offset]);
        offset += 2;
        gdnsd_put_una32(dr->addrs_v4[i], &packet[offset]);
        offset += 4;
    OFFSET_LOOP_END
    return offset;
}

F_NONNULL
static unsigned int enc_aaaa_dynamic(dnspacket_context_t* c, unsigned int offset, const ltree_rrset_addr_t* rrset, const unsigned int nameptr, const bool is_addtl) {
    dmn_assert(c); dmn_assert(c->packet);

    uint8_t* packet = is_addtl ? c->addtl_store : c->packet;
    const dynaddr_result_t* dr = c->dynaddr;
    dmn_assert(dr->count_v6);

    const unsigned limit_v6 = rrset->limit_v6 && rrset->limit_v6 < dr->count_v6
        ? rrset->limit_v6
        : dr->count_v6;

    if(is_addtl)
        c->arcount += limit_v6;
    else
        c->ancount += limit_v6;

    OFFSET_LOOP_START(dr->count_v6, limit_v6)
        offset += repeat_name(c, offset, nameptr, is_addtl);
        gdnsd_put_una32(DNS_RRFIXED_AAAA, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(htonl(dr->ttl), &packet[offset]);
        offset += 4;
        gdnsd_put_una16(htons(16), &packet[offset]);
        offset += 2;
        memcpy(&packet[offset], dr->addrs_v6 + (i << 4), 16);
        offset += 16;
    OFFSET_LOOP_END
    return offset;
}

// Invoke dynaddr callback for DYNA rr 'rrset', taking care of zeroing
//   out c->dynaddr, setting up the ttl from the zonefile, and accounting
//   for the packet's scope_mask after the callback.
// After invoking this function, code can assume c->dynaddr contains proper results
F_NONNULL
static void do_dynaddr_callback(dnspacket_context_t* c, const ltree_rrset_addr_t* rrset) {
    dmn_assert(c); dmn_assert(rrset); dmn_assert(!rrset->gen.is_static);

    dynaddr_result_t* dr = c->dynaddr;
    memset(dr, 0, sizeof(dynaddr_result_t));
    dr->ttl = ntohl(rrset->gen.ttl);
    rrset->dyn.func(c->threadnum, rrset->dyn.resource, &c->client_info, dr);
    if(dr->edns_scope_mask > c->edns_client_scope_mask)
        c->edns_client_scope_mask = dr->edns_scope_mask;
}

F_NONNULL
static unsigned int encode_rrs_anyaddr(dnspacket_context_t* c, unsigned int offset, const ltree_rrset_addr_t* rrset, const unsigned int nameptr, const bool is_addtl) {
    dmn_assert(c); dmn_assert(rrset);

    // This is to prevent duplicating the answer AAAA+A
    // rrset in the addtl section
    if(!is_addtl)
        c->answer_addr_rrset = rrset;

    if(rrset->gen.is_static) {
        if(rrset->gen.count_v4)
            offset = enc_a_static(c, offset, rrset, nameptr, is_addtl);
        if(rrset->gen.count_v6)
            offset = enc_aaaa_static(c, offset, rrset, nameptr, is_addtl);
    }
    else {
        do_dynaddr_callback(c, rrset);
        if(c->dynaddr->count_v4)
            offset = enc_a_dynamic(c, offset, rrset, nameptr, is_addtl);
        if(c->dynaddr->count_v6)
            offset = enc_aaaa_dynamic(c, offset, rrset, nameptr, is_addtl);
    }

    return offset;
}

// retval indicates whether to actually add it or not
F_NONNULL
static bool add_addtl_rrset_check(const dnspacket_context_t* c, const ltree_rrset_addr_t* rrset) {
    dmn_assert(c); dmn_assert(rrset);

    bool rv = true;

    // gconfig.max_addtl_rrsets unique addtl rrsets
    if(unlikely(c->addtl_count == gconfig.max_addtl_rrsets)) {
        rv = false;
    }
    else {
        for(unsigned int i = 0; i < c->addtl_count; i++) {
            if(unlikely(c->addtl_rrsets[i].rrset == rrset)) {
                rv = false;
                break;
            }
        }
    }

    return rv;
}

F_NONNULL
static void track_addtl_rrset_unwind(dnspacket_context_t* c, const ltree_rrset_addr_t* rrset) {
    dmn_assert(c); dmn_assert(rrset);

    // arcount and addtl_offset should be zero when first additional is added...
    dmn_assert(c->addtl_count || !c->addtl_offset);
    dmn_assert(c->addtl_count || !c->arcount);

    // store info for unwinding if we run out of space for additionals
    addtl_rrset_t* arrset = &c->addtl_rrsets[c->addtl_count++];
    arrset->rrset = rrset;
    arrset->prev_offset = c->addtl_offset;
    arrset->prev_arcount = c->arcount;
}

F_NONNULL
static void add_addtl_rrset(dnspacket_context_t* c, const ltree_rrset_addr_t* rrset, const unsigned int nameptr) {
    dmn_assert(c); dmn_assert(rrset);

    if(rrset != c->answer_addr_rrset && add_addtl_rrset_check(c, rrset)) {
        track_addtl_rrset_unwind(c, rrset);
        c->addtl_offset = encode_rrs_anyaddr(c, c->addtl_offset, rrset, nameptr, true);
    }
}

// Note we track_addtl_rrset_unwind() in encode_rrs_a/aaaa, but
//  do not do the add_addtl_rrset_check() first.  These functions
//  are asserted to only be called for direct A/AAAA queries, so
//  it's impossible for the check to fail.
F_NONNULL
static unsigned int encode_rrs_a(dnspacket_context_t* c, unsigned int offset, const ltree_rrset_addr_t* rrset, const bool answer V_UNUSED) {
    dmn_assert(c); dmn_assert(offset); dmn_assert(rrset);
    dmn_assert(c->qtype == DNS_TYPE_A);

    // This is to prevent duplicating the answer AAAA+A
    // rrset in the addtl section
    c->answer_addr_rrset = rrset;

    if(rrset->gen.is_static) {
        if(rrset->gen.count_v4)
            offset = enc_a_static(c, offset, rrset, c->qname_comp, false);
        if(rrset->gen.count_v6) {
            track_addtl_rrset_unwind(c, rrset);
            c->addtl_offset = enc_aaaa_static(c, c->addtl_offset, rrset, c->qname_comp, true);
        }
    }
    else {
        do_dynaddr_callback(c, rrset);
        if(c->dynaddr->count_v4)
            offset = enc_a_dynamic(c, offset, rrset, c->qname_comp, false);
        if(c->dynaddr->count_v6) {
            track_addtl_rrset_unwind(c, rrset);
            c->addtl_offset = enc_aaaa_dynamic(c, c->addtl_offset, rrset, c->qname_comp, true);
        }
    }

    return offset;
}

F_NONNULL
static unsigned int encode_rrs_aaaa(dnspacket_context_t* c, unsigned int offset, const ltree_rrset_addr_t* rrset, const bool answer V_UNUSED) {
    dmn_assert(c); dmn_assert(offset); dmn_assert(rrset);
    dmn_assert(c->qtype == DNS_TYPE_AAAA);

    // This is to prevent duplicating the answer AAAA+A
    // rrset in the addtl section
    c->answer_addr_rrset = rrset;

    if(rrset->gen.is_static) {
        if(rrset->gen.count_v6)
            offset = enc_aaaa_static(c, offset, rrset, c->qname_comp, false);
        if(rrset->gen.count_v4) {
            track_addtl_rrset_unwind(c, rrset);
            c->addtl_offset = enc_a_static(c, c->addtl_offset, rrset, c->qname_comp, true);
        }
    }
    else {
        do_dynaddr_callback(c, rrset);
        if(c->dynaddr->count_v6)
            offset = enc_aaaa_dynamic(c, offset, rrset, c->qname_comp, false);
        if(c->dynaddr->count_v4) {
            track_addtl_rrset_unwind(c, rrset);
            c->addtl_offset = enc_a_dynamic(c, c->addtl_offset, rrset, c->qname_comp, true);
        }
    }

    return offset;
}

F_NONNULL
static unsigned int encode_rrs_ns(dnspacket_context_t* c, unsigned int offset, const ltree_rrset_ns_t* rrset, const bool answer) {
    dmn_assert(c); dmn_assert(c->packet); dmn_assert(offset); dmn_assert(rrset);
    dmn_assert(rrset->gen.count); // we never call encode_rrs_ns without an NS record present

    uint8_t* packet = c->packet;

    OFFSET_LOOP_START(rrset->gen.count, rrset->gen.count)
        offset += repeat_name(c, offset, c->auth_comp, false);
        gdnsd_put_una32(DNS_RRFIXED_NS, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;
        const unsigned int newlen = store_dname(c, offset, rrset->rdata[i].dname, false);
        gdnsd_put_una16(htons(newlen), &packet[offset - 2]);
        if(rrset->rdata[i].ad) {
            if(AD_IS_GLUE(rrset->rdata[i].ad)) {
                c->addtl_has_glue = true;
                add_addtl_rrset(c, AD_GET_PTR(rrset->rdata[i].ad), offset);
            }
            else {
                add_addtl_rrset(c, rrset->rdata[i].ad, offset);
            }
        }
        offset += newlen;
    OFFSET_LOOP_END

    if(answer)
        c->ancount += rrset->gen.count;
    else
        c->nscount += rrset->gen.count;

    return offset;
}

F_NONNULL
static unsigned int encode_rrs_ptr(dnspacket_context_t* c, unsigned int offset, const ltree_rrset_ptr_t* rrset, const bool answer V_UNUSED) {
    dmn_assert(c); dmn_assert(c->packet); dmn_assert(offset); dmn_assert(rrset);

    uint8_t* packet = c->packet;

    const unsigned rrct = rrset->gen.count;
    c->ancount += rrct;
    for(unsigned i = 0; i < rrct; i++) {
        offset += repeat_name(c, offset, c->qname_comp, false);
        gdnsd_put_una32(DNS_RRFIXED_PTR, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;
        const unsigned int newlen = store_dname(c, offset, rrset->rdata[i].dname, false);
        gdnsd_put_una16(htons(newlen), &packet[offset - 2]);
        if(rrset->rdata[i].ad)
            add_addtl_rrset(c, rrset->rdata[i].ad, offset);
        offset += newlen;
    }

    return offset;
}

F_NONNULL
static unsigned int encode_rrs_mx(dnspacket_context_t* c, unsigned int offset, const ltree_rrset_mx_t* rrset, const bool answer V_UNUSED) {
    dmn_assert(c); dmn_assert(c->packet); dmn_assert(offset); dmn_assert(rrset);

    uint8_t* packet = c->packet;

    const unsigned rrct = rrset->gen.count;
    c->ancount += rrct;
    for(unsigned int i = 0; i < rrct; i++) {
        offset += repeat_name(c, offset, c->qname_comp, false);
        gdnsd_put_una32(DNS_RRFIXED_MX, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;
        const ltree_rdata_mx_t* rd = &rrset->rdata[i];
        gdnsd_put_una16(rd->pref, &packet[offset]);
        offset += 2;
        const unsigned int newlen = store_dname(c, offset, rd->dname, false);
        gdnsd_put_una16(htons(newlen + 2), &packet[offset - 4]);
        if(rd->ad)
            add_addtl_rrset(c, rd->ad, offset);
        offset += newlen;
    }

    return offset;
}

F_NONNULL
static unsigned int encode_rrs_srv(dnspacket_context_t* c, unsigned int offset, const ltree_rrset_srv_t* rrset, const bool answer V_UNUSED) {
    dmn_assert(c); dmn_assert(c->packet); dmn_assert(rrset);

    uint8_t* packet = c->packet;

    const unsigned rrct = rrset->gen.count;
    c->ancount += rrct;
    for(unsigned int i = 0; i < rrct; i++) {
        offset += repeat_name(c, offset, c->qname_comp, false);
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
        const unsigned int newlen = store_dname_nocomp(c, offset, rd->dname);
        gdnsd_put_una16(htons(newlen + 6), &packet[offset - 8]);
        if(rd->ad)
            add_addtl_rrset(c, rd->ad, offset);
        offset += newlen;
    }

    return offset;
}

F_NONNULL
static unsigned int encode_rrs_naptr(dnspacket_context_t* c, unsigned int offset, const ltree_rrset_naptr_t* rrset, const bool answer V_UNUSED) {
    dmn_assert(c); dmn_assert(c->packet); dmn_assert(offset); dmn_assert(rrset);

    uint8_t* packet = c->packet;

    const unsigned rrct = rrset->gen.count;
    c->ancount += rrct;
    for(unsigned int i = 0; i < rrct; i++) {
        offset += repeat_name(c, offset, c->qname_comp, false);
        gdnsd_put_una32(DNS_RRFIXED_NAPTR, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;
        const unsigned int rdata_offset = offset;
        const ltree_rdata_naptr_t* rd = &rrset->rdata[i];
        gdnsd_put_una16(rd->order, &packet[offset]);
        offset += 2;
        gdnsd_put_una16(rd->pref, &packet[offset]);
        offset += 2;

        // flags, services, regexp
        for(unsigned j = 0; j < 3; j++) {
            const uint8_t* this_txt = rd->texts[j];
            const unsigned int oal = *this_txt + 1; // oal is the encoded len value + 1 for the len byte itself
            memcpy(&packet[offset], this_txt, oal);
            offset += oal;
        }

        // NAPTR target can't be compressed
        const unsigned newlen = store_dname_nocomp(c, offset, rd->dname);
        gdnsd_put_una16(htons(offset - rdata_offset + newlen), &packet[rdata_offset - 2]);
        if(rd->ad)
            add_addtl_rrset(c, rd->ad, offset);
        offset += newlen;
    }

    return offset;
}

F_NONNULL
static unsigned int encode_rrs_txt(dnspacket_context_t* c, unsigned int offset, const ltree_rrset_txt_t* rrset, const bool answer V_UNUSED) {
    dmn_assert(c); dmn_assert(c->packet); dmn_assert(offset); dmn_assert(rrset);

    uint8_t* packet = c->packet;

    const bool is_spf = (c->qtype == DNS_TYPE_SPF);

    const unsigned rrct = rrset->gen.count;
    c->ancount += rrct;
    for(unsigned int i = 0; i < rrct; i++) {
        offset += repeat_name(c, offset, c->qname_comp, false);
        gdnsd_put_una32(is_spf ? DNS_RRFIXED_SPF : DNS_RRFIXED_TXT, &packet[offset]);
        offset += 4;
        gdnsd_put_una32(rrset->gen.ttl, &packet[offset]);
        offset += 6;

        const unsigned int rdata_offset = offset;
        unsigned int rdata_len = 0;
        const uint8_t* restrict bs;
        unsigned int j = 0;
        const ltree_rdata_txt_t rd = rrset->rdata[i];
        while((bs = rd[j++])) {
            const unsigned int oal = *bs + 1; // oal is the encoded len value + 1 for the len byte itself
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
static unsigned int encode_rr_cname(dnspacket_context_t* c, unsigned int offset, const ltree_rrset_cname_t* rd, const bool answer) {
    dmn_assert(c); dmn_assert(c->packet); dmn_assert(offset); dmn_assert(rd);

    uint8_t* packet = c->packet;

    unsigned int rdata_offset, ttl;
    const uint8_t* dname;

    if(rd->gen.is_static) {
        ttl = rd->gen.ttl;
        dname = rd->dname;
    }
    else {
        dmn_assert(c->dync_count < gconfig.max_cname_depth);
        dyncname_result_t ans_dync = {0, 0, &c->dync_store[(c->dync_count++ * 256)] };
        dname = ans_dync.dname;
        ans_dync.ttl = ntohl(rd->gen.ttl);

        rd->dyn.func(c->threadnum, rd->dyn.resource, rd->dyn.origin, &c->client_info, &ans_dync);
        if(ans_dync.edns_scope_mask > c->edns_client_scope_mask)
            c->edns_client_scope_mask = ans_dync.edns_scope_mask;
        ttl = htonl(ans_dync.ttl);

        // plugin is responsible for ensuring ans_dync.dname contents are valid,
        //   and not casting away const and overwriting the pointer
        dmn_assert(dname == ans_dync.dname);
        dmn_assert(gdnsd_dname_status(dname) == DNAME_VALID);
    }

    // start formulating response
    offset += repeat_name(c, offset, c->qname_comp, false);
    gdnsd_put_una32(DNS_RRFIXED_CNAME, &packet[offset]);
    offset += 4;

    gdnsd_put_una32(ttl, &packet[offset]);
    offset += 6;

    rdata_offset = offset;
    offset += store_dname(c, offset, dname, false);

    // set rdata_len
    gdnsd_put_una16(htons(offset - rdata_offset), &packet[rdata_offset - 2]);

    if(answer) {
        c->ancount++;
    }
    else {
        c->qname_comp = rdata_offset;
        c->cname_ancount++;
    }

    return offset;
}

F_NONNULL
static unsigned int encode_rr_soa(dnspacket_context_t* c, unsigned int offset, const ltree_rrset_soa_t* rdata, const bool answer) {
    dmn_assert(c); dmn_assert(c->packet); dmn_assert(offset); dmn_assert(rdata);

    uint8_t* packet = c->packet;

    offset += repeat_name(c, offset, c->auth_comp, false);
    gdnsd_put_una32(DNS_RRFIXED_SOA, &packet[offset]);
    offset += 4;
    gdnsd_put_una32(rdata->gen.ttl, &packet[offset]);
    offset += 6;

    // fill in the rdata
    const unsigned int rdata_offset = offset;
    offset += store_dname(c, offset, rdata->master, false);
    offset += store_dname(c, offset, rdata->email, false);
    memcpy(&packet[offset], &rdata->times, 20);
    offset += 20; // 5x 32-bits

    // set rdata_len
    gdnsd_put_una16(htons(offset - rdata_offset), &packet[rdata_offset - 2]);

    if(answer)
        c->ancount++;
    else
        c->nscount++;

    return offset;
}

static unsigned int encode_rrs_rfc3597(dnspacket_context_t* c, unsigned int offset, const ltree_rrset_rfc3597_t* rrset, const bool answer V_UNUSED) {
    dmn_assert(c); dmn_assert(c->packet); dmn_assert(offset); dmn_assert(rrset);

    uint8_t* packet = c->packet;

    const unsigned rrct = rrset->gen.count;
    c->ancount += rrct;
    for(unsigned int i = 0; i < rrct; i++) {
        offset += repeat_name(c, offset, c->qname_comp, false);
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

F_NONNULL
static unsigned int encode_rrs_any(dnspacket_context_t* c, unsigned int offset, const ltree_node_t* resdom) {
    dmn_assert(c); dmn_assert(resdom);

    // Address rrsets have to be processed first outside of the main loop,
    //   so that c->answer_addr_rrset gets set before any other RR-types
    //   try to add duplicate addr records to the addtl section
    const ltree_rrset_t* rrset = resdom->rrsets;
    while(rrset) {
        if(rrset->gen.type == DNS_TYPE_A)
            offset = encode_rrs_anyaddr(c, offset, (const void*)rrset, c->qname_comp, false);
        rrset = rrset->gen.next;
    }

    rrset = resdom->rrsets;
    while(rrset) {
        switch(rrset->gen.type) {
            case DNS_TYPE_A:
                // handled above
                break;
            case DNS_TYPE_SOA:
                offset = encode_rr_soa(c, offset, (const void*)rrset, true);
                break;
            case DNS_TYPE_NS:
                offset = encode_rrs_ns(c, offset, (const void*)rrset, true);
                break;
            case DNS_TYPE_PTR:
                offset = encode_rrs_ptr(c, offset, (const void*)rrset, true);
                break;
            case DNS_TYPE_MX:
                offset = encode_rrs_mx(c, offset, (const void*)rrset, true);
                break;
            case DNS_TYPE_SRV:
                offset = encode_rrs_srv(c, offset, (const void*)rrset, true);
                break;
            case DNS_TYPE_NAPTR:
                offset = encode_rrs_naptr(c, offset, (const void*)rrset, true);
                break;
            case DNS_TYPE_TXT:
                offset = encode_rrs_txt(c, offset, (const void*)rrset, true);
                break;
            case DNS_TYPE_SPF:;
                c->qtype = DNS_TYPE_SPF;
                offset = encode_rrs_txt(c, offset, (const void*)rrset, true);
                c->qtype = DNS_TYPE_ANY;
                break;
            default:
                offset = encode_rrs_rfc3597(c, offset, (const void*)rrset, true);
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
    while(rrsets->gen.type != _dtyp)\
        rrsets = rrsets->gen.next;\
    return &rrsets-> _typ;\
}
MK_RRSET_GET(soa, soa, DNS_TYPE_SOA)
MK_RRSET_GET(ns, ns, DNS_TYPE_NS)

// typecast for the encode funcs in the funcptr table
#define EC (unsigned int(*)(dnspacket_context_t*, unsigned int, const void*, const bool))

static unsigned int (*encode_funcptrs[256])(dnspacket_context_t*, unsigned int, const void*, const bool) = {
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
    EC encode_rrs_txt,     // 099 - DNS_TYPE_SPF
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

F_NONNULL
static unsigned int construct_normal_response(dnspacket_context_t* c, unsigned int offset, const ltree_node_t* resdom, const ltree_node_t* authdom) {
    dmn_assert(c); dmn_assert(resdom); dmn_assert(authdom);

    if(c->qtype == DNS_TYPE_ANY) {
        offset = encode_rrs_any(c, offset, resdom);
    }
    else if(resdom->rrsets) {
        const ltree_rrset_t* node_rrset = resdom->rrsets;
        unsigned etype = c->qtype;
        // rrset_addr is stored as type DNS_TYPE_A for both A and AAAA
        if(etype == DNS_TYPE_AAAA) etype = DNS_TYPE_A;
        while(node_rrset) {
            if(node_rrset->gen.type == etype) {
                if(unlikely(etype & 0xFF00))
                    offset = encode_rrs_rfc3597(c, offset, (const void*)node_rrset, true);
                else
                    offset = encode_funcptrs[c->qtype](c, offset, (const void*)node_rrset, true);
                break;
            }
            node_rrset = node_rrset->gen.next;
        }
    }

    if(!c->ancount)
        offset = encode_rr_soa(c, offset, ltree_node_get_rrset_soa(authdom), false);
    else if(gconfig.include_optional_ns && c->qtype != DNS_TYPE_NS
        && (c->qtype != DNS_TYPE_ANY || resdom != authdom))
            offset = encode_rrs_ns(c, offset, ltree_node_get_rrset_ns(authdom), false);

    return offset;
}

// Find the start of the (uncompressed) auth zone name at auth_depth bytes into the name at qname_offset,
//  chasing compression pointers as necc.
// XXX - really, the necessity of this is sort of the last straw on the current scheme involving
//  the interactions of c->qname_comp, c->auth_comp, lqname, store_dname(), search_ltree(), and CNAME
//  processing.  It's too complex to understand easily and needs refactoring.
F_NONNULL
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
            if(!memcmp(entry->label, child_label, *child_label + 1)) {
                current = entry;
                goto top_loop;
            }
            entry = entry->next;
        }
    } while(0);

    //  If in auth space with no match, and we still have a child_table, check for wildcard
    if(!rv_node && current->child_table) {
        dmn_assert(rval == DNAME_AUTH);
        ltree_node_t* entry = current->child_table[label_djb_hash((const uint8_t*)"\001*", current->child_hash_mask)];
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

F_NONNULL
static unsigned int answer_from_db(dnspacket_context_t* c, const uint8_t* qname, unsigned int offset) {
    dmn_assert(c); dmn_assert(qname); dmn_assert(offset);

    const unsigned first_offset = offset;
    bool via_cname = false;
    unsigned cname_depth = 0;
    const ltree_node_t* resdom = NULL;
    const ltree_node_t* resauth = NULL;
    wire_dns_header_t* res_hdr = (wire_dns_header_t*)c->packet;

    ltree_dname_status_t status = DNAME_NOAUTH;
    unsigned auth_depth;

    gdnsd_prcu_rdr_lock();

    zone_t* query_zone = ztree_find_zone_for(qname, &auth_depth);

    if(query_zone) { // matches auth space somewhere
        // In the initial search, it's known that "qname" is in fact the real query name and therefore
        //  uncompressed, which is what makes the simplistic c->auth_comp calculation possible.
        resauth = query_zone->root;
        status = search_zone_for_dname(qname, query_zone, &resdom, &auth_depth);
        c->auth_comp = c->qname_comp + auth_depth;
        dmn_assert(status == DNAME_AUTH || status == DNAME_DELEG);

        // CNAME handling, which fills in 1+ CNAME RRs and then alters status/resdom/via_cname
        //  for the normal response handling code below.  The explicit check of the first
        //  rrsets entry works because if CNAME exists at all, by definition it is the only
        //  type of rrset at this node.
        while(resdom && resdom->rrsets
            && resdom->rrsets->gen.type == DNS_TYPE_CNAME && c->qtype != DNS_TYPE_CNAME) {
            dmn_assert(status == DNAME_AUTH);

            res_hdr->flags1 |= 4; // AA bit
            via_cname = true;

            if(++cname_depth > gconfig.max_cname_depth) {
                log_err("Query for '%s' leads to a CNAME chain longer than %u (max_cname_depth)! This is a DYNC plugin configuration problem, and gdnsd will respond with NXDOMAIN protect against infinite client<->server CNAME-chasing loops!", logf_dname(qname), gconfig.max_cname_depth);
                resdom = NULL; // clear resdom to generate NXDOMAIN-style response
                // wipe any data already added to the packet
                offset = first_offset;
                c->ancount = 0;
                c->cname_ancount = 0;
                break;
            }

            const ltree_rrset_cname_t* cname = &resdom->rrsets->cname;
            offset = encode_rr_cname(c, offset, cname, false);

            const uint8_t* dname = cname->gen.is_static ? cname->dname : &c->dync_store[(c->dync_count - 1) * 256];
            if(dname_isinzone(query_zone->dname, dname)) {
                auth_depth = *dname - *query_zone->dname;
                status = search_zone_for_dname(dname, query_zone, &resdom, &auth_depth);
                c->auth_comp = chase_auth_ptr(c->packet, c->qname_comp, auth_depth);
            }
            else {
                status = DNAME_NOAUTH;
                break;
            }
        } // end CNAME block
    } // end if(query_zone) block

    if(status == DNAME_AUTH) {
        dmn_assert(resauth);
        res_hdr->flags1 |= 4; // AA bit
        if(likely(resdom)) {
            offset = construct_normal_response(c, offset, resdom, resauth);
        }
        else {
            const ltree_rrset_soa_t* soa = ltree_node_get_rrset_soa(resauth);
            dmn_assert(soa);
            res_hdr->flags2 = DNS_RCODE_NXDOMAIN;
            offset = encode_rr_soa(c, offset, soa, false);
            stats_own_inc(&c->stats->nxdomain);
        }
    }
    else if(status == DNAME_DELEG) {
        dmn_assert(resdom);
        const ltree_rrset_ns_t* ns = ltree_node_get_rrset_ns(resdom);
        dmn_assert(ns);
        offset = encode_rrs_ns(c, offset, ns, false);
    }
    else {
        dmn_assert(status == DNAME_NOAUTH);
        if(!via_cname) {
            res_hdr->flags2 = DNS_RCODE_REFUSED;
            stats_own_inc(&c->stats->refused);
        }
    }

    gdnsd_prcu_rdr_unlock();

    return offset;
}

F_NONNULL
static unsigned int answer_from_db_outer(dnspacket_context_t* c, uint8_t* qname, unsigned int offset) {
    dmn_assert(c); dmn_assert(qname); dmn_assert(offset);

    const unsigned full_trunc_offset = offset;

    wire_dns_header_t* res_hdr = (wire_dns_header_t*)c->packet;
    offset = answer_from_db(c, qname, offset);

    // Check for TC-bit (overflow w/ just ans, auth, and glue)
    if(unlikely(offset + (c->addtl_has_glue ? c->addtl_offset : 0) > c->this_max_response)) {
        c->ancount = 0;
        c->nscount = 0;
        c->arcount = 0;
        res_hdr->flags1 |= 0x2; // TC bit
        if(c->use_edns) {
            stats_own_inc(&c->stats->udp.edns_tc);
        }
        else {
            stats_own_inc(&c->stats->udp.tc);
        }
        return full_trunc_offset;
    }

    // Trim back the additional section by whole rrsets as necc to fit
    while(unlikely(c->addtl_offset > c->this_max_response - offset)) {
        const addtl_rrset_t* arrset = &c->addtl_rrsets[--c->addtl_count];
        c->addtl_offset = arrset->prev_offset;
        c->arcount = arrset->prev_arcount;
    }

    // Copy additional section (if any)
    memcpy(&c->packet[offset], c->addtl_store, c->addtl_offset);
    offset += c->addtl_offset;

    return offset;
}

unsigned int process_dns_query(dnspacket_context_t* c, const anysin_t* asin, uint8_t* packet, const unsigned int packet_len) {
    dmn_assert(c && asin && packet);

    reset_context(c);
    c->packet = packet;

/*
    log_debug("Processing %sv%u DNS query of length %u from %s",
        (c->is_udp ? "UDP" : "TCP"),
        (asin->sa.sa_family == AF_INET6) ? 6 : 4,
        packet_len,
        logf_anysin(asin));
*/

    if(asin->sa.sa_family == AF_INET6)
        stats_own_inc(&c->stats->v6);

    uint8_t lqname[256];
    unsigned question_len = 0;

    const rcode_rv_t status = decode_query(c, lqname, &question_len, packet_len, asin);

    if(status == DECODE_IGNORE) {
        stats_own_inc(&c->stats->dropped);
        return 0;
    }

    unsigned int res_offset = sizeof(wire_dns_header_t);

    wire_dns_header_t* hdr = (wire_dns_header_t*)packet;
    hdr->flags1 &= 0x79;
    hdr->flags1 |= 0x80;
    gdnsd_put_una16(0, &hdr->ancount);
    gdnsd_put_una16(0, &hdr->nscount);
    gdnsd_put_una16(0, &hdr->arcount);

    if(status == DECODE_NOTIMP) {
        gdnsd_put_una16(0, &hdr->qdcount);
        hdr->flags2 = DNS_RCODE_NOTIMP;
        stats_own_inc(&c->stats->notimp);
        return res_offset;
    }

    res_offset += question_len;

    if(likely(status == DECODE_OK)) {
        hdr->flags2 = DNS_RCODE_NOERROR;
        if(*lqname != 1) {
            c->comptarget_count = 1;
            c->comptargets[0].original = lqname;
            c->comptargets[0].comp_ptr = lqname + 255;
            c->comptargets[0].stored_at = sizeof(wire_dns_header_t);
        }
        c->qname_comp = 0x0C;

        if(likely(!c->chaos)) {
            memcpy(&c->client_info.dns_source, asin, sizeof(anysin_t));
            res_offset = answer_from_db_outer(c, lqname, res_offset);
        }
        else {
            c->ancount = 1;
            memcpy(&packet[res_offset], gconfig.chaos, gconfig.chaos_len);
            res_offset += gconfig.chaos_len;
        }

        if(hdr->flags2 == DNS_RCODE_NOERROR) stats_own_inc(&c->stats->noerror);
    }
    else {
        if(status == DECODE_FORMERR) {
            hdr->flags2 = DNS_RCODE_FORMERR;
            stats_own_inc(&c->stats->formerr);
        }
        else {
            dmn_assert(status == DECODE_BADVERS);
            hdr->flags2 = DNS_RCODE_NOERROR;
            stats_own_inc(&c->stats->badvers);
        }
    }

    if(c->use_edns) {
        packet[res_offset++] = '\0'; // domainname part of OPT
        wire_dns_rr_opt_t* opt = (wire_dns_rr_opt_t*)&packet[res_offset];
        res_offset += sizeof_optrr;

        gdnsd_put_una16(htons(DNS_TYPE_OPT), &opt->type);
        gdnsd_put_una16(htons(DNS_EDNS0_SIZE), &opt->maxsize);
        gdnsd_put_una32((status == DECODE_BADVERS) ? htonl(0x01000000) : 0, &opt->extflags);
        gdnsd_put_una16(0, &opt->rdlen);

        if(c->use_edns_client_subnet) {
            dmn_assert(c->clientsub_opt_code);
            gdnsd_put_una16(htons(c->clientsub_opt_code), &packet[res_offset]);
            res_offset += 2;
            const unsigned src_mask = c->client_info.edns_client_mask;
            const unsigned addr_bytes = (src_mask >> 3) + ((src_mask & 7) ? 1 : 0);
            gdnsd_put_una16(htons(8 + addr_bytes), &opt->rdlen);
            gdnsd_put_una16(htons(4 + addr_bytes), &packet[res_offset]);
            res_offset += 2;
            if(c->client_info.edns_client.sa.sa_family == AF_INET) {
                gdnsd_put_una16(htons(1), &packet[res_offset]); // family IPv4
                res_offset += 2;
                packet[res_offset++] = src_mask;
                packet[res_offset++] = c->edns_client_scope_mask;
                memcpy(&packet[res_offset], &c->client_info.edns_client.sin.sin_addr.s_addr, addr_bytes);
                res_offset += addr_bytes;
            }
            else {
                dmn_assert(c->client_info.edns_client.sa.sa_family == AF_INET6);
                gdnsd_put_una16(htons(2), &packet[res_offset]); // family IPv6
                res_offset += 2;
                packet[res_offset++] = src_mask;
                packet[res_offset++] = c->edns_client_scope_mask;
                memcpy(&packet[res_offset], c->client_info.edns_client.sin6.sin6_addr.s6_addr, addr_bytes);
                res_offset += addr_bytes;
            }
        }

        c->arcount++;
        if(likely(c->is_udp)) {
            // We only do one kind of truncation: complete truncation.
            //  therefore if we're returning a >512 packet, it wasn't truncated
            if(res_offset > 512) stats_own_inc(&c->stats->udp.edns_big);
        }
    }

    gdnsd_put_una16(htons(c->cname_ancount + c->ancount), &hdr->ancount);
    gdnsd_put_una16(htons(c->nscount), &hdr->nscount);
    gdnsd_put_una16(htons(c->arcount), &hdr->arcount);

    return res_offset;
}
