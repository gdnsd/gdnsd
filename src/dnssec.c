/* Copyright © 2021 Brandon L Black <blblack@gmail.com>
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
#include "dnssec.h"

#include "ltree.h"
#include "conf.h"
#include "dnssec.h"
#include "dnssec_alg.h"

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <gdnsd/alloc.h>

#include <sodium.h>

// Used to decide if we ask the alg layer to use deterministic ECDSA or not
static unsigned alg_req_flags = 0;

// For now, this stores up to 16 keys directly per-zone.  Later (when we have
// real, persistent keys), to be efficient in the common use-case of multiple
// zones sharing ZSKs, we'll probably want to load them all up once in a
// tree-global keystore, and then reference the subset for each zone at the
// per-zone level.
struct dnssec {
    unsigned num_zsks;
    uint32_t ncache;
    uint32_t rrsig_expire;
    uint32_t rrsig_incept;
    uint8_t* zone_dname; // aliases zroot->c.dname storage
    struct dnssec_zsk* zsks;
};

void dnssec_init_global(void)
{
    gdnsd_assume(gcfg);
    if (gcfg->dnssec_deterministic_ecdsa)
        alg_req_flags = ALG_DETERMINISTIC;
}

static uint16_t make_keytag(const uint8_t* rdata)
{
    const unsigned rdlen = ntohs(gdnsd_get_una16(rdata));
    rdata += 2U;
    uint32_t ac = 0;
    for (unsigned i = 0; i < rdlen; i++)
        if (i & 1)
            ac += rdata[i];
        else
            ac += rdata[i] * 256U;
    ac += ac >> 16U;
    return (uint16_t)ac;
}

// This auto-generates a fresh, ephemeral, unique key for each zone, each time
// it's loaded.  This is an intentionally-bad design for keys at this stage of
// development so we can focus on the other bits before looping back to key
// management, and should also help dissaude anyone from trying to use any of
// our development code with a production zone.
bool dnssec_add_ephemeral_zsk(struct ltree_node_zroot* zroot, const unsigned algid)
{
    struct dnssec* sec = zroot->sec;
    if (!sec) {
        if (!gcfg->dnssec_enabled) {
            log_err("dnssec_enabled is false in server config, cannot add keys for zone %s", logf_dname(zroot->c.dname));
            return true;
        }
        sec = zroot->sec = xcalloc(sizeof(*sec));
        sec->zone_dname = zroot->c.dname;
        sec->zsks = sodium_malloc(gcfg->dnssec_max_active_zsks * sizeof(*sec->zsks));
        if (!sec->zsks) {
            log_err("sodium_malloc() for ZSKs failed: %s", logf_errno());
            return true;
        }
        sodium_memzero(sec->zsks, gcfg->dnssec_max_active_zsks * sizeof(*sec->zsks));
    } else {
        gdnsd_assume(sec->num_zsks);
        gdnsd_assume(sec->zsks);
        if (sec->num_zsks == gcfg->dnssec_max_active_zsks) {
            log_err("Too many ZSKs for zone %s (try config option dnssec_max_active_zsks)", logf_dname(zroot->c.dname));
            return true;
        }
        if (sodium_mprotect_readwrite(sec->zsks)) {
            log_err("sodium_mprotect_readwrite failed: %s", logf_errno());
            return true;
        }
    }

    struct dnssec_zsk* zsk = &sec->zsks[sec->num_zsks];

    uint8_t* dnskey_rdata = dnssec_alg_init_zsk(zsk, algid, alg_req_flags);
    if (!dnskey_rdata) {
        log_err("Unsupported DNSKEY algorithm %u", algid);
        return true;
    }
    zsk->tag = make_keytag(dnskey_rdata); // cached for signing

    if (sodium_mprotect_readonly(sec->zsks)) {
        free(dnskey_rdata);
        log_err("sodium_mprotect_readonly failed: %s", logf_errno());
        return true;
    }

    // Create a DNSKEY record from the key (will be signed like all others, later)
    if (ltree_add_rec(zroot, zroot->c.dname, dnskey_rdata, DNS_TYPE_DNSKEY, 4321U)) {
        free(dnskey_rdata);
        return true;
    }

    sec->num_zsks++;
    return false;
}

void dnssec_set_tstamp_ncache(struct dnssec* sec, const uint32_t tstamp, const uint32_t ncache)
{
    sec->ncache = ncache;
    // XXX - Generate the inception/expiry dates.  Obviously, this should be
    // done more-robustly (check for under/over flow conditions and use the
    // proper date math from the RFCs, etc).
    sec->rrsig_incept = ((tstamp / 86400U) * 86400U) - 86400U;
    sec->rrsig_expire = sec->rrsig_incept + (86400U * 7U * 4U);
}

void dnssec_destroy(struct dnssec* sec)
{
    if (sec->num_zsks) {
        gdnsd_assume(sec->zsks);
        for (unsigned i = 0; i < sec->num_zsks; i++) {
            struct dnssec_zsk* zsk = &sec->zsks[i];
            gdnsd_assume(zsk->sk);
            if (zsk->alg->wipe_sk)
                zsk->alg->wipe_sk(zsk);
        }
        sodium_free(sec->zsks);
        sec->zsks = NULL;
        sec->num_zsks = 0;
    } else {
        gdnsd_assert(!sec->zsks);
    }
    free(sec);
}

F_NONNULL
static unsigned label_count(const uint8_t* name)
{
    unsigned rv = 0;
    unsigned llen;
    while ((llen = *name++)) {
        name += llen;
        rv++;
    }
    return rv;
}

// This is where we stuff the Key Tag into the preimage during signing, per-ZSK
#define RRSIG_ALG_OFFSET 2U

// This is where we stuff the Key Tag into the preimage during signing, per-ZSK
#define RRSIG_TAG_OFFSET 16U

// Max len of the preimage for a rrsig rdata
#define RRSIG_PRE_MAX 273U

// Creates the RRSIG RDATA preimage used for signing.  This is a copy of the
// rdata itself with the Key Tag field set to zero and no signature at the end.
// "lcount" is the label count for the RRSIG's eventual owner
// "out" must have sufficient space!  The size of this preimage varies with the
//       length of the name of the zone, and the maximum size of this preimage
//       is RRSIG_PRE_MAX bytes with a maximal 255 byte zone name.
// Return value is the number of bytes written.
static unsigned dnssec_rrsigs_make_preimage(uint8_t* out, const struct dnssec* sec, unsigned lcount, unsigned rrtype, uint32_t ttl)
{
    gdnsd_assume(lcount < 128U);
    gdnsd_assume(rrtype < 65536U);
    unsigned offs = 0;
    gdnsd_put_una16(htons(rrtype), &out[offs]);
    offs += 2U;
    gdnsd_assert(offs == RRSIG_ALG_OFFSET);
    out[offs++] = 0xEE; // Algorithm to fill during signing
    out[offs++] = lcount;
    gdnsd_put_una32(htonl(ttl), &out[offs]);
    offs += 4U;
    gdnsd_put_una32(htonl(sec->rrsig_expire), &out[offs]);
    offs += 4U;
    gdnsd_put_una32(htonl(sec->rrsig_incept), &out[offs]);
    offs += 4U;
    gdnsd_assert(offs == RRSIG_TAG_OFFSET);
    gdnsd_put_una16(htons(0xDEAD), &out[offs]); // Tag is set during signing
    offs += 2U;
    const unsigned znlen = sec->zone_dname[0];
    memcpy(&out[offs], &sec->zone_dname[1], znlen);
    offs += znlen;
    gdnsd_assert(offs <= RRSIG_PRE_MAX);
    return offs;
}

// Gives the size to expect or allocate when calling dnssec_rrsig_make()
// "sec" is for the zone we're signing for
// "preimage_len" the length of the preimage returned by rrsigs_make_preimage earlier
// "rrsig_comp_offset" for this function's purpose, the special value 0
//      indicates that we're working with the root-of-dns node with a name
//      length of 1, and any other value count 2 bytes for a name pointer.
static unsigned dnssec_rrsigs_len(const struct dnssec* sec, const unsigned preimage_len, const unsigned rrsig_comp_offset)
{
    gdnsd_assume(sec->zsks && sec->num_zsks);
    gdnsd_assert(rrsig_comp_offset < 0x4000);
    const unsigned rrsig_left_len = rrsig_comp_offset ? 12U : 11U;
    unsigned rv = 0;
    for (unsigned i = 0; i < sec->num_zsks; i++)
        rv += (rrsig_left_len + preimage_len + sec->zsks[i].alg->sig_len);
    return rv;
}

// Create the actual RRSIGs:
// "out" needs room to write them all, which can be predicted with the function above
// "sign_buf" should have, in order: the preimage created earlier and then the whole uncompressed rrset being signed
// "sign_buf_len" total bytes to sign in sign_buf
// "sec" is from the zone we're signing for
// "preimage_len" the length of the preimage at the start of "sign_buf", returned by rrsigs_make_preimage earlier
// "rrsig_comp_offset" the rrsig's owner name will be created as a 2-byte
//     compression pointer (0xC000 | offset) to this location, unless the
//     special value zero is passed, in which case it will be written as the
//     single-byte root-of-dns name 0x00.
// retval is the bytes written (should be identical to prediction from dnssec_rrsigs_len!)
static unsigned dnssec_rrsigs_make(uint8_t* out, uint8_t* sign_buf, const struct dnssec* sec, unsigned sign_buf_len, unsigned preimage_len, unsigned rrsig_comp_offset, uint32_t ttl)
{
    gdnsd_assume(rrsig_comp_offset < 0x4000);
    uint8_t sig_left[10U];
    unsigned sl_offs = 0U;
    if (rrsig_comp_offset) {
        gdnsd_put_una16(htons(0xC000 | rrsig_comp_offset), &sig_left[sl_offs]);
        sl_offs += 2U;
    } else {
        sig_left[sl_offs++] = 0U;
    }
    gdnsd_put_una16(htons(DNS_TYPE_RRSIG), &sig_left[sl_offs]);
    sl_offs += 2U;
    gdnsd_put_una16(htons(DNS_CLASS_IN), &sig_left[sl_offs]);
    sl_offs += 2U;
    gdnsd_put_una32(htonl(ttl), &sig_left[sl_offs]);
    sl_offs += 4U;

    unsigned offs = 0U;
    for (unsigned i = 0; i < sec->num_zsks; i++) {
        struct dnssec_zsk* zsk = &sec->zsks[i];
        // Overwrite the alg + key tag fields in sign_buf just before creating each RRSIG:
        sign_buf[RRSIG_ALG_OFFSET] = zsk->alg->id;
        gdnsd_put_una16(htons(zsk->tag), &sign_buf[RRSIG_TAG_OFFSET]);
        // Copy the common left of the RRSIG into the RRSIG buffer
        memcpy(&out[offs], sig_left, sl_offs);
        offs += sl_offs;
        // Set the rdlen per-key:
        gdnsd_put_una16(htons(preimage_len + zsk->alg->sig_len), &out[offs]);
        offs += 2U;
        // Copy the rdata porion of the RRSIG into the RRSIG buffer, using the
        // copy that's in sign_buf because it has the updated key tag
        memcpy(&out[offs], sign_buf, preimage_len);
        offs += preimage_len;
        // Sign the data from sign_buf, placing the signature into the RRSIG
        // buffer as the last part of the rdata
        gdnsd_assume(zsk->alg->sign);
        offs += zsk->alg->sign(zsk, &out[offs], sign_buf, sign_buf_len);
    }

    return offs;
}

uint8_t* dnssec_sign_rrset(const union ltree_node* node, struct ltree_rrset_raw* raw, const struct dnssec* sec)
{
    gdnsd_assert(!raw->data_len);
    gdnsd_assert(raw->gen.count);
    gdnsd_assert(raw->scan_rdata);
    gdnsd_assert(!raw->num_rrsig);
    gdnsd_assert(!raw->rrsig_offset);
    gdnsd_assert(!raw->rrsig_len);

    uint8_t rrsig_pre[RRSIG_PRE_MAX];
    const unsigned rrsig_pre_len = dnssec_rrsigs_make_preimage(rrsig_pre, sec, label_count(&node->c.dname[1]), raw->gen.type, raw->ttl);

    // This stores the common left side of the real RRSet (all but
    // rdlen+rdata), with the left name uncompressed for signing
    uint8_t left[255U + 8U];
    unsigned left_len = 0;
    const unsigned dnlen = node->c.dname[0];
    memcpy(left, &node->c.dname[1], dnlen);
    left_len += dnlen;
    gdnsd_put_una16(htons(raw->gen.type), &left[left_len]);
    left_len += 2U;
    gdnsd_put_una16(htons(DNS_CLASS_IN), &left[left_len]);
    left_len += 2U;
    gdnsd_put_una32(htonl(raw->ttl), &left[left_len]);
    left_len += 4U;

    // This counts the total size of the real RRSet, with no compression at all
    unsigned total_size = raw->gen.count * (left_len + 2U);
    for (unsigned i = 0; i < raw->gen.count; i++)
        total_size += ntohs(gdnsd_get_una16(raw->scan_rdata[i]));

    // sign_buf will hold the whole data that needs crypto signing (rrsig rdata
    // + rrs).  It's large enough and unpredictable enough that we won't use
    // the stack for it, so it needs to be freed later once we're done
    const unsigned sbuf_size = rrsig_pre_len + total_size;
    uint8_t* sign_buf = xmalloc(sbuf_size);
    unsigned sbuf_len = 0;
    memcpy(&sign_buf[sbuf_len], rrsig_pre, rrsig_pre_len);
    sbuf_len += rrsig_pre_len;
    for (unsigned i = 0; i < raw->gen.count; i++) {
        memcpy(&sign_buf[sbuf_len], left, left_len);
        sbuf_len += left_len;
        uint8_t* rd = raw->scan_rdata[i];
        unsigned rd_copy = ntohs(gdnsd_get_una16(rd)) + 2U;
        memcpy(&sign_buf[sbuf_len], rd, rd_copy);
        sbuf_len += rd_copy;
    }
    gdnsd_assert(sbuf_len == sbuf_size);

    // Set up the final rrsig metadata and the data allocation and create the RRSIGs
    const unsigned rrsig_comp_offset = node->c.dname[1] ? 12U : 0;
    raw->num_rrsig = sec->num_zsks;
    raw->rrsig_len = dnssec_rrsigs_len(sec, rrsig_pre_len, rrsig_comp_offset);
    uint8_t* d = xmalloc(raw->rrsig_len);
    const unsigned written V_UNUSED = dnssec_rrsigs_make(d, sign_buf, sec, sbuf_len, rrsig_pre_len, rrsig_comp_offset, raw->ttl);
    gdnsd_assert(written == raw->rrsig_len);

    free(sign_buf);
    return d;
}

// This is intended to be a faithful implementation of the "absolute method"
// successor function from RFC 4471 Sec 3.1.2, which creates an exact increment
// by a single step in the total namespace of the zone, and thus does not imply
// the non-existence of any other names.  The only thing we've added is an
// "include_subs" argument which, if set, causes the first step to be skipped
// even if there was enough room for it, which causes the NSEC to deny all
// names which are subdomains of the node name, which is useful for insecure
// deleg NSECs as well as our NXDOMAIN scheme.
//
// "next_name" is written in wire form, and must in general have room for up to
// 255 bytes, but in practice you could also just gaurantee owner_name_len + 2,
// because the next function can't add more bytes than that (and sometimes even
// subtracts!)
// "owner_name" input is expected to be in wire format with the total len already handed to us.
// "zone_name_len" is the length of the wire format zone apex name that owner exists within.
// retval is number of bytes written to "next_name"
static unsigned dnssec_nsec_next(uint8_t* next_name, const uint8_t* owner_name, unsigned owner_name_len, const unsigned zone_name_len, const bool include_subs)
{
    gdnsd_assume(owner_name_len);
    gdnsd_assume(zone_name_len);
    gdnsd_assume(owner_name_len < 256U);
    gdnsd_assume(zone_name_len < 256U);
    gdnsd_assume(owner_name_len >= zone_name_len);

    // "Step 1", the easy-out (and by far most-common) case for a perfect
    // minimal with at least two bytes of total length available, prepending a
    // fresh label "\000.":
    if (!include_subs && owner_name_len < 254U) {
        next_name[0] = 1U;
        next_name[1] = 0U;
        memcpy(&next_name[2], owner_name, owner_name_len);
        return owner_name_len + 2U;
    }

    // We can't create a name that's not within our zone apex
    while (owner_name_len > zone_name_len) {
        // "Step 2": room to append one 0x00 byte to the leftmost label, which
        // is our next-best case for a non-apex minimal if a new label won't
        // fit, and is our best non-apex case for include_subs as well.
        const unsigned first_llen = owner_name[0];
        if (owner_name_len < 255U && first_llen < 63U) {
            unsigned n_offs = 0;
            next_name[n_offs++] = first_llen + 1U;
            memcpy(&next_name[n_offs], &owner_name[1], first_llen);
            n_offs += first_llen;
            next_name[n_offs++] = 0U;
            const unsigned tocopy = owner_name_len - first_llen - 1U;
            memcpy(&next_name[n_offs], &owner_name[1U + first_llen], tocopy);
            n_offs += tocopy;
            gdnsd_assert(n_offs == owner_name_len + 1U);
            return n_offs;
        }

        // "Step 3": No room for adding bytes to leftmost label, so we have to
        // increment the rightmost byte of the leftmost label that isn't
        // already maxed out at 0xFF (and our increment has to skip the
        // uppercase ASCII range), and then delete any trailing 0xFF.
        unsigned i = first_llen;
        while (i && owner_name[i] == 0xFF)
            i--;
        if (i) {
            const unsigned len_diff = first_llen - i;
            const unsigned new_first_llen = first_llen - len_diff;
            const unsigned new_name_len = owner_name_len - len_diff;
            unsigned n_offs = 0;
            next_name[n_offs++] = new_first_llen;
            memcpy(&next_name[n_offs], &owner_name[1], new_first_llen);
            n_offs += new_first_llen;
            const unsigned inc_offs = n_offs - 1U;
            gdnsd_assert(next_name[inc_offs] != 0xFF);
            if (next_name[inc_offs] == 'A' - 1U)
                next_name[inc_offs] =  'Z' + 1U;
            else
                next_name[inc_offs]++;
            memcpy(&next_name[n_offs], &owner_name[1 + first_llen], owner_name_len - first_llen - 1U);
            return new_name_len;
        }

        // "Step 4": If all previous steps were impossible we must remove the
        // whole leftmost label and loop back to just above step 2 (the while
        // condition will drop us out if we hit the apex).
        const unsigned adjust = first_llen + 1U;
        gdnsd_assume(owner_name_len > adjust);
        owner_name += adjust;
        owner_name_len -= adjust;
    }

    // If we fall out of the loop above, then we wrapped back to the zone apex
    gdnsd_assert(owner_name_len == zone_name_len);
    memcpy(next_name, owner_name, owner_name_len);
    return owner_name_len;
}

void dnssec_nxd_fixup(const struct dnssec* sec, uint8_t* buf, const unsigned offset, const unsigned fixup)
{
    gdnsd_assert(fixup);
    unsigned fix_offs = offset;
    const unsigned nsec_comp_offset = 12U + fixup;
    gdnsd_put_una16(htons(0xC000 | nsec_comp_offset), &buf[fix_offs]);
    fix_offs += 10U;
    const unsigned nsec_rdlen = ntohs(gdnsd_get_una16(&buf[fix_offs]));
    fix_offs += 2U + nsec_rdlen;

    const unsigned rrsig_comp_offset = offset;
    for (unsigned i = 0; i < sec->num_zsks; i++) {
        gdnsd_put_una16(htons(0xC000 | rrsig_comp_offset), &buf[fix_offs]);
        fix_offs += 10U;
        const unsigned rdlen = ntohs(gdnsd_get_una16(&buf[fix_offs]));
        fix_offs += 2U + rdlen;
    }
}

unsigned dnssec_synth_nxd(const struct dnssec* sec, const uint8_t* nxd_name, uint8_t* buf, const unsigned nxd_name_len)
{
    gdnsd_assume(nxd_name_len >= 3U); // can't be root-of-dns, and all other cases are 3+ bytes, e.g. "\1a\0"
    gdnsd_assume(nxd_name[0] != 0U); // can't be root-of-dns
    const unsigned nxd_name_lcount = label_count(nxd_name);

    // Just to be pedantic:
    static_assert((MAX_RESP_START + RRSIG_PRE_MAX) <= MAX_RESPONSE_BUF, "RRSIG max preimage fits in a response buffer");

    // Write the preimage to our packet response buffer, which is being reused as a signing buffer too
    const unsigned preimage_len = dnssec_rrsigs_make_preimage(buf, sec, nxd_name_lcount, DNS_TYPE_NSEC, sec->ncache);
    unsigned offset = preimage_len;

    // Write the NSEC RR just after it (with a full uncompressed left name),
    // completing the data that needs signing
    const unsigned nxd_name_offset = offset;
    memcpy(&buf[offset], nxd_name, nxd_name_len);
    offset += nxd_name_len;
    gdnsd_put_una16(htons(DNS_TYPE_NSEC), &buf[offset]);
    offset += 2U;
    gdnsd_put_una16(htons(DNS_CLASS_IN), &buf[offset]);
    offset += 2U;
    gdnsd_put_una32(htonl(sec->ncache), &buf[offset]);
    offset += 6U; // skip rdlen for now, we'll come back to it
    const unsigned rdata_offset = offset;
    offset += dnssec_nsec_next(&buf[offset], nxd_name, nxd_name_len, sec->zone_dname[0], true);
    memcpy(&buf[offset], "\x00\x06\x00\x00\x00\x00\x00\x03", 8U); // Fixed typemask "RRSIG NSEC"
    offset += 8U;
    gdnsd_put_una16(htons(offset - rdata_offset), &buf[rdata_offset - 2U]); // write rdlen
    const unsigned nsec_full_len = offset - nxd_name_offset;

    // Since we only allow up to 16x ZSKs, and the max length of our RRSIG RRs
    // is 349 bytes, and the length of the above NSEC RR maxes out at 275
    // bytes, we shouldn't ever have to runtime-check for overflows:
    gdnsd_assert(MAX_RESP_START + offset + dnssec_rrsigs_len(sec, preimage_len, 12U) <= MAX_RESPONSE_BUF);

    // This reads the preimage + NSEC we set up earlier and produces 1+ RRSIGs right after them in the buffer
    offset += dnssec_rrsigs_make(&buf[offset], buf, sec, preimage_len + nsec_full_len, preimage_len, 12U, sec->ncache);

    // Now we overwrite the final two bytes of the full NSEC owner name with
    // a compression pointer at the qname.  This gives us the real wire-level
    // output we're looking for (NSEC with compressed owner name followed by
    // RRSIGs), it's just not where it should be in the packet yet!
    const unsigned nsec_wire_start = nxd_name_offset + nxd_name_len - 2U;
    gdnsd_put_una16(htons(0xC00C), &buf[nsec_wire_start]);

    // Move the final wire response data down to where it belongs at the start of the buf
    gdnsd_assume(offset > nsec_wire_start);
    const unsigned wire_resp_size = offset - nsec_wire_start;
    memmove(buf, &buf[nsec_wire_start], wire_resp_size);

    // This somewhat naturally follows from earlier asserts, but is subtly important too!
    gdnsd_assert(MAX_RESP_START + wire_resp_size <= MAX_RESPONSE_DATA);

    return wire_resp_size;
}

// "wins" must have enough storage for the full 34 bytes (win#, octet count, 32
// bytes mask) for all possible windows up to and including the one for "type".
// In the general case this would be at most 256 * 34 = 8704 bytes, but the
// caller below optimizes for common cases.
// This function accurately keeps tabs on the octet counts while setting bits,
// and also fills in the window numbers.  Octet string trimming and unused
// window elimination is done later during typemap_encode()
F_NONNULL
static void typemap_add_type(uint8_t* wins, const unsigned rrtype)
{
    gdnsd_assume(rrtype <= 0xFFFF);
    const unsigned win_idx = rrtype >> 8U;
    const unsigned type_oct_idx = (rrtype & 0xFF) >> 3U;
    const unsigned type_oct_cnt = type_oct_idx + 1U;
    const uint8_t type_bit = 1U << (7U - (rrtype & 0x7));

    uint8_t* win = &wins[34U * win_idx];
    win[0] = win_idx;
    if (win[1] < type_oct_cnt)
        win[1] = type_oct_cnt;
    win[2U + type_oct_idx] |= type_bit;
}

F_NONNULL
static void typemap_encode(uint8_t* out, const uint8_t* wins, const unsigned wins_allocated)
{
    unsigned offs = 0;
    for (unsigned i = 0; i < wins_allocated; i++) {
        const uint8_t* win = &wins[i * 34U];
        if (win[1]) {
            out[offs++] = win[0];
            out[offs++] = win[1];
            memcpy(&out[offs], &win[2], win[1]);
            offs += win[1];
        }
    }
}

F_NONNULL
static unsigned typemap_encoded_len(const uint8_t* wins, const unsigned wins_allocated)
{
    unsigned rv = 0;
    for (unsigned i = 0; i < wins_allocated; i++) {
        const uint8_t* win = &wins[i * 34U];
        if (win[1])
            rv += win[1] + 2U;
    }

    return rv;
}

void dnssec_node_add_nsec(union ltree_node* node, const struct dnssec* sec)
{
    uint8_t* all_wins = NULL;
    uint8_t two_wins[68] = { 0 };
    uint8_t* wins = two_wins;

    typemap_add_type(wins, DNS_TYPE_NSEC);
    typemap_add_type(wins, DNS_TYPE_RRSIG);

    union ltree_rrset** store_at = &node->c.rrsets;
    while (*store_at) {
        const unsigned rrtype = (*store_at)->gen.type;
        gdnsd_assert(rrtype != DNS_TYPE_NSEC);
        if (rrtype == DNS_TYPE_DS) {
            gdnsd_assert(!all_wins); // because check_deleg earlier
            return; // we never use deleg-NSEC when DS is present
        }
        // This condition ensures we don't add NSEC bits for glue addresses at
        // the deleg node, which haven't been cut yet at this stage
        if (!node->c.zone_cut_deleg || rrtype == DNS_TYPE_NS) {
            if (rrtype >= 512U && !all_wins) {
                gdnsd_assume(wins == two_wins);
                all_wins = wins = xcalloc_n(34U, 256U);
                gdnsd_assume(sizeof(two_wins) == 68U);
                memcpy(all_wins, two_wins, sizeof(two_wins));
            }
            typemap_add_type(wins, rrtype);
        }
        store_at = &(*store_at)->gen.next;
    }

    uint8_t next_name[255];
    const unsigned next_name_len = dnssec_nsec_next(next_name,
                                   &node->c.dname[1], node->c.dname[0], sec->zone_dname[0], node->c.zone_cut_deleg);

    const unsigned wins_allocated = all_wins ? 256U : 2U;
    const unsigned tmlen = typemap_encoded_len(wins, wins_allocated);
    const unsigned rdlen = next_name_len + tmlen;

    uint8_t* rdata = xmalloc(2U + rdlen);
    gdnsd_put_una16(htons(rdlen), rdata);
    memcpy(&rdata[2], next_name, next_name_len);
    typemap_encode(&rdata[2U + next_name_len], wins, wins_allocated);

    if (all_wins)
        free(all_wins);

    struct ltree_rrset_raw* raw = xcalloc(sizeof(*raw));
    *store_at = (union ltree_rrset*)raw;
    raw->gen.type = DNS_TYPE_NSEC;
    raw->gen.count = 1U;
    raw->ttl = sec->ncache;
    raw->scan_rdata = xmalloc(sizeof(*raw->scan_rdata));
    raw->scan_rdata[0] = rdata;
}

unsigned dnssec_num_zsks(const struct dnssec* sec)
{
    return sec->num_zsks;
}
