/* Copyright © 2020 Brandon L Black <blblack@gmail.com>
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
#include "comp.h"

#include "dnswire.h"

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

// The fixed offset of qname compression target
#define QNAME_COMP sizeof(struct wire_dns_hdr)

// Max number of *unique* compression targets we'll store info about.  Note
// there are separate targets per super-domain, e.g. storing all targets for
// "www.example.com" consumes 3 entries.  256 is a ton of targets; it's hard to
// imagine realistic cases where we'd miss a compression opportunity for lack
// of more target space here.
#define COMPTARGETS_MAX 256U

// Storage for general-purpose compression target info
struct comp_target {
    const uint8_t* orig; // Target in uncompressed wire form
    unsigned len; // length of the target in total bytes (all labels + label len bytes, including terminal \0)
    unsigned offset; // where this named was stored in the packet (this & 0xC000 is our wire target if match)
};

// struct comp_state tracks compressor state for an entire packet, through the
// storage of multiple names that might need compression, and which might be
// compression targets themselves
struct comp_state {
    unsigned count;
    struct comp_target targets[COMPTARGETS_MAX];
};

// Initialize compression context for working on one response packet.
// "qname" is the wire-format with no compression, as it would appear in the
// query section of the packet.  qname's storage must endure so long as the
// struct comp_state endures, as struct comp_state will hold pointers into it.
F_NONNULL F_RETNN
static struct comp_state* comp_new(const uint8_t* qname, unsigned qname_len)
{
    struct comp_state* cs = xcalloc(sizeof(*cs));
    unsigned offset = QNAME_COMP;
    // root is "." => "\0" => len==1 and is not worth compressing
    // next-shortest is "a." => "\1a\0" => len==3, and is worth compressing
    while (qname_len > 2) {
        gdnsd_assume(cs->count < COMPTARGETS_MAX);
        cs->targets[cs->count].orig = qname;
        cs->targets[cs->count].len = qname_len;
        cs->targets[cs->count].offset = offset;
        cs->count++;
        const unsigned jump = *qname + 1U;
        qname += jump;
        qname_len -= jump;
        offset += jump;
    }
    return cs;
}

F_NONNULL
static void comp_destroy(struct comp_state* cs)
{
    free(cs);
}

// "cs" - context from comp_new()
// "name" - Uncompressed wire-format name, to be stored into a packet (with attempted compression)
// "store_at" - Pointer into an output packet where we'd like "name" to be stored (compressed if possible, copied directly otherwise)
// "name_len" - Total bytes of storage for uncompressed "name"
// "offset" - The offset of store_at within a hypothetical real DNS packet, used to construct future compression pointers, iff:
// "make_targets" - If true, "name" will also be tracked as a compression target for future invocations to compress against, if it's in the size range to be applicable
F_NONNULL
static unsigned comp_store_name(struct comp_state* cs, const uint8_t* name, uint8_t* store_at, const unsigned name_len, unsigned offset, bool make_targets)
{
    const uint8_t* cur_name = name;
    unsigned cur_name_len = name_len;

    if (offset > 16383U)
        make_targets = false;

    // Search for a match, take the first match found since they're pre-sorted by len
    for (unsigned i = 0; i < cs->count; i++) {
        // So long as the target (longest remaining in sorted list) is shorter
        // than the input, we must iterate storing new names into the list
        while (cs->targets[i].len < cur_name_len) {
            if (make_targets && cs->count < COMPTARGETS_MAX) {
                gdnsd_assert(cur_name_len > 2U); // implied by rest of the logic...
                unsigned to_move = cs->count - i;
                memmove(cs->targets + i + 1U, cs->targets + i, to_move * sizeof(struct comp_target));
                cs->targets[i].orig = cur_name;
                cs->targets[i].len = cur_name_len;
                cs->targets[i].offset = offset;
                i++;
                cs->count++;
            }
            const unsigned jump = *cur_name + 1U;
            cur_name_len -= jump;
            cur_name += jump;
            offset += jump;
            if (offset > 16383U)
                make_targets = false;
        }

        if (cs->targets[i].len == cur_name_len && !memcmp(cur_name, cs->targets[i].orig, cur_name_len)) {
            // exact match!
            unsigned match_depth = name_len - cur_name_len;
            memcpy(store_at, name, match_depth);
            gdnsd_assert(cs->targets[i].offset < 16384U);
            gdnsd_put_una16(htons(0xC000u | cs->targets[i].offset), &store_at[match_depth]);
            return match_depth + 2U;
        }

        // otherwise cs->targets[i].len is > cur_name_len, or == cur_name_len but no
        // match yet, so we iterate further in the sorted list to find a case
        // that triggers one of the above
    }

    // Target list exhausted without any match.
    // For the make_targets case, we may still have one or more new entries to
    // add to the cs.targets set, all at the end (<= len of shortest existing)
    while (make_targets && cur_name_len > 2U && cs->count < COMPTARGETS_MAX) {
        cs->targets[cs->count].orig = cur_name;
        cs->targets[cs->count].len = cur_name_len;
        cs->targets[cs->count].offset = offset;
        cs->count++;
        const unsigned jump = *cur_name + 1U;
        cur_name_len -= jump;
        cur_name += jump;
        offset += jump;
        if (offset > 16383U)
            make_targets = false;
    }

    // store name in full
    memcpy(store_at, name, name_len);
    return name_len;
}

F_NONNULL
static void raw_add_fixup(struct ltree_rrset_raw* rrset, const unsigned offset)
{
    rrset->comp_offsets = xrealloc_n(rrset->comp_offsets, rrset->num_comp_offsets + 1U, sizeof(*rrset->comp_offsets));
    rrset->comp_offsets[rrset->num_comp_offsets++] = offset;
}

void comp_do_mx_cname_ptr(struct ltree_rrset_raw* rrset, const uint8_t* node_dname)
{
    gdnsd_assert(rrset->gen.type == DNS_TYPE_CNAME
                 || rrset->gen.type == DNS_TYPE_MX || rrset->gen.type == DNS_TYPE_PTR);
    gdnsd_assert(dname_get_status(node_dname) == DNAME_VALID);

    unsigned node_name_len = node_dname[0];
    const uint8_t* node_name = &node_dname[1];

    // The key difference between CNAME/PTR and MX, for this function's
    // purpose, is the two extra bytes of rdata for MX's priority field:
    const unsigned rdata_extra = (rrset->gen.type == DNS_TYPE_MX) ? 2U : 0U;

    // For wildcards, we act as if the QNAME were the enclosing name (ignore
    // the leading "*" label) for RHS compression purposes, and then later
    // fixup offsets to account for whatever matched at runtime.
    const bool is_wild = (node_name[0] == '\1' && node_name[1] == '*');
    if (is_wild) {
        node_name += 2U;
        gdnsd_assume(node_name_len > 2U);
        node_name_len -= 2U;
    }

    // pkt_voffset is the additional virtual offset to be applied to translate
    // the offsets of the comp_buffer to output packet offsets, shifting them
    // out by enough room for the packet header (12 bytes), the query name, and
    // the query class and type.
    const unsigned pkt_voffset = 12U + node_name_len + 2U + 2U;

    struct comp_state* cs = comp_new(node_name, node_name_len);

    uint8_t* input = rrset->data;
    uint8_t* comp_buffer = xmalloc(rrset->data_len);
    unsigned cbuf_offset = 0;
    unsigned input_offset = 0;
    const unsigned first_part = (*node_name ? 12U : 11U) + rdata_extra;
    for (unsigned i = 0; i < rrset->gen.count; i++) {
        memcpy(&comp_buffer[cbuf_offset], &input[input_offset], first_part); // everything but the RHS dname
        cbuf_offset += first_part;
        input_offset += first_part;
        const unsigned name_len = len_from_name(&input[input_offset]);
        const unsigned stored_len = comp_store_name(cs, &input[input_offset], &comp_buffer[cbuf_offset], name_len, pkt_voffset + cbuf_offset, (i != rrset->gen.count - 1U));
        gdnsd_assume(stored_len <= name_len);
        const unsigned savings = name_len - stored_len;
        if (savings) {
            if (is_wild)
                raw_add_fixup(rrset, pkt_voffset + cbuf_offset + stored_len - 2U);
            const unsigned rdlen_offset = cbuf_offset - 2U - rdata_extra;
            unsigned rdlen = ntohs(gdnsd_get_una16(&comp_buffer[rdlen_offset]));
            gdnsd_assume(rdlen == name_len + rdata_extra);
            rdlen -= savings;
            gdnsd_put_una16(htons(rdlen), &comp_buffer[rdlen_offset]);
        }
        cbuf_offset += stored_len;
        input_offset += name_len;
    }

    comp_destroy(cs);

    if (cbuf_offset != input_offset) {
        gdnsd_assert(cbuf_offset < input_offset); // savings, not expansion!
        // If RRSIG was present at end, copy it over as well.
        if (rrset->num_rrsig) {
            gdnsd_assert(rrset->rrsig_len);
            gdnsd_assert(rrset->rrsig_offset);
            gdnsd_assert(rrset->rrsig_offset + rrset->rrsig_len == rrset->data_len);
            gdnsd_assert(input_offset == rrset->rrsig_offset);
            memcpy(&comp_buffer[cbuf_offset], &input[input_offset], rrset->rrsig_len);
            cbuf_offset += rrset->rrsig_len;
            gdnsd_assert(cbuf_offset < rrset->data_len);
        } else {
            gdnsd_assert(input_offset == rrset->data_len);
        }
        free(rrset->data);
        comp_buffer = xrealloc(comp_buffer, cbuf_offset);
        rrset->data = comp_buffer;
        rrset->data_len = cbuf_offset;
    } else {
        // No point replacing the existing if nothing happened
        free(comp_buffer);
    }
}

static void fixup_all_lhs(struct ltree_rrset_raw* rrset, uint8_t* rrset_data, const unsigned num_rrs, const unsigned pkt_voffset)
{
    // Skip if it was an uncompressed root-of-dns case
    unsigned d_offs = 0;
    if (rrset_data[d_offs] == 0x00)
        return;

    rrset->comp_offsets = xrealloc_n(rrset->comp_offsets, rrset->num_comp_offsets + num_rrs, sizeof(*rrset->comp_offsets));
    for (unsigned i = 0; i < num_rrs; i++) {
        gdnsd_assert(rrset_data[d_offs] == 0xC0 && rrset_data[d_offs + 1U] == 0x0C);
        rrset->comp_offsets[rrset->num_comp_offsets++] = pkt_voffset + d_offs;
        const unsigned rdlen = ntohs(gdnsd_get_una16(&rrset_data[d_offs + 10U]));
        d_offs += (rdlen + 12U);
    }
}

void comp_do_soa(struct ltree_rrset_raw* rrset, const uint8_t* node_dname)
{
    gdnsd_assert(rrset->gen.type == DNS_TYPE_SOA);
    // SOA only exists at the zone root and always has a count of 1
    gdnsd_assert(rrset->gen.count == 1U);
    gdnsd_assert(dname_get_status(node_dname) == DNAME_VALID);

    const unsigned node_name_len = node_dname[0];
    const uint8_t* node_name = &node_dname[1];

    // pkt_voffset is the additional virtual offset to be applied to translate
    // the offsets of the comp_buffer to output packet offsets, shifting them
    // out by enough room for the packet header (12 bytes), the query name, and
    // the query class and type.
    const unsigned pkt_voffset = 12U + node_name_len + 2U + 2U;

    struct comp_state* cs = comp_new(node_name, node_name_len);

    uint8_t* input = rrset->data;
    uint8_t* comp_buffer = xmalloc(rrset->data_len);
    unsigned cbuf_offset = 0;
    unsigned input_offset = 0;

    // First fixup is the LHS 0xC00C itself, unless root case
    if (input[0]) {
        gdnsd_assert(input[0] == 0xC0 && input[1] == 0x0C);
        raw_add_fixup(rrset, pkt_voffset);
    }

    // Copy in the fixed portion
    const unsigned first_part = (*node_name ? 12U : 11U);
    memcpy(&comp_buffer[cbuf_offset], &input[input_offset], first_part); // everything but the RHS dname
    cbuf_offset += first_part;
    input_offset += first_part;

    // Copy and possibly-compress a pair of dnames for mname/rname
    unsigned total_savings = 0;
    for (unsigned i = 0; i < 2; i++) {
        const unsigned name_len = len_from_name(&input[input_offset]);
        const unsigned stored_len = comp_store_name(cs, &input[input_offset], &comp_buffer[cbuf_offset], name_len, pkt_voffset + cbuf_offset, !i);
        gdnsd_assume(stored_len <= name_len);
        const unsigned savings = name_len - stored_len;
        if (savings) {
            raw_add_fixup(rrset, pkt_voffset + cbuf_offset + stored_len - 2U);
            total_savings += savings;
        }
        cbuf_offset += stored_len;
        input_offset += name_len;
    }

    comp_destroy(cs);

    if (total_savings) {
        // Copy the final 20 bytes (5x 32-bit numeric values, the various SOA TTL-ish fields)
        memcpy(&comp_buffer[cbuf_offset], &input[input_offset], 20U);
        cbuf_offset += 20U;
        input_offset += 20U;
        // If RRSIG was present at end, copy it over as well.
        if (rrset->num_rrsig) {
            gdnsd_assert(rrset->rrsig_len);
            gdnsd_assert(rrset->rrsig_offset);
            gdnsd_assert(rrset->rrsig_offset + rrset->rrsig_len == rrset->data_len);
            gdnsd_assert(input_offset == rrset->rrsig_offset);
            memcpy(&comp_buffer[cbuf_offset], &input[input_offset], rrset->rrsig_len);
            cbuf_offset += rrset->rrsig_len;
            gdnsd_assert(cbuf_offset < rrset->data_len);
            gdnsd_assert(total_savings < rrset->rrsig_offset);
            rrset->rrsig_offset -= total_savings;
        } else {
            gdnsd_assert(input_offset == rrset->data_len);
        }
        const unsigned rdlen_offset = 10U;
        unsigned rdlen = ntohs(gdnsd_get_una16(&comp_buffer[rdlen_offset]));
        rdlen -= total_savings;
        gdnsd_put_una16(htons(rdlen), &comp_buffer[rdlen_offset]);
        free(rrset->data);
        comp_buffer = xrealloc(comp_buffer, cbuf_offset);
        rrset->data = comp_buffer;
        rrset->data_len = cbuf_offset;
    } else {
        // No point replacing the existing if nothing happened
        free(comp_buffer);
    }

    // Create LHS fixups for the SOA RRSIG, since it's used in auth-adjusted responses alongside the SOA
    if (rrset->num_rrsig)
        fixup_all_lhs(rrset, &rrset->data[rrset->rrsig_offset], rrset->num_rrsig, pkt_voffset + rrset->rrsig_offset);
}

// This one doesn't do any real compression, it just records comp_offset stuff
// for dnspacket to use in delegation output cases
void comp_do_deleg_ds_nsec(struct ltree_rrset_raw* rrset, const uint8_t* node_dname)
{
    gdnsd_assert(rrset->gen.type == DNS_TYPE_DS || rrset->gen.type == DNS_TYPE_NSEC);
    gdnsd_assert(rrset->num_rrsig);
    gdnsd_assert(!rrset->num_comp_offsets);
    gdnsd_assert(!rrset->comp_offsets);
    gdnsd_assert(dname_get_status(node_dname) == DNAME_VALID);

    fixup_all_lhs(rrset, rrset->data, rrset->gen.count + rrset->num_rrsig,
                  12U + node_dname[0] + 2U + 2U);
}

F_NONNULL
static enum ltree_dnstatus ltree_search_name_zone(const uint8_t* name, unsigned name_len, struct ltree_node_zroot* zroot, union ltree_node** node_out)
{
    gdnsd_assume(zroot->c.dname);

    const uint8_t* zone_name = zroot->c.dname;
    const unsigned zone_name_len = *zone_name++;

    // Easiest out: can't be in the zone if our length is shorter than the zone name length
    // (note the memcmp later could read invalid bytes if this check wasn't done first)
    if (name_len < zone_name_len)
        return DNAME_NOAUTH;

    // Convert both names to treepath form
    uint8_t name_treepath[255];
    uint8_t zone_treepath[255];
    treepath_from_name(name_treepath, name);
    treepath_from_name(zone_treepath, zone_name);

    // Check that the name is actually in the zone
    unsigned zone_check_offset = 0;
    unsigned llen;
    while ((llen = zone_treepath[zone_check_offset])) {
        llen++;
        if (memcmp(&zone_treepath[zone_check_offset], &name_treepath[zone_check_offset], llen))
            return DNAME_NOAUTH;
        zone_check_offset += llen;
    }

    enum ltree_dnstatus rval = DNAME_AUTH;
    union ltree_node* cur_node = (union ltree_node*)zroot;
    const uint8_t* cur_label = &name_treepath[zone_check_offset];
    unsigned cur_label_len = *cur_label;
    while (cur_node && cur_label_len) {
        union ltree_node* next = ltree_node_find_child(cur_node, cur_label);
        // Check for delegation cut and switch status
        if (next && next->c.zone_cut_deleg)
            rval = DNAME_DELEG;
        // Note we don't check for a wildcard match here, because this is NS
        // hostnames and we don't choose to support wildcard delegation
        cur_label += cur_label_len + 1U;
        cur_label_len = *cur_label;
        cur_node = next;
    }

    *node_out = cur_node;
    return rval;
}

F_NONNULL
static void ns_add_glue_data(struct ltree_rrset_raw* glue_fake, const struct ltree_rrset_raw* target, const unsigned glue_name_offset, const unsigned rr_len, const bool in_deleg)
{
    glue_fake->data = xrealloc(glue_fake->data, glue_fake->data_len + target->data_len);
    memcpy(&glue_fake->data[glue_fake->data_len], target->data, target->data_len);
    if (target->data[0]) { // Zero here would mean the target root-of-dns, and thus doesn't have or need compression
        for (unsigned i = 0; i < target->gen.count; i++) {
            const unsigned comp_ptr_offs = glue_fake->data_len + (i * rr_len);
            gdnsd_put_una16(htons(0xC000 | glue_name_offset), &glue_fake->data[comp_ptr_offs]);
            if (in_deleg)
                raw_add_fixup(glue_fake, comp_ptr_offs);
        }
    }
    glue_fake->data_len += target->data_len;
    glue_fake->gen.count += target->gen.count;
}

F_WUNUSED F_NONNULL
static bool ns_add_glue(struct ltree_rrset_raw* glue_fake, struct ltree_node_zroot* zroot, const uint8_t* node_dname, const uint8_t* name, unsigned name_len, unsigned glue_name_offset, const bool in_deleg)
{
    union ltree_node* ns_target = NULL;
    enum ltree_dnstatus target_status = ltree_search_name_zone(name, name_len, zroot, &ns_target);

    // Only attach glue from delegated spaces
    if (target_status != DNAME_DELEG)
        return false;

    struct ltree_rrset_raw* target_a = NULL;
    struct ltree_rrset_raw* target_aaaa = NULL;

    if (ns_target) {
        union ltree_rrset* target_rrset = ns_target->c.rrsets;
        while (target_rrset) {
            if (target_rrset->gen.type == DNS_TYPE_A)
                target_a = &target_rrset->raw;
            else if (target_rrset->gen.type == DNS_TYPE_AAAA)
                target_aaaa = &target_rrset->raw;
            target_rrset = target_rrset->gen.next;
        }
    }

    // Sanity checks!
    if (!target_a && !target_aaaa)
        log_zfatal("Missing A and/or AAAA records for target nameserver in '%s NS %s'",
                   logf_dname(node_dname), logf_name(name));
    if ((target_a && !target_a->gen.count)
            || (target_aaaa && !target_aaaa->gen.count))
        log_zfatal("Address records for '%s NS %s' must be static data, not dynamic",
                   logf_dname(node_dname), logf_name(name));
    if (glue_name_offset > 16383U)
        log_zfatal("Too many NS records for %s, exceeds glue compression limits", logf_dname(node_dname));

    gdnsd_assume(ns_target); // If this were false, we'd lack a+aaaa and fatal out above

    if (target_a) {
        realize_rdata(ns_target, target_a, zroot, true);
        ns_add_glue_data(glue_fake, target_a, glue_name_offset, 16U, in_deleg);
    }
    if (target_aaaa) {
        realize_rdata(ns_target, target_aaaa, zroot, true);
        ns_add_glue_data(glue_fake, target_aaaa, glue_name_offset, 28U, in_deleg);
    }

    return false;
}

bool comp_do_ns(struct ltree_rrset_raw* rrset, struct ltree_node_zroot* zroot, const union ltree_node* node, const bool in_deleg)
{
    gdnsd_assume(node->c.dname);
    gdnsd_assert(rrset->gen.type == DNS_TYPE_NS);
    gdnsd_assert(dname_get_status(node->c.dname) == DNAME_VALID);

    const uint8_t* node_dname = node->c.dname;
    const unsigned node_name_len = node_dname[0];
    const uint8_t* node_name = &node_dname[1];

    // pkt_voffset is the additional virtual offset to be applied to translate
    // the offsets of the comp_buffer to output packet offsets, shifting them
    // out by enough room for the packet header (12 bytes), the query name, and
    // the query class and type.
    const unsigned pkt_voffset = 12U + node_name_len + 2U + 2U;

    // Used to store and edit copies of glue address rrsets
    struct ltree_rrset_raw glue_fake;
    memset(&glue_fake, 0, sizeof(glue_fake));

    struct comp_state* cs = comp_new(node_name, node_name_len);

    uint8_t* input = rrset->data;
    uint8_t* comp_buffer = xmalloc(rrset->data_len);
    unsigned cbuf_offset = 0;
    unsigned input_offset = 0;
    const unsigned first_part = (*node_name ? 12U : 11U);
    for (unsigned i = 0; i < rrset->gen.count; i++) {
        if (in_deleg)
            raw_add_fixup(rrset, pkt_voffset + cbuf_offset);
        memcpy(&comp_buffer[cbuf_offset], &input[input_offset], first_part); // everything but the RHS dname
        cbuf_offset += first_part;
        input_offset += first_part;
        const unsigned name_len = len_from_name(&input[input_offset]);
        unsigned glue_name_offset = pkt_voffset + cbuf_offset;
        const unsigned stored_len = comp_store_name(cs, &input[input_offset], &comp_buffer[cbuf_offset], name_len, glue_name_offset, (i != rrset->gen.count - 1U));
        gdnsd_assume(stored_len <= name_len);
        if (stored_len == 2U) {
            // avoid ptr-to-ptr; len 2 can only be a lone ptr
            glue_name_offset = ntohs(gdnsd_get_una16(&comp_buffer[cbuf_offset]));
            gdnsd_assume(glue_name_offset & 0xC000u);
            glue_name_offset &= 0x3FFF;
        }
        if (ns_add_glue(&glue_fake, zroot, node_dname, &input[input_offset], name_len, glue_name_offset, in_deleg)) {
            free(comp_buffer);
            return true;
        }
        const unsigned savings = name_len - stored_len;
        if (savings) {
            if (in_deleg)
                raw_add_fixup(rrset, pkt_voffset + cbuf_offset + stored_len - 2U);
            const unsigned rdlen_offset = cbuf_offset - 2U;
            unsigned rdlen = ntohs(gdnsd_get_una16(&comp_buffer[rdlen_offset]));
            rdlen -= savings;
            gdnsd_put_una16(htons(rdlen), &comp_buffer[rdlen_offset]);
        }
        cbuf_offset += stored_len;
        input_offset += name_len;
    }

    comp_destroy(cs);

    // If rrsig, copy it over now as well, before we get to glue and/or realloc
    if (rrset->num_rrsig) {
        gdnsd_assert(rrset->rrsig_len);
        gdnsd_assert(rrset->rrsig_offset);
        gdnsd_assert(rrset->rrsig_offset + rrset->rrsig_len == rrset->data_len);
        gdnsd_assert(input_offset == rrset->rrsig_offset);
        memcpy(&comp_buffer[cbuf_offset], &input[input_offset], rrset->rrsig_len);
        cbuf_offset += rrset->rrsig_len;
        input_offset += rrset->rrsig_len;
        gdnsd_assume(cbuf_offset <= rrset->data_len);
        // Adjust rrsig offset for compression savings:
        if (cbuf_offset != input_offset) {
            gdnsd_assume(cbuf_offset < input_offset); // savings, not expansion!
            const unsigned savings = input_offset - cbuf_offset;
            gdnsd_assume(savings < rrset->rrsig_offset);
            rrset->rrsig_offset -= savings;
        }
    } else {
        gdnsd_assert(input_offset == rrset->data_len);
    }

    if (glue_fake.gen.count) {
        // merge glue_fake data
        free(rrset->data);
        rrset->num_addtl = glue_fake.gen.count;
        const unsigned total_len = cbuf_offset + glue_fake.data_len;
        comp_buffer = xrealloc(comp_buffer, total_len);
        memcpy(&comp_buffer[cbuf_offset], glue_fake.data, glue_fake.data_len);
        rrset->data = comp_buffer;
        rrset->data_len = total_len;
        free(glue_fake.data);

        // merge and fixup glue_fake offsets
        if (glue_fake.num_comp_offsets) {
            gdnsd_assume(glue_fake.comp_offsets);
            for (unsigned i = 0; i < glue_fake.num_comp_offsets; i++)
                glue_fake.comp_offsets[i] += cbuf_offset + pkt_voffset;
            const unsigned total_comp_offsets = rrset->num_comp_offsets + glue_fake.num_comp_offsets;
            rrset->comp_offsets = xrealloc_n(rrset->comp_offsets, total_comp_offsets, sizeof(*rrset->comp_offsets));
            memcpy(&rrset->comp_offsets[rrset->num_comp_offsets], glue_fake.comp_offsets, glue_fake.num_comp_offsets * sizeof(*glue_fake.comp_offsets));
            rrset->num_comp_offsets = total_comp_offsets;
            free(glue_fake.comp_offsets);
        }

        if (node->c.zone_cut_deleg) {
            gdnsd_assert(!rrset->num_rrsig);
            gdnsd_assert(!rrset->rrsig_offset);
            gdnsd_assert(!rrset->rrsig_len);
            rrset->deleg_glue_offset = cbuf_offset;
            rrset->deleg_comp_offsets = glue_fake.num_comp_offsets;
        }
    } else if (cbuf_offset != input_offset) {
        gdnsd_assert(cbuf_offset < input_offset); // savings, not expansion!
        // no glue, but we do have compression savings
        free(rrset->data);
        comp_buffer = xrealloc(comp_buffer, cbuf_offset);
        rrset->data = comp_buffer;
        rrset->data_len = cbuf_offset;
    } else {
        // No point replacing the existing if nothing happened
        free(comp_buffer);
    }

    return false;
}
