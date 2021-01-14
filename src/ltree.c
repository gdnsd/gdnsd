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
#include "ltree.h"

#include "conf.h"
#include "dnspacket.h"
#include "zsrc_rfc1035.h"
#include "chal.h"
#include "main.h"
#include "comp.h"

#include <gdnsd/alloc.h>
#include <gdnsd/dname.h>
#include <gdnsd/log.h>
#include <gdnsd/misc.h>
#include <gdnsd/grcu.h>
#include "plugins/plugapi.h"

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

// root_tree is RCU-managed and accessed by reader threads.
GRCU_PUB_DEF(root_tree, NULL);

F_NONNULL
static void ltree_node_insert(const union ltree_node* node, union ltree_node* child, uintptr_t child_hash, uint32_t probe_dist, const uint32_t mask)
{
    do {
        const uint32_t slot = ((uint32_t)child_hash + probe_dist) & mask;
        struct ltree_hslot* s = &node->c.child_table[slot];
        if (!s->node) {
            s->node = child;
            s->hash = child_hash;
            break;
        }
        const uint32_t s_pdist = (slot - s->hash) & mask;
        if (s_pdist < probe_dist) {
            probe_dist = s_pdist;
            struct ltree_hslot tmp = *s;
            s->hash = child_hash;
            s->node = child;
            child_hash = tmp.hash;
            child = tmp.node;
        }
        probe_dist++;
    } while (1);
}

F_MALLOC F_RETNN F_NONNULL
static uint8_t* dname_from_name(const uint8_t* name, unsigned name_len)
{
    gdnsd_assume(name_len);
    gdnsd_assume(name_len < 256U);
    uint8_t* rv = xmalloc(name_len + 1U);
    rv[0] = name_len;
    memcpy(&rv[1], name, name_len);
    return rv;
}

F_NONNULLX(1, 2)
static union ltree_node* ltree_node_find_or_add_child(union ltree_node* node, const uint8_t* child_name, union ltree_node* ins, unsigned child_name_len)
{
    const uint32_t ccount = node->c.ccount;
    const uintptr_t kh = ltree_hash_label(child_name);
    uint32_t probe_dist = 0;
    uint32_t mask = 0;
    if (ccount) {
        mask = count2mask_u32_lf80(ccount);
        do {
            const uint32_t slot = ((uint32_t)kh + probe_dist) & mask;
            const struct ltree_hslot* s = &node->c.child_table[slot];
            if (!s->node || ((slot - s->hash) & mask) < probe_dist)
                break;
            gdnsd_assume(s->node->c.dname);
            if (s->hash == kh && likely(!label_cmp(&s->node->c.dname[1], child_name)))
                return s->node;
            probe_dist++;
        } while (1);
    }
    if (unlikely((ccount + (ccount >> 2U)) == LTREE_NODE_MAX_SLOTS)) {
        log_err("Failed to create node '%s': Too many nodes at this level", logf_name(child_name));
        return NULL;
    }
    const uint32_t next_mask = count2mask_u32_lf80(ccount + 1U);
    if (next_mask != mask) {
        struct ltree_hslot* old_table = node->c.child_table;
        node->c.child_table = xcalloc_n(next_mask + 1U, sizeof(*node->c.child_table));
        if (old_table) {
            for (uint32_t i = 0; i <= mask; i++)
                if (old_table[i].node)
                    ltree_node_insert(node, old_table[i].node, old_table[i].hash, 0, next_mask);
            free(old_table);
        }
        probe_dist = 0; // if grow, reset saved distance
        mask = next_mask; // new mask in play below
    }

    if (!ins) {
        ins = xcalloc(sizeof(*ins));
        ins->c.dname = dname_from_name(child_name, child_name_len);
    }
    ltree_node_insert(node, ins, kh, probe_dist, mask);
    node->c.ccount++;
    return ins;
}

F_WUNUSED F_NONNULL
static unsigned dname_to_lstack_relative(const uint8_t* dname, const uint8_t** lstack, uint8_t* lstack_len, const uint8_t* zone_dname)
{
    gdnsd_assert(dname_get_status(dname) == DNAME_VALID);
    gdnsd_assert(dname_isinzone(zone_dname, dname));
    const uint8_t* dname_rel_end = &dname[*dname - *zone_dname];
    unsigned total_len = *dname++;
    unsigned lcount = 0;
    unsigned llen; // current label len
    while ((llen = *dname) && dname < dname_rel_end) {
        gdnsd_assume(lcount < 127);
        lstack_len[lcount] = total_len;
        lstack[lcount++] = dname;
        llen++;
        dname += llen;
        gdnsd_assume(total_len >= llen);
        total_len -= llen;
    }
    return lcount;
}

// "dname" should be a true FQDN!
F_NONNULL
static union ltree_node* ltree_zone_find_or_add_dname(struct ltree_node_zroot* zroot, const uint8_t* dname)
{
    gdnsd_assume(zroot->c.dname);
    gdnsd_assert(dname_get_status(dname) == DNAME_VALID);
    gdnsd_assert(dname_isinzone(zroot->c.dname, dname));

    uint8_t lstack_len[127];
    const uint8_t* lstack[127];
    unsigned lcount = dname_to_lstack_relative(dname, lstack, lstack_len, zroot->c.dname);

    union ltree_node* current = (union ltree_node*)zroot;
    while (lcount-- && current)
        current = ltree_node_find_or_add_child(current, lstack[lcount], NULL, lstack_len[lcount]);

    return current;
}

// rdata_cmp() intends to compare rdata according to DNSSEC canonical ordering
// for RRSets, which is specified in RFC 4034 sec 6.3 as:
// [RRs] are sorted by treating the RDATA portion of the canonical form of each
// RR as a left-justified unsigned octet sequence in which the absence of an
// octet sorts before a zero octet.
F_NONNULL
static int rdata_cmp(const uint8_t* r1, const uint8_t* r2)
{
    const int r1_len = (int)ntohs(gdnsd_get_una16(r1));
    const int r2_len = (int)ntohs(gdnsd_get_una16(r2));
    const int len_diff = r1_len - r2_len;
    int rv = memcmp(r1 + 2, r2 + 2, (size_t)((len_diff < 0) ? r1_len : r2_len));
    if (!rv)
        rv = len_diff;
    return rv;
}

bool ltree_add_rec(struct ltree_node_zroot* zroot, const uint8_t* dname, uint8_t* rdata, unsigned rrtype, unsigned ttl)
{
    union ltree_node* node = ltree_zone_find_or_add_dname(zroot, dname);
    if (unlikely(!node))
        return true; // find_or_add already logged about it

    // Check both directions: Adding CNAME with any other existing rrset, and
    // adding anything to a node that already has a CNAME:
    if (node->c.rrsets)
        if (rrtype == DNS_TYPE_CNAME || node->c.rrsets->gen.type == DNS_TYPE_CNAME)
            log_zfatal("Name '%s': CNAME cannot co-exist with any other record, even other CNAMEs", logf_dname(dname));

    if (rrtype == DNS_TYPE_NS && node != (union ltree_node*)zroot) {
        if (dname_iswild(node->c.dname))
            log_zfatal("Name '%s': Cannot delegate via wildcards", logf_dname(dname));
        node->c.zone_cut_deleg = true;
    }

    struct ltree_rrset_raw* rrset = NULL;
    union ltree_rrset** store_at = &node->c.rrsets;
    while (!rrset && *store_at) {
        if ((*store_at)->gen.type == rrtype)
            rrset = (struct ltree_rrset_raw*)*store_at;
        else
            store_at = &(*store_at)->gen.next;
    }

    if (rrset) {
        if (!rrset->gen.count)
            log_zfatal("Name '%s': dynamic and static results for type %s cannot co-exist", logf_dname(dname), logf_rrtype(rrtype));
        if (rrset->gen.count == LTREE_RRSET_MAX_RRS)
            log_zfatal("Name '%s': Too many RRs of type %s", logf_dname(dname), logf_rrtype(rrtype));
        if (rrset->ttl != ttl)
            log_zwarn("Name '%s': All TTLs for type %s should match (using %u)", logf_dname(dname), logf_rrtype(rrtype), rrset->ttl);
        if (rrtype == DNS_TYPE_SOA) {
            // Parsers only allow SOA at zone root
            gdnsd_assert(node != (union ltree_node*)zroot);
            if (rrset->gen.count)
                log_zfatal("Zone '%s': SOA defined twice", logf_dname(dname));
        }
        gdnsd_assert(!rrset->data_len);
    } else {
        rrset = xcalloc(sizeof(*rrset));
        *store_at = (union ltree_rrset*)rrset;
        rrset->gen.type = rrtype;
        rrset->ttl = ttl;
    }

    // Find the DNSSEC-sorted insert position for the new RR, and check for
    // dupes while we're at it.
    unsigned pos;
    for (pos = 0; pos < rrset->gen.count; pos++) {
        int c = rdata_cmp(rdata, rrset->scan_rdata[pos]);
        if (!c) {
            // We want different messages for the strict and non-strict cases
            // here, so we're not using the standard log_zwarn macro:
            if (gcfg->zones_strict_data) {
                log_err("Name '%s': duplicate RR of type %s detected", logf_dname(dname), logf_rrtype(rrtype));
                return true; // On return true (failure), the caller (parser) frees the rdata
            }
            log_err("Name '%s': duplicate RR of type %s ignored", logf_dname(dname), logf_rrtype(rrtype));
            free(rdata); // On return false (success), we have to free the duplicate we're ignoring
            return false;
        }
        if (c < 0)
            break;
    }

    // Realloc array and insert at the sorted position
    rrset->scan_rdata = xrealloc(rrset->scan_rdata, (rrset->gen.count + 1U) * sizeof(*rrset->scan_rdata));
    gdnsd_assume(pos <= rrset->gen.count);
    unsigned to_move = rrset->gen.count - pos;
    if (to_move)
        memmove(&rrset->scan_rdata[pos + 1U], &rrset->scan_rdata[pos], to_move * sizeof(*rrset->scan_rdata));
    rrset->scan_rdata[pos] = rdata;
    rrset->gen.count++;
    return false;
}

bool ltree_add_rec_dynaddr(struct ltree_node_zroot* zroot, const uint8_t* dname, const char* rhs, unsigned ttl_max, unsigned ttl_min)
{
    if (ttl_min < gcfg->min_ttl) {
        log_zwarn("Name '%s': DYNA Min-TTL /%u too small, clamped to min_ttl setting of %u", logf_dname(dname), ttl_min, gcfg->min_ttl);
        ttl_min = gcfg->min_ttl;
    }
    if (ttl_min > ttl_max) {
        log_zwarn("Name '%s': DYNA Min-TTL /%u larger than Max-TTL %u, clamping to Max-TTL", logf_dname(dname), ttl_min, ttl_max);
        ttl_min = ttl_max;
    }

    union ltree_node* node = ltree_zone_find_or_add_dname(zroot, dname);
    if (unlikely(!node))
        return true; // find_or_add already logged about it

    struct ltree_rrset_raw* rrset = NULL;
    union ltree_rrset** store_at = &node->c.rrsets;
    while (*store_at) {
        rrset = (struct ltree_rrset_raw*)*store_at;
        if (rrset->gen.type == DNS_TYPE_A || rrset->gen.type == DNS_TYPE_AAAA)
            log_zfatal("Name '%s': DYNA cannot co-exist at the same name as A, AAAA, or another DYNA", logf_dname(dname));
        store_at = &(*store_at)->gen.next;
    }

    // Allocate and link them up
    struct ltree_rrset_dynac* rrset_a = xcalloc(sizeof(*rrset_a));
    struct ltree_rrset_dynac* rrset_aaaa = xcalloc(sizeof(*rrset_aaaa));
    *store_at = (union ltree_rrset*)rrset_a;
    rrset_a->gen.next = (union ltree_rrset*)rrset_aaaa;

    rrset_a->gen.type = DNS_TYPE_A;
    rrset_a->ttl_min = ttl_min;
    rrset_a->ttl_max = ttl_max;
    rrset_a->resource = 0;

    rrset_aaaa->gen.type = DNS_TYPE_AAAA;
    rrset_aaaa->ttl_min = ttl_min;
    rrset_aaaa->ttl_max = ttl_max;
    rrset_aaaa->resource = 0;

    const unsigned rhs_size = strlen(rhs) + 1;
    if (rhs_size > 256)
        log_zfatal("Name '%s': DYNA plugin!resource string cannot exceed 255 chars", logf_dname(dname));
    char plugin_name[256];
    memcpy(plugin_name, rhs, rhs_size);
    char* resource_name = strchr(plugin_name, '!');
    if (resource_name)
        *resource_name++ = '\0';

    const struct plugin* const p = gdnsd_plugin_find(plugin_name);
    if (likely(p)) {
        if (!p->resolve)
            log_zfatal("Name '%s': DYNA RR refers to a non-resolver plugin", logf_dname(dname));
        rrset_a->func = p->resolve;
        rrset_aaaa->func = p->resolve;
        if (p->map_res) {
            const int res = p->map_res(resource_name, NULL);
            if (res < 0)
                log_zfatal("Name '%s': resolver plugin '%s' rejected resource name '%s'", logf_dname(dname), plugin_name, resource_name);
            rrset_a->resource = (unsigned)res;
            rrset_aaaa->resource = (unsigned)res;
        }
        return false;
    }

    log_zfatal("Name '%s': DYNA RR refers to plugin '%s', which is not loaded", logf_dname(dname), plugin_name);
}

bool ltree_add_rec_dync(struct ltree_node_zroot* zroot, const uint8_t* dname, const char* rhs, unsigned ttl_max, unsigned ttl_min)
{
    if (ttl_min < gcfg->min_ttl) {
        log_zwarn("Name '%s': DYNC Min-TTL /%u too small, clamped to min_ttl setting of %u", logf_dname(dname), ttl_min, gcfg->min_ttl);
        ttl_min = gcfg->min_ttl;
    }
    if (ttl_min > ttl_max) {
        log_zwarn("Name '%s': DYNC Min-TTL /%u larger than Max-TTL %u, clamping to Max-TTL", logf_dname(dname), ttl_min, ttl_max);
        ttl_min = ttl_max;
    }

    union ltree_node* node = ltree_zone_find_or_add_dname(zroot, dname);
    if (unlikely(!node))
        return true; // find_or_add already logged about it
    if (node->c.rrsets)
        log_zfatal("Name '%s': DYNC not allowed alongside other data", logf_dname(dname));
    struct ltree_rrset_dynac* rrset = xcalloc(sizeof(*rrset));
    node->c.rrsets = (union ltree_rrset*)rrset;
    rrset->gen.type = DNS_TYPE_CNAME;
    rrset->ttl_max = ttl_max;
    rrset->ttl_min = ttl_min;

    const unsigned rhs_size = strlen(rhs) + 1;
    if (rhs_size > 256)
        log_zfatal("Name '%s': DYNC plugin!resource string cannot exceed 255 chars", logf_dname(dname));
    char plugin_name[256];
    memcpy(plugin_name, rhs, rhs_size);
    char* resource_name = strchr(plugin_name, '!');
    if (resource_name)
        *resource_name++ = '\0';

    const struct plugin* const p = gdnsd_plugin_find(plugin_name);
    if (!p)
        log_zfatal("Name '%s': DYNC refers to plugin '%s', which is not loaded", logf_dname(dname), plugin_name);
    if (!p->resolve)
        log_zfatal("Name '%s': DYNC RR refers to a non-resolver plugin", logf_dname(dname));
    rrset->func = p->resolve;

    rrset->resource = 0;
    if (p->map_res) {
        const int res = p->map_res(resource_name, zroot->c.dname);
        if (res < 0)
            log_zfatal("Name '%s': plugin '%s' rejected DYNC resource '%s'", logf_dname(dname), plugin_name, resource_name);
        rrset->resource = (unsigned)res;
    }

    return false;
}

F_WUNUSED F_NONNULL
static bool check_deleg(const union ltree_node* node)
{
    if (dname_iswild(node->c.dname))
        log_zfatal("Domainname '%s': Wildcards not allowed for delegation/glue data",
                   logf_dname(node->c.dname));

    const union ltree_rrset* rrset_dchk = node->c.rrsets;
    while (rrset_dchk) {
        if (!(rrset_dchk->gen.type == DNS_TYPE_A || rrset_dchk->gen.type == DNS_TYPE_AAAA || (rrset_dchk->gen.type == DNS_TYPE_NS && node->c.zone_cut_deleg)))
            log_zfatal("Domainname '%s' is inside a delegated subzone, and can only have NS and/or address records as appropriate",
                       logf_dname(node->c.dname));
        rrset_dchk = rrset_dchk->gen.next;
    }

    return false;
}

F_WUNUSED F_NONNULL
static unsigned store_qname_comp(uint8_t* buf, const uint8_t* dname)
{
    if (dname[1] == '\0') {
        *buf = '\0';
        return 1U;
    }
    gdnsd_put_una16(htons(0xC00C), buf);
    return 2U;
}

void realize_rdata(const union ltree_node* node, struct ltree_rrset_raw* raw)
{
    // This makes this method idempotent, which is important because we don't
    // know whether the compressor code will need to realize additional nodes
    // for additional data before the postproc walk naturally reaches them
    // (currently only used for A/AAAA glue for NSes, but there may for better
    // or worse be other future uses of the additional section that are
    // warranted)
    if (raw->data_len)
        return;

    // DNSSEC TODO - Generate an uncompressed copy at this stage as well, and
    // sign it for RRSIG, and then add the completed RRSIG to raw->data

    // Encode a compressed left side (name, type, class, ttl)
    uint8_t left[10];
    unsigned left_len = 0;
    left_len += store_qname_comp(left, node->c.dname);
    gdnsd_put_una16(htons(raw->gen.type), &left[left_len]);
    left_len += 2U;
    gdnsd_put_una16(htons(DNS_CLASS_IN), &left[left_len]);
    left_len += 2U;
    gdnsd_put_una32(htonl(raw->ttl), &left[left_len]);
    left_len += 4U;
    gdnsd_assert(left_len == 10U || left_len == 9U); // latter is root-of-dns case

    unsigned total_size = raw->gen.count * (left_len + 2U);
    for (unsigned i = 0; i < raw->gen.count; i++)
        total_size += ntohs(gdnsd_get_una16(raw->scan_rdata[i]));

    uint8_t* data = xmalloc(total_size);
    unsigned offs = 0;
    for (unsigned i = 0; i < raw->gen.count; i++) {
        memcpy(&data[offs], left, left_len);
        offs += left_len;
        uint8_t* rd = raw->scan_rdata[i];
        unsigned rd_copy = ntohs(gdnsd_get_una16(rd)) + 2U;
        memcpy(&data[offs], rd, rd_copy);
        offs += rd_copy;
        free(raw->scan_rdata[i]);
    }
    free(raw->scan_rdata);

    gdnsd_assert(offs == total_size);
    raw->data = data;
    raw->data_len = offs;
}

F_WUNUSED F_NONNULL
static bool postproc_static_rrset(const union ltree_node* node, struct ltree_rrset_raw* raw, struct ltree_node_zroot* zroot, const bool in_deleg)
{
    realize_rdata(node, raw);
    // Type-specific compression for raw (and gluing in the case of NS):
    if (raw->gen.type == DNS_TYPE_MX || raw->gen.type == DNS_TYPE_CNAME || raw->gen.type == DNS_TYPE_PTR)
        comp_do_mx_cname_ptr(raw, node->c.dname);
    else if (raw->gen.type == DNS_TYPE_SOA)
        comp_do_soa(raw, node->c.dname);
    else if (raw->gen.type == DNS_TYPE_NS)
        if (comp_do_ns(raw, zroot, node->c.dname, in_deleg))
            return true;
    return false;
}

F_WUNUSED F_NONNULL
static bool ltree_postproc_node(union ltree_node* node, struct ltree_node_zroot* zroot, const bool in_deleg)
{
    // This checks for junk/excess/wildcard data in delegations, imposing the
    // constraint that within a delegation cut (which starts at any NS record
    // other than at a zone root), only A and AAAA records with non-wildcard
    // labels can exist.
    if (in_deleg && check_deleg(node))
        return true;

    // Size for everything but the actual response RRs:
    unsigned rsize_base = BASE_RESP_SIZE;
    if (node->c.zone_cut_deleg || dname_iswild(node->c.dname))
        // For delegations and wildcards, assume max qname len
        rsize_base += 255U;
    else
        rsize_base += *node->c.dname;

    // Iterate the rrsets of the target node, doing various fixup/comp/glue
    // work and finally checking their response packet size limits:
    union ltree_rrset* rrset = node->c.rrsets;
    while (rrset) {
        // dynamics skip all of this: they're known-small and don't have data to
        // glue or compress:
        if (rrset->gen.count) {
            if (postproc_static_rrset(node, &rrset->raw, zroot, in_deleg))
                return true;
            // assert that the above converted scan_rdata -> data
            gdnsd_assert(rrset->raw.data_len);
            // deterministic output size check
            unsigned rsize_resp = rsize_base + rrset->raw.data_len;
            if (rsize_resp > MAX_RESPONSE_DATA)
                log_zfatal("'%s %s' has too much data (%u > %u)",
                           logf_dname(node->c.dname), logf_rrtype(rrset->gen.type),
                           rsize_resp, MAX_RESPONSE_DATA);
        }
        rrset = rrset->gen.next;
    }

    return false;
}

F_WUNUSED F_NONNULL
static bool ltree_postproc_zroot(struct ltree_node_zroot* zroot)
{
    union ltree_rrset* zroot_soa = NULL;
    const union ltree_rrset* zroot_ns = NULL;

    union ltree_rrset* rrset = zroot->c.rrsets;
    while (rrset) {
        switch (rrset->gen.type) {
        case DNS_TYPE_SOA:
            zroot_soa = rrset;
            break;
        case DNS_TYPE_NS:
            zroot_ns = rrset;
            break;
        default:
            break;
        }
        rrset = rrset->gen.next;
    }

    if (!zroot_soa)
        log_zfatal("Zone '%s' has no SOA record", logf_dname(zroot->c.dname));
    if (!zroot_ns)
        log_zfatal("Zone '%s' has no NS records", logf_dname(zroot->c.dname));
    gdnsd_assert(zroot_ns->gen.count);
    if (zroot_ns->gen.count < 2)
        log_zwarn("Zone '%s' only has one NS record, this is (probably) bad practice", logf_dname(zroot->c.dname));

    // In the probably-rare case that the SOA record wasn't the first data line
    // in the zonefile, re-arrange the rrsets to place it at the beginning, so
    // that we can rely on it being the first rrset at runtime over in
    // dnspacket.c:
    if (unlikely(zroot_soa != zroot->c.rrsets)) {
        union ltree_rrset* srch = zroot->c.rrsets;
        while (srch->gen.next != zroot_soa)
            srch = srch->gen.next;
        srch->gen.next = zroot_soa->gen.next;
        zroot_soa->gen.next = zroot->c.rrsets;
        zroot->c.rrsets = zroot_soa;
    }

    // Extract SOA serial to zone->serial
    struct ltree_rrset_raw* zsoa = &zroot_soa->raw;
    gdnsd_assert(!zsoa->num_comp_offsets); // still in scan_rdata mode
    gdnsd_assume(zsoa->scan_rdata && zsoa->scan_rdata[0]);
    const unsigned serial_offset = ntohs(gdnsd_get_una16(zsoa->scan_rdata[0])) - 18U;
    zroot->serial = ntohl(gdnsd_get_una32(&zsoa->scan_rdata[0][serial_offset]));

    return false;
}

F_WUNUSED F_NONNULL
static bool ltree_postproc_recurse(union ltree_node* node, struct ltree_node_zroot* zroot, bool in_deleg)
{
    gdnsd_assume(node->c.dname);

    if (node->c.zone_cut_deleg) {
        if (in_deleg)
            log_zfatal("Delegation '%s' is within another delegation", logf_dname(node->c.dname));
        in_deleg = true;
    }

    if (unlikely(ltree_postproc_node(node, zroot, in_deleg)))
        return true;

    // Recurse into children
    const uint32_t ccount = node->c.ccount;
    if (ccount) {
        gdnsd_assume(node->c.child_table);
        const uint32_t cmask = count2mask_u32_lf80(ccount);
        for (uint32_t i = 0; i <= cmask; i++) {
            union ltree_node* child = node->c.child_table[i].node;
            if (child && unlikely(ltree_postproc_recurse(child, zroot, in_deleg)))
                return true;
        }
    }

    return false;
}

F_NONNULL
static void ltree_postproc_recurse_phase2(union ltree_node* node, struct ltree_node_zroot* zroot)
{
    gdnsd_assume(node->c.dname);

    // Recurse into children and destroy all child nodes of delegation points as we go
    const uint32_t ccount = node->c.ccount;
    if (ccount) {
        gdnsd_assume(node->c.child_table);
        const uint32_t cmask = count2mask_u32_lf80(ccount);
        for (uint32_t i = 0; i <= cmask; i++) {
            union ltree_node* child = node->c.child_table[i].node;
            if (child) {
                if (node->c.zone_cut_deleg)
                    ltree_destroy(child);
                else
                    ltree_postproc_recurse_phase2(child, zroot);
            }
        }
        if (node->c.zone_cut_deleg) {
            free(node->c.child_table);
            node->c.child_table = NULL;
            node->c.ccount = 0;
        }
    }

    // As we unwind from recursion at a deleg cut, unless we already have a
    // singular NS RRset, delete the excess address rrsets leaving only the NS
    if (node->c.zone_cut_deleg && (node->c.rrsets->gen.type != DNS_TYPE_NS || (node->c.rrsets->gen.next))) {
        union ltree_rrset* ns = NULL;
        union ltree_rrset* srch = node->c.rrsets;
        gdnsd_assume(srch); // always has at least NS
        do {
            union ltree_rrset* next = srch->gen.next;
            if (srch->gen.type == DNS_TYPE_NS) {
                ns = srch;
            } else {
                gdnsd_assert(srch->gen.type == DNS_TYPE_A || srch->gen.type == DNS_TYPE_AAAA);
                free(srch->raw.data);
                free(srch);
            }
            srch = next;
        } while (srch);
        gdnsd_assume(ns);
        ns->gen.next = NULL;
        node->c.rrsets = ns;
    }
}

bool ltree_postproc_zone(struct ltree_node_zroot* zroot)
{
    if (unlikely(ltree_postproc_zroot(zroot)))
        return true;

    // Recursively process tree nodes breadth-first for things like data sanity
    // checks (e.g. CNAME+X), RHS compression, NS glue attachment, output size
    // checks, etc, etc...
    if (unlikely(ltree_postproc_recurse((union ltree_node*)zroot, zroot, false)))
        return true;

    // The second recursive phase destroys all nodes and address rrset data
    // beneath delegation points, as their data was already consumed into the
    // appropriate NS RRSets at (possibly different) delegation points, which
    // will now be the only rrset left at delegation nodes.  Cannot fail.
    ltree_postproc_recurse_phase2((union ltree_node*)zroot, zroot);
    return false;
}

void ltree_destroy(union ltree_node* node)
{
    union ltree_rrset* rrset = node->c.rrsets;
    while (rrset) {
        union ltree_rrset* next = rrset->gen.next;
        // Everything is in raw form, except !count dynac entries
        if (rrset->gen.count) {
            struct ltree_rrset_raw* r = &rrset->raw;
            if (!r->data_len && r->scan_rdata) {
                for (unsigned i = 0; i < rrset->gen.count; i++)
                    free(r->scan_rdata[i]);
                free(r->scan_rdata);
                gdnsd_assert(!r->comp_offsets);
            } else if (r->data) {
                free(r->data);
                if (r->comp_offsets)
                    free(r->comp_offsets);
            }
        }
        free(rrset);
        rrset = next;
    }

    if (node->c.child_table) {
        const uint32_t mask = count2mask_u32_lf80(node->c.ccount);
        for (uint32_t i = 0; i <= mask; i++)
            if (node->c.child_table[i].node)
                ltree_destroy(node->c.child_table[i].node);
        free(node->c.child_table);
    }
    free(node->c.dname);
    free(node);
}

// -- meta-stuff for zone loading/reloading, etc:

void* ltree_zones_reloader_thread(void* init_asvoid)
{
    gdnsd_thread_setname("gdnsd-zreload");
    const bool init = (bool)init_asvoid;
    if (init) {
        gdnsd_assert(!GRCU_OWN_READ(root_tree));
    } else {
        gdnsd_assert(GRCU_OWN_READ(root_tree));
        gdnsd_thread_reduce_prio();
    }

    uintptr_t rv = 0;

    // This does not fail if the zones data directory doesn't exist
    union ltree_node* new_root_tree = zsrc_rfc1035_load_zones();

    if (!new_root_tree) {
        rv = 1; // the zsrc already logged why
    } else {
        union ltree_node* old_root_tree = GRCU_OWN_READ(root_tree);
        grcu_assign_pointer(root_tree, new_root_tree);
        grcu_synchronize_rcu();
        if (old_root_tree)
            ltree_destroy(old_root_tree);
    }

    if (!init)
        notify_reload_zones_done();

    return (void*)rv;
}

void ltree_init(void)
{
    gdnsd_shorthash_init(); // idempotent
    zsrc_rfc1035_init();
}

struct ltree_node_zroot* ltree_new_zone(const char* zname)
{
    uint8_t dname[256];
    enum dname_status status = dname_from_string(dname, zname, strlen(zname));

    if (status == DNAME_INVALID) {
        log_err("Zone name '%s' is illegal", zname);
        return NULL;
    }
    if (dname_iswild(dname)) {
        log_err("Zone '%s': Wildcard zone names not allowed", logf_dname(dname));
        return NULL;
    }
    if (status == DNAME_PARTIAL)
        dname_terminate(dname);

    struct ltree_node_zroot* zroot = xcalloc(sizeof(*zroot));
    zroot->c.zone_cut_root = true;
    zroot->c.dname = dname_dup(dname);
    return zroot;
}

F_WUNUSED F_NONNULL
static unsigned dname_to_lstack(const uint8_t* dname, const uint8_t** lstack, uint8_t* lstack_len)
{
    gdnsd_assert(dname_get_status(dname) == DNAME_VALID);
    unsigned total_len = *dname++;
    unsigned lcount = 0;
    unsigned llen; // current label len
    while ((llen = *dname)) {
        gdnsd_assume(lcount < 127);
        lstack_len[lcount] = total_len;
        lstack[lcount++] = dname;
        llen++;
        dname += llen;
        gdnsd_assume(total_len >= llen);
        total_len -= llen;
    }
    gdnsd_assert(total_len == 1U); // because we don't lstack the final \0
    return lcount;
}

bool ltree_merge_zone(union ltree_node** root_of_dns_p, struct ltree_node_zroot* zroot)
{
    gdnsd_assume(zroot->c.dname);
    gdnsd_assume(zroot->c.zone_cut_root);

    union ltree_node* root_of_dns = *root_of_dns_p;

    gdnsd_assume(!root_of_dns->c.dname[1]); // merge target is global root

    // Special case for insert of ROOT_ZONE, has to replace *root_of_dns_p storage
    if (!zroot->c.dname[1]) { // ROOT_ZONE
        if (root_of_dns->c.ccount) {
            log_err("ROOT_ZONE cannot co-exist with other zones");
            return true;
        }
        ltree_destroy(root_of_dns);
        *root_of_dns_p = (union ltree_node*)zroot;
        log_info("ROOT ZONE with serial %" PRIu32 " loaded", zroot->serial);
        return false;
    }

    uint8_t lstack_len[127];
    const uint8_t* lstack[127];
    unsigned lcount = dname_to_lstack(zroot->c.dname, lstack, lstack_len);

    union ltree_node* n = root_of_dns;
    while (lcount) {
        if (n->c.zone_cut_root) {
            log_err("Zone '%s' is a sub-zone of an existing zone", logf_dname(zroot->c.dname));
            return true;
        }
        lcount--;
        union ltree_node* ins = lcount ? NULL : (union ltree_node*)zroot;
        n = ltree_node_find_or_add_child(n, lstack[lcount], ins, lstack_len[lcount]);
        if (unlikely(!n))
            return true; // find_or_add already logged about it
    }

    if (n != (union ltree_node*)zroot) {
        if (n->c.zone_cut_root)
            log_err("Zone '%s' is a duplicate of an existing zone", logf_dname(zroot->c.dname));
        else if (n->c.ccount)
            log_err("Zone '%s' is a super-zone of one or more existing zones", logf_dname(zroot->c.dname));
        return true;
    }

    log_info("Zone %s with serial %" PRIu32 " loaded", logf_dname(zroot->c.dname), zroot->serial);
    return false;
}
