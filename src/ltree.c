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
static void ltree_node_insert(const struct ltree_node* node, struct ltree_node* child, uintptr_t child_hash, uint32_t probe_dist, const uint32_t mask)
{
    do {
        const uint32_t slot = ((uint32_t)child_hash + probe_dist) & mask;
        struct ltree_hslot* s = &node->child_table[slot];
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

F_NONNULL
static struct ltree_node* ltree_node_find_or_add_child(struct ltree_node* node, const uint8_t* child_name, unsigned child_name_len)
{
    const uint32_t ccount = node->ccount;
    const uintptr_t kh = ltree_hash_label(child_name);
    uint32_t probe_dist = 0;
    uint32_t mask = 0;
    if (ccount) {
        mask = count2mask_u32_lf80(ccount);
        do {
            const uint32_t slot = ((uint32_t)kh + probe_dist) & mask;
            const struct ltree_hslot* s = &node->child_table[slot];
            if (!s->node || ((slot - s->hash) & mask) < probe_dist)
                break;
            gdnsd_assume(s->node->dname);
            if (s->hash == kh && likely(!label_cmp(&s->node->dname[1], child_name)))
                return s->node;
            probe_dist++;
        } while (1);
    }
    if (unlikely((ccount + (ccount >> 2U)) == LTREE_NODE_MAX_SLOTS))
        return NULL;
    const uint32_t next_mask = count2mask_u32_lf80(ccount + 1U);
    if (next_mask != mask) {
        struct ltree_hslot* old_table = node->child_table;
        node->child_table = xcalloc_n(next_mask + 1U, sizeof(*node->child_table));
        if (old_table) {
            for (uint32_t i = 0; i <= mask; i++)
                if (old_table[i].node)
                    ltree_node_insert(node, old_table[i].node, old_table[i].hash, 0, next_mask);
            free(old_table);
        }
        probe_dist = 0; // if grow, reset saved distance
        mask = next_mask; // new mask in play below
    }
    struct ltree_node* ins = xcalloc(sizeof(*ins));
    ins->dname = dname_from_name(child_name, child_name_len);
    ltree_node_insert(node, ins, kh, probe_dist, mask);
    node->ccount++;
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
static struct ltree_node* ltree_zone_find_or_add_dname(struct ltree_node* zroot, const uint8_t* dname)
{
    gdnsd_assume(zroot->dname);
    gdnsd_assert(dname_get_status(dname) == DNAME_VALID);
    gdnsd_assert(dname_isinzone(zroot->dname, dname));

    uint8_t lstack_len[127];
    const uint8_t* lstack[127];
    unsigned lcount = dname_to_lstack_relative(dname, lstack, lstack_len, zroot->dname);

    struct ltree_node* current = zroot;
    while (lcount-- && current)
        current = ltree_node_find_or_add_child(current, lstack[lcount], lstack_len[lcount]);

    return current;
}

F_WUNUSED F_NONNULL
static bool ltree_add_rr_raw(struct ltree_node* zroot, const uint8_t* dname, uint8_t* data, const unsigned data_size, const char* rrtype_desc, unsigned ttl, unsigned rrtype)
{
    struct ltree_node* node = ltree_zone_find_or_add_dname(zroot, dname);
    if (unlikely(!node))
        log_zfatal("Too many domainnames at one level in zone '%s'", logf_dname(zroot->dname));

    // Check both directions: Adding CNAME with any other existing rrset, and
    // adding anything to a node that already has a CNAME:
    if (node->rrsets)
        if (rrtype == DNS_TYPE_CNAME || node->rrsets->gen.type == DNS_TYPE_CNAME)
            log_zfatal("Name '%s': CNAME cannot co-exist with any other record, even other CNAMEs", logf_dname(dname));

    if (rrtype == DNS_TYPE_NS && node != zroot) {
        node->zone_cut = true;
        if (dname_iswild(node->dname))
            log_zfatal("Name '%s': Cannot delegate via wildcards", logf_dname(dname));
    }

    struct ltree_rrset_raw* rrset = NULL;
    union ltree_rrset** store_at = &node->rrsets;
    while (*store_at) {
        if ((*store_at)->gen.type == rrtype) {
            rrset = (struct ltree_rrset_raw*)*store_at;
            if (!rrset->gen.count)
                log_zfatal("Name '%s': %s dynamic and static results of the same type cannot co-exist", logf_dname(dname), rrtype_desc);
            if (rrset->gen.count == LTREE_RRSET_MAX_RRS)
                log_zfatal("Name '%s': Too many RRs of type %s", logf_dname(dname), rrtype_desc);
            gdnsd_assume(rrset->data); // we asserted count earlier
            const unsigned first_ttl = ntohl(gdnsd_get_una32(&rrset->data[6U]));
            if (ttl != first_ttl) {
                log_zwarn("Name '%s': All TTLs for type %s should match (using %u)", logf_dname(dname), rrtype_desc, first_ttl);
                gdnsd_put_una32(htonl(first_ttl), &data[6U]); // correct the new RR data
            }
            rrset->gen.count++;
            break;
        }
        store_at = &(*store_at)->gen.next;
    }

    if (!rrset) {
        rrset = xcalloc(sizeof(*rrset));
        *store_at = (union ltree_rrset*)rrset;
        rrset->gen.type = rrtype;
        rrset->gen.count = 1U;
    }

    if (rrtype == DNS_TYPE_SOA) {
        // Parsers only allow SOA at zone root
        gdnsd_assert(zroot == node);
        if (rrset->gen.count > 1U)
            log_zfatal("Zone '%s': SOA defined twice", logf_dname(dname));
    }

    const unsigned new_size = rrset->data_len + data_size;
    rrset->data = xrealloc(rrset->data, new_size);
    memcpy(&rrset->data[rrset->data_len], data, data_size);
    rrset->data_len = new_size;

    return false;
}

// for clamping TTLs in ltree_add_rec_*
F_NONNULL
static unsigned clamp_ttl(const uint8_t* dname, const char* rrtype, const unsigned ttl)
{
    if (ttl > gcfg->max_ttl) {
        log_warn("Name '%s': %s TTL %u too large, clamped to max_ttl setting of %u",
                 logf_dname(dname), rrtype, ttl, gcfg->max_ttl);
        return gcfg->max_ttl;
    } else if (ttl < gcfg->min_ttl) {
        log_warn("Name '%s': %s TTL %u too small, clamped to min_ttl setting of %u",
                 logf_dname(dname), rrtype, ttl, gcfg->min_ttl);
        return gcfg->min_ttl;
    }
    return ttl;
}

bool ltree_add_rec_dynaddr(struct ltree_node* zroot, const uint8_t* dname, const char* rhs, unsigned ttl_max, unsigned ttl_min)
{
    ttl_max = clamp_ttl(dname, "DYNA", ttl_max);
    if (ttl_min < gcfg->min_ttl) {
        log_zwarn("Name '%s': DYNA Min-TTL /%u too small, clamped to min_ttl setting of %u", logf_dname(dname), ttl_min, gcfg->min_ttl);
        ttl_min = gcfg->min_ttl;
    }
    if (ttl_min > ttl_max) {
        log_zwarn("Name '%s': DYNA Min-TTL /%u larger than Max-TTL %u, clamping to Max-TTL", logf_dname(dname), ttl_min, ttl_max);
        ttl_min = ttl_max;
    }

    struct ltree_node* node = ltree_zone_find_or_add_dname(zroot, dname);
    if (unlikely(!node))
        log_zfatal("Too many domainnames at one level in zone '%s'", logf_dname(zroot->dname));

    struct ltree_rrset_raw* rrset = NULL;
    union ltree_rrset** store_at = &node->rrsets;
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

bool ltree_add_rec_dync(struct ltree_node* zroot, const uint8_t* dname, const char* rhs, unsigned ttl_max, unsigned ttl_min)
{
    ttl_max = clamp_ttl(dname, "DYNC", ttl_max);
    if (ttl_min < gcfg->min_ttl) {
        log_zwarn("Name '%s': DYNC Min-TTL /%u too small, clamped to min_ttl setting of %u", logf_dname(dname), ttl_min, gcfg->min_ttl);
        ttl_min = gcfg->min_ttl;
    }
    if (ttl_min > ttl_max) {
        log_zwarn("Name '%s': DYNC Min-TTL /%u larger than Max-TTL %u, clamping to Max-TTL", logf_dname(dname), ttl_min, ttl_max);
        ttl_min = ttl_max;
    }

    struct ltree_node* node = ltree_zone_find_or_add_dname(zroot, dname);
    if (unlikely(!node))
        log_zfatal("Too many domainnames at one level in zone '%s'", logf_dname(zroot->dname));
    if (node->rrsets)
        log_zfatal("Name '%s': DYNC not allowed alongside other data", logf_dname(dname));
    struct ltree_rrset_dynac* rrset = xcalloc(sizeof(*rrset));
    node->rrsets = (union ltree_rrset*)rrset;
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
        const int res = p->map_res(resource_name, zroot->dname);
        if (res < 0)
            log_zfatal("Name '%s': plugin '%s' rejected DYNC resource '%s'", logf_dname(dname), plugin_name, resource_name);
        rrset->resource = (unsigned)res;
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

bool ltree_add_rec_a(struct ltree_node* zroot, const uint8_t* dname, const uint32_t addr, unsigned ttl)
{
    ttl = clamp_ttl(dname, "A", ttl);
    unsigned offs = 0;
    uint8_t buf[16U];
    offs += store_qname_comp(buf, dname);
    gdnsd_put_una32(DNS_RRFIXED_A, &buf[offs]);
    offs += 4U;
    gdnsd_put_una32(htonl(ttl), &buf[offs]);
    offs += 4U;
    gdnsd_put_una16(htons(4U), &buf[offs]);
    offs += 2U;
    gdnsd_put_una32(addr, &buf[offs]);
    offs += 4U;
    return ltree_add_rr_raw(zroot, dname, buf, offs, "A", ttl, DNS_TYPE_A);
}

bool ltree_add_rec_aaaa(struct ltree_node* zroot, const uint8_t* dname, const uint8_t* addr, unsigned ttl)
{
    ttl = clamp_ttl(dname, "AAAA", ttl);
    unsigned offs = 0;
    uint8_t buf[28U];
    offs += store_qname_comp(buf, dname);
    gdnsd_put_una32(DNS_RRFIXED_AAAA, &buf[offs]);
    offs += 4U;
    gdnsd_put_una32(htonl(ttl), &buf[offs]);
    offs += 4U;
    gdnsd_put_una16(htons(16U), &buf[offs]);
    offs += 2U;
    memcpy(&buf[offs], addr, 16U);
    offs += 16U;
    return ltree_add_rr_raw(zroot, dname, buf, offs, "AAAA", ttl, DNS_TYPE_AAAA);
}

bool ltree_add_rec_ns(struct ltree_node* zroot, const uint8_t* dname, const uint8_t* rhs, unsigned ttl)
{
    ttl = clamp_ttl(dname, "NS", ttl);
    const unsigned this_rr_rdlen = rhs[0];
    unsigned offs = 0;
    uint8_t buf[12U + 255U];
    offs += store_qname_comp(buf, dname);
    gdnsd_put_una32(DNS_RRFIXED_NS, &buf[offs]);
    offs += 4U;
    gdnsd_put_una32(htonl(ttl), &buf[offs]);
    offs += 4U;
    gdnsd_put_una16(htons(this_rr_rdlen), &buf[offs]);
    offs += 2U;
    memcpy(&buf[offs], &rhs[1], rhs[0]);
    offs += rhs[0];
    return ltree_add_rr_raw(zroot, dname, buf, offs, "NS", ttl, DNS_TYPE_NS);
}

bool ltree_add_rec_soa_args(struct ltree_node* zroot, const uint8_t* dname, struct lt_soa_args args)
{
    // Here we clamp the negative TTL using min_ttl and max_ncache_ttl
    if (args.ncache > gcfg->max_ncache_ttl) {
        log_zwarn("Zone '%s': SOA negative-cache field %u too large, clamped to max_ncache_ttl setting of %u", logf_dname(dname), args.ncache, gcfg->max_ncache_ttl);
        args.ncache = gcfg->max_ncache_ttl;
    } else if (args.ncache < gcfg->min_ttl) {
        log_zwarn("Zone '%s': SOA negative-cache field %u too small, clamped to min_ttl setting of %u", logf_dname(dname), args.ncache, gcfg->min_ttl);
        args.ncache = gcfg->min_ttl;
    }

    // And here, we clamp the real RR TTL using min_ttl and the ncache value derived above
    if (args.ttl > args.ncache) {
        log_zwarn("Zone '%s': SOA TTL %u > ncache field %u, clamped to ncache value", logf_dname(dname), args.ttl, args.ncache);
        args.ttl = args.ncache;
    } else if (args.ttl < gcfg->min_ttl) {
        log_zwarn("Zone '%s': SOA TTL %u too small, clamped to min_ttl setting of %u", logf_dname(dname), args.ttl, gcfg->min_ttl);
        args.ttl = gcfg->min_ttl;
    }

    const unsigned this_rr_rdlen = args.mname[0] + args.rname[0] + 20U;
    unsigned offs = 0;
    uint8_t buf[12U + 255U + 255U + 20U];
    offs += store_qname_comp(buf, dname);
    gdnsd_put_una32(DNS_RRFIXED_SOA, &buf[offs]);
    offs += 4U;
    gdnsd_put_una32(htonl(args.ttl), &buf[offs]);
    offs += 4U;
    gdnsd_put_una16(htons(this_rr_rdlen), &buf[offs]);
    offs += 2U;

    memcpy(&buf[offs], &args.mname[1], args.mname[0]);
    offs += args.mname[0];
    memcpy(&buf[offs], &args.rname[1], args.rname[0]);
    offs += args.rname[0];
    gdnsd_put_una32(htonl(args.serial), &buf[offs]);
    offs += 4U;
    gdnsd_put_una32(htonl(args.refresh), &buf[offs]);
    offs += 4U;
    gdnsd_put_una32(htonl(args.retry), &buf[offs]);
    offs += 4U;
    gdnsd_put_una32(htonl(args.expire), &buf[offs]);
    offs += 4U;
    gdnsd_put_una32(htonl(args.ncache), &buf[offs]);
    offs += 4U;

    return ltree_add_rr_raw(zroot, dname, buf, offs, "SOA", args.ttl, DNS_TYPE_SOA);
}

bool ltree_add_rec_cname(struct ltree_node* zroot, const uint8_t* dname, const uint8_t* rhs, unsigned ttl)
{
    ttl = clamp_ttl(dname, "CNAME", ttl);

    const unsigned this_rr_rdlen = rhs[0];
    unsigned offs = 0;
    uint8_t buf[12U + 255U];
    offs += store_qname_comp(buf, dname);
    gdnsd_put_una32(DNS_RRFIXED_CNAME, &buf[offs]);
    offs += 4U;
    gdnsd_put_una32(htonl(ttl), &buf[offs]);
    offs += 4U;
    gdnsd_put_una16(htons(this_rr_rdlen), &buf[offs]);
    offs += 2U;
    memcpy(&buf[offs], &rhs[1], rhs[0]);
    offs += rhs[0];

    return ltree_add_rr_raw(zroot, dname, buf, offs, "CNAME", ttl, DNS_TYPE_CNAME);
}

bool ltree_add_rec_mx(struct ltree_node* zroot, const uint8_t* dname, const uint8_t* rhs, unsigned ttl, const unsigned pref)
{
    ttl = clamp_ttl(dname, "MX", ttl);

    const unsigned this_rr_rdlen = 2U + rhs[0];
    unsigned offs = 0;
    uint8_t buf[12U + 2U + 255U];
    offs += store_qname_comp(buf, dname);
    gdnsd_put_una32(DNS_RRFIXED_MX, &buf[offs]);
    offs += 4U;
    gdnsd_put_una32(htonl(ttl), &buf[offs]);
    offs += 4U;
    gdnsd_put_una16(htons(this_rr_rdlen), &buf[offs]);
    offs += 2U;
    gdnsd_put_una16(htons(pref), &buf[offs]);
    offs += 2U;
    memcpy(&buf[offs], &rhs[1], rhs[0]);
    offs += rhs[0];

    return ltree_add_rr_raw(zroot, dname, buf, offs, "MX", ttl, DNS_TYPE_MX);
}

bool ltree_add_rec_ptr(struct ltree_node* zroot, const uint8_t* dname, const uint8_t* rhs, unsigned ttl)
{
    ttl = clamp_ttl(dname, "PTR", ttl);

    const unsigned this_rr_rdlen = rhs[0];
    unsigned offs = 0;
    uint8_t buf[12U + 255U];

    offs += store_qname_comp(buf, dname);
    gdnsd_put_una32(DNS_RRFIXED_PTR, &buf[offs]);
    offs += 4U;
    gdnsd_put_una32(htonl(ttl), &buf[offs]);
    offs += 4U;
    gdnsd_put_una16(htons(this_rr_rdlen), &buf[offs]);
    offs += 2U;
    memcpy(&buf[offs], &rhs[1], rhs[0]);
    offs += rhs[0];

    return ltree_add_rr_raw(zroot, dname, buf, offs, "PTR", ttl, DNS_TYPE_PTR);
}

bool ltree_add_rec_srv_args(struct ltree_node* zroot, const uint8_t* dname, struct lt_srv_args args)
{
    const unsigned ttl = clamp_ttl(dname, "SRV", args.ttl);

    const unsigned this_rr_rdlen = 6U + args.rhs[0];
    unsigned offs = 0;
    uint8_t buf[12U + 6U + 255U];
    offs += store_qname_comp(buf, dname);
    gdnsd_put_una32(DNS_RRFIXED_SRV, &buf[offs]);
    offs += 4U;
    gdnsd_put_una32(htonl(ttl), &buf[offs]);
    offs += 4U;
    gdnsd_put_una16(htons(this_rr_rdlen), &buf[offs]);
    offs += 2U;
    gdnsd_put_una16(htons(args.priority), &buf[offs]);
    offs += 2U;
    gdnsd_put_una16(htons(args.weight), &buf[offs]);
    offs += 2U;
    gdnsd_put_una16(htons(args.port), &buf[offs]);
    offs += 2U;
    memcpy(&buf[offs], &args.rhs[1], args.rhs[0]);
    offs += args.rhs[0];

    return ltree_add_rr_raw(zroot, dname, buf, offs, "SRV", ttl, DNS_TYPE_SRV);
}

bool ltree_add_rec_naptr_args(struct ltree_node* zroot, const uint8_t* dname, struct lt_naptr_args args)
{
    unsigned ttl = clamp_ttl(dname, "NAPTR", args.ttl);

    const unsigned this_rr_rdlen = 4U + args.text_len + args.rhs[0];
    uint8_t* buf = xmalloc(12U + this_rr_rdlen);
    unsigned offs = 0;
    offs += store_qname_comp(buf, dname);
    gdnsd_put_una32(DNS_RRFIXED_NAPTR, &buf[offs]);
    offs += 4U;
    gdnsd_put_una32(htonl(ttl), &buf[offs]);
    offs += 4U;
    gdnsd_put_una16(htons(this_rr_rdlen), &buf[offs]);
    offs += 2U;
    gdnsd_put_una16(htons(args.order), &buf[offs]);
    offs += 2U;
    gdnsd_put_una16(htons(args.pref), &buf[offs]);
    offs += 2U;
    memcpy(&buf[offs], args.text, args.text_len);
    offs += args.text_len;
    memcpy(&buf[offs], &args.rhs[1], args.rhs[0]);
    offs += args.rhs[0];
    const bool rv = ltree_add_rr_raw(zroot, dname, buf, offs, "NAPTR", ttl, DNS_TYPE_NAPTR);
    free(buf);
    return rv;
}

bool ltree_add_rec_txt(struct ltree_node* zroot, const uint8_t* dname, const unsigned text_len, uint8_t* text, unsigned ttl)
{
    ttl = clamp_ttl(dname, "TXT", ttl);

    const unsigned this_rr_rdlen = text_len;
    uint8_t* buf = xmalloc(12U + this_rr_rdlen);
    unsigned offs = 0;

    offs += store_qname_comp(buf, dname);
    gdnsd_put_una32(DNS_RRFIXED_TXT, &buf[offs]);
    offs += 4U;
    gdnsd_put_una32(htonl(ttl), &buf[offs]);
    offs += 4U;
    gdnsd_put_una16(htons(this_rr_rdlen), &buf[offs]);
    offs += 2U;
    memcpy(&buf[offs], text, text_len);
    offs += text_len;
    const bool rv = ltree_add_rr_raw(zroot, dname, buf, offs, "TXT", ttl, DNS_TYPE_TXT);
    free(buf);
    return rv;
}

bool ltree_add_rec_rfc3597(struct ltree_node* zroot, const uint8_t* dname, const unsigned rrtype, unsigned ttl, const unsigned rdlen, uint8_t* rd)
{
    // For various error/log outputs, some of which are indirect
    char type_desc[64];
    int snp_rv = snprintf(type_desc, 64, "RFC3597 TYPE%u", rrtype);
    gdnsd_assert(snp_rv > 0 && snp_rv < 64);

    if (rrtype == DNS_TYPE_A
            || rrtype == DNS_TYPE_AAAA
            || rrtype == DNS_TYPE_SOA
            || rrtype == DNS_TYPE_CNAME
            || rrtype == DNS_TYPE_NS
            || rrtype == DNS_TYPE_PTR
            || rrtype == DNS_TYPE_MX
            || rrtype == DNS_TYPE_SRV
            || rrtype == DNS_TYPE_NAPTR
            || rrtype == DNS_TYPE_TXT)
        log_zfatal("Name '%s': %s not allowed, please use the explicit support built in for this RR type", logf_dname(dname), type_desc);

    if (rrtype == DNS_TYPE_HINFO
            || (rrtype > 127 && rrtype < 256)
            || rrtype == 0)
        log_zfatal("Name '%s': %s not allowed", logf_dname(dname), type_desc);

    ttl = clamp_ttl(dname, type_desc, ttl);

    unsigned offs = 0;
    uint8_t* buf = xmalloc(12U + rdlen);
    offs += store_qname_comp(buf, dname);
    gdnsd_put_una16(htons(rrtype), &buf[offs]);
    offs += 2U;
    gdnsd_put_una16(htons(DNS_CLASS_IN), &buf[offs]);
    offs += 2U;
    gdnsd_put_una32(htonl(ttl), &buf[offs]);
    offs += 4U;
    gdnsd_put_una16(htons(rdlen), &buf[offs]);
    offs += 2U;
    memcpy(&buf[offs], rd, rdlen);
    offs += rdlen;
    const bool rv = ltree_add_rr_raw(zroot, dname, buf, offs, type_desc, ttl, rrtype);
    free(buf);
    return rv;
}

F_WUNUSED F_NONNULL
static bool check_deleg(const struct ltree_node* node, const bool at_deleg)
{
    if (dname_iswild(node->dname))
        log_zfatal("Domainname '%s': Wildcards not allowed for delegation/glue data",
                   logf_dname(node->dname));

    const union ltree_rrset* rrset_dchk = node->rrsets;
    while (rrset_dchk) {
        if (!(rrset_dchk->gen.type == DNS_TYPE_A || rrset_dchk->gen.type == DNS_TYPE_AAAA || (rrset_dchk->gen.type == DNS_TYPE_NS && at_deleg)))
            log_zfatal("Domainname '%s' is inside a delegated subzone, and can only have NS and/or address records as appropriate",
                       logf_dname(node->dname));
        rrset_dchk = rrset_dchk->gen.next;
    }

    return false;
}

F_WUNUSED F_NONNULL
static bool ltree_postproc_node(struct ltree_node* node, struct ltree_node* zroot, const bool in_deleg)
{
    const bool at_deleg = node->zone_cut && node != zroot;

    // This checks for junk/excess/wildcard data in delegations, imposing the
    // constraint that within a delegation cut (which starts at any NS record
    // other than at a zone root), only A and AAAA records with non-wildcard
    // labels can exist.
    if (in_deleg && check_deleg(node, at_deleg))
        return true;

    // Size for everything but the actual response RRs:
    unsigned rsize_base = BASE_RESP_SIZE;
    if (at_deleg || dname_iswild(node->dname))
        // For delegations and wildcards, assume max qname len
        rsize_base += 255U;
    else
        rsize_base += *node->dname;

    // Iterate the rrsets of the target node, doing various fixup/comp/glue
    // work and finally checking their response packet size limits:
    union ltree_rrset* rrset = node->rrsets;
    while (rrset) {
        // dynamics skip all of this: they're known-small and don't have data to
        // glue or compress:
        if (rrset->gen.count) {
            // Type-specific compression for raw (and gluing in the case of NS):
            if (rrset->gen.type == DNS_TYPE_MX || rrset->gen.type == DNS_TYPE_CNAME || rrset->gen.type == DNS_TYPE_PTR) {
                comp_do_mx_cname_ptr(&rrset->raw, node->dname);
            } else if (rrset->gen.type == DNS_TYPE_SOA) {
                comp_do_soa(&rrset->raw, node->dname);
            } else if (rrset->gen.type == DNS_TYPE_NS) {
                if (comp_do_ns(&rrset->raw, zroot, node->dname, in_deleg))
                    return true;
            }
            // deterministic output size check
            unsigned rsize_resp = rsize_base + rrset->raw.data_len;
            if (rsize_resp > MAX_RESPONSE_DATA)
                log_zfatal("'%s TYPE %u' has too much data (%u > %u)",
                           logf_dname(node->dname), (unsigned)rrset->gen.type,
                           rsize_resp, MAX_RESPONSE_DATA);
        }
        rrset = rrset->gen.next;
    }

    return false;
}

F_WUNUSED F_NONNULL
static bool ltree_postproc_zroot(struct ltree_node* zroot)
{
    union ltree_rrset* zroot_soa = NULL;
    const union ltree_rrset* zroot_ns = NULL;

    union ltree_rrset* rrset = zroot->rrsets;
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
        log_zfatal("Zone '%s' has no SOA record", logf_dname(zroot->dname));
    if (!zroot_ns)
        log_zfatal("Zone '%s' has no NS records", logf_dname(zroot->dname));
    gdnsd_assert(zroot_ns->gen.count);
    if (zroot_ns->gen.count < 2)
        log_zwarn("Zone '%s' only has one NS record, this is (probably) bad practice", logf_dname(zroot->dname));

    // In the probably-rare case that the SOA record wasn't the first data line
    // in the zonefile, re-arrange the rrsets to place it at the beginning, so
    // that we can rely on it being the first rrset at runtime over in
    // dnspacket.c:
    if (unlikely(zroot_soa != zroot->rrsets)) {
        union ltree_rrset* srch = zroot->rrsets;
        while (srch->gen.next != zroot_soa)
            srch = srch->gen.next;
        srch->gen.next = zroot_soa->gen.next;
        zroot_soa->gen.next = zroot->rrsets;
        zroot->rrsets = zroot_soa;
    }
    return false;
}

F_WUNUSED F_NONNULL
static bool ltree_postproc_recurse(struct ltree_node* node, struct ltree_node* zroot, bool in_deleg)
{
    gdnsd_assume(node->dname);

    if (node != zroot && node->zone_cut) {
        if (in_deleg)
            log_zfatal("Delegation '%s' is within another delegation", logf_dname(node->dname));
        in_deleg = true;
    }

    if (unlikely(ltree_postproc_node(node, zroot, in_deleg)))
        return true;

    // Recurse into children
    const uint32_t ccount = node->ccount;
    if (ccount) {
        gdnsd_assume(node->child_table);
        const uint32_t cmask = count2mask_u32_lf80(ccount);
        for (uint32_t i = 0; i <= cmask; i++) {
            struct ltree_node* child = node->child_table[i].node;
            if (child && unlikely(ltree_postproc_recurse(child, zroot, in_deleg)))
                return true;
        }
    }

    return false;
}

F_NONNULL
static void ltree_postproc_recurse_phase2(struct ltree_node* node, struct ltree_node* zroot)
{
    gdnsd_assume(node->dname);

    // Recurse into children and destroy all child nodes of delegation points as we go
    const uint32_t ccount = node->ccount;
    if (ccount) {
        gdnsd_assume(node->child_table);
        const uint32_t cmask = count2mask_u32_lf80(ccount);
        for (uint32_t i = 0; i <= cmask; i++) {
            struct ltree_node* child = node->child_table[i].node;
            if (child) {
                if (node->zone_cut && node != zroot)
                    ltree_destroy(child);
                else
                    ltree_postproc_recurse_phase2(child, zroot);
            }
        }
        if (node->zone_cut && node != zroot) {
            free(node->child_table);
            node->child_table = NULL;
            node->ccount = 0;
        }
    }

    // As we unwind from recursion at a deleg cut, unless we already have a
    // singular NS RRset, delete the excess address rrsets leaving only the NS
    if (node->zone_cut && node != zroot
            && (node->rrsets->gen.type != DNS_TYPE_NS || (node->rrsets->gen.next))) {
        union ltree_rrset* ns = NULL;
        union ltree_rrset* srch = node->rrsets;
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
        node->rrsets = ns;
    }
}

bool ltree_postproc_zone(struct ltree_node* zroot)
{
    if (unlikely(ltree_postproc_zroot(zroot)))
        return true;

    // Recursively process tree nodes breadth-first for things like data sanity
    // checks (e.g. CNAME+X), RHS compression, NS glue attachment, output size
    // checks, etc, etc...
    if (unlikely(ltree_postproc_recurse(zroot, zroot, false)))
        return true;

    // The second recursive phase destroys all nodes and address rrset data
    // beneath delegation points, as their data was already consumed into the
    // appropriate NS RRSets at (possibly different) delegation points, which
    // will now be the only rrset left at delegation nodes.  Cannot fail.
    ltree_postproc_recurse_phase2(zroot, zroot);
    return false;
}

void ltree_destroy(struct ltree_node* node)
{
    union ltree_rrset* rrset = node->rrsets;
    while (rrset) {
        union ltree_rrset* next = rrset->gen.next;
        // Everything is in raw form, except !count dynac entries
        if (rrset->gen.count) {
            if (rrset->raw.data)
                free(rrset->raw.data);
            if (rrset->raw.comp_offsets)
                free(rrset->raw.comp_offsets);
        }
        free(rrset);
        rrset = next;
    }

    if (node->child_table) {
        const uint32_t mask = count2mask_u32_lf80(node->ccount);
        for (uint32_t i = 0; i <= mask; i++)
            if (node->child_table[i].node)
                ltree_destroy(node->child_table[i].node);
        free(node->child_table);
    }
    free(node->dname);
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

    struct ltree_node* new_root_tree = xcalloc(sizeof(*new_root_tree));
    new_root_tree->dname = xmalloc(2U);
    new_root_tree->dname[0] = '\1';
    new_root_tree->dname[1] = '\0';

    // These do not fail if their data directory doesn't exist
    const bool rfc1035_failed = zsrc_rfc1035_load_zones(new_root_tree);

    if (rfc1035_failed) {
        ltree_destroy(new_root_tree);
        rv = 1; // the zsrc already logged why
    } else {
        struct ltree_node* old_root_tree = GRCU_OWN_READ(root_tree);
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

struct ltree_node* ltree_new_zone(const char* zname)
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

    struct ltree_node* zroot = xcalloc(sizeof(*zroot));
    zroot->zone_cut = true;
    zroot->dname = dname_dup(dname);
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

bool ltree_merge_zone(struct ltree_node* new_root_tree, struct ltree_node* zroot)
{
    gdnsd_assume(zroot->dname);
    gdnsd_assume(zroot->zone_cut);
    gdnsd_assume(!new_root_tree->dname[1]); // merge target is global root

    uint8_t lstack_len[127];
    const uint8_t* lstack[127];
    unsigned lcount = dname_to_lstack(zroot->dname, lstack, lstack_len);

    struct ltree_node* n = new_root_tree;
    while (lcount) {
        if (n->zone_cut) {
            log_err("Zone '%s' is a sub-zone of an existing zone", logf_dname(zroot->dname));
            return true;
        }
        lcount--;
        n = ltree_node_find_or_add_child(n, lstack[lcount], lstack_len[lcount]);
        if (unlikely(!n))
            log_zfatal("Too many zones!");
    }

    if (n->zone_cut) {
        log_err("Zone '%s' is a duplicate of an existing zone", logf_dname(zroot->dname));
        return true;
    }

    if (n->ccount) {
        log_err("Zone '%s' is a super-zone of one or more existing zones", logf_dname(zroot->dname));
        return true;
    }
    gdnsd_assume(!n->child_table);
    gdnsd_assume(!n->rrsets);
    gdnsd_assume(n->dname);
    free(n->dname); // to be replaced by the zroot name storage
    memcpy(n, zroot, sizeof(*n));
    free(zroot);
    gdnsd_assume(n->rrsets);
    gdnsd_assume(n->dname);

    // Extract serial just for this log output:
    struct ltree_rrset_raw* zsoa = &n->rrsets->raw;
    gdnsd_assume(zsoa->gen.type == DNS_TYPE_SOA);
    gdnsd_assume(zsoa->data_len >= 36U); // bare min with full compression on mname+rname
    const unsigned serial = ntohl(gdnsd_get_una32(&zsoa->data[zsoa->data_len - 20U]));
    log_info("Zone %s with serial %u loaded", logf_dname(n->dname), serial);

    return false;
}
