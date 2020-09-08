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

#include <gdnsd/alloc.h>
#include <gdnsd/dname.h>
#include <gdnsd/log.h>
#include <gdnsd/misc.h>
#include "plugins/plugapi.h"

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include <urcu-qsbr.h>

// special label used to hide out-of-zone glue
//  inside zone root node child lists
static const uint8_t ooz_glue_label[1] = { 0 };

// initialized to realistic value by ltree_init(), is the total response size
// of all A+AAAA RRs from a DYNA that returns the maximal configured set (of
// all global plugin configurations).
static size_t dyna_max_response = 65536U;

// root_tree is RCU-managed and accessed by reader threads.
ltree_node_t* root_tree = NULL;

// root_arena doesn't need RCU and is local here, but holds strings referenced
// by root_tree, so needs to be deleted after it
static ltarena_t* root_arena = NULL;

#define log_zfatal(...)\
    do {\
        log_err(__VA_ARGS__);\
        return true;\
    } while (0)

#define log_zwarn(...)\
    do {\
        if (gcfg->zones_strict_data) {\
            log_err(__VA_ARGS__);\
            return true;\
        } else {\
            log_warn(__VA_ARGS__);\
        }\
    } while (0);

// don't use this directly, use macro below
// this logs the lstack labels as a partial domainname (possibly empty),
// intended to be completed with the zone name via the macro below
static const char* logf_lstack_labels(const uint8_t** lstack, unsigned depth)
{
    char* dnbuf = gdnsd_fmtbuf_alloc(1024);
    char* dnptr = dnbuf;

    while (depth--) {
        const uint8_t llen = *(lstack[depth]);
        for (unsigned i = 1; i <= llen; i++) {
            char x = (char)lstack[depth][i];
            if (x > 0x20 && x < 0x7F) {
                *dnptr++ = x;
            } else {
                *dnptr++ = '\\';
                *dnptr++ = '0' + (x / 100);
                *dnptr++ = '0' + ((x / 10) % 10);
                *dnptr++ = '0' + (x % 10);
            }
        }
        *dnptr++ = '.';
    }

    *dnptr = '\0';
    return dnbuf;
}

#define logf_lstack(_lstack, _depth, _zdname) \
    logf_lstack_labels(_lstack, _depth), logf_dname(_zdname)

F_NONNULL
static void ltree_node_insert(const ltree_node_t* node, ltree_node_t* child, size_t child_hash, size_t probe_dist, const size_t mask)
{
    do {
        const size_t slot = (child_hash + probe_dist) & mask;
        ltree_hslot* s = &node->child_table[slot];
        if (!s->node) {
            s->node = child;
            s->hash = child_hash;
            break;
        }
        const size_t s_pdist = (slot - s->hash) & mask;
        if (s_pdist < probe_dist) {
            probe_dist = s_pdist;
            ltree_hslot tmp = *s;
            s->hash = child_hash;
            s->node = child;
            child_hash = tmp.hash;
            child = tmp.node;
        }
        probe_dist++;
    } while (1);
}

F_RETNN F_NONNULL
static ltree_node_t* ltree_node_find_or_add_child(ltarena_t* arena, ltree_node_t* node, const uint8_t* child_label)
{
    const size_t ccount = LTN_GET_CCOUNT(node);
    const size_t kh = ltree_hash(child_label);
    size_t mask = count2mask_sz(ccount | 1U);
    size_t probe_dist = 0;
    if (ccount) {
        do {
            const size_t slot = (kh + probe_dist) & mask;
            const ltree_hslot* s = &node->child_table[slot];
            if (!s->node || ((slot - s->hash) & mask) < probe_dist)
                break;
            if (s->hash == kh && likely(!label_cmp(s->node->label, child_label)))
                return s->node;
            probe_dist++;
        } while (1);
    }
    if (!ccount || ccount == mask) {
        const size_t old_mask = ccount ? mask : 0;
        ltree_hslot* old_table = node->child_table;
        mask = (old_mask << 1) + 1;
        node->child_table = xcalloc_n(mask + 1, sizeof(*node->child_table));
        if (old_table) {
            for (size_t i = 0; i <= old_mask; i++)
                if (old_table[i].node)
                    ltree_node_insert(node, old_table[i].node, old_table[i].hash, 0, mask);
            free(old_table);
        }
        probe_dist = 0; // if grow, reset saved distance
    }
    ltree_node_t* ins = xcalloc(sizeof(*ins));
    ins->label = lta_labeldup(arena, child_label);
    ltree_node_insert(node, ins, kh, probe_dist, mask);
    LTN_INC_CCOUNT(node);
    return ins;
}

// "dname" should be an FQDN format-wise, but:
//   (a) Must be in-zone for the given zone
//   (b) Must have the zone portion cut off the end,
//     e.g. for zone "example.com.", the dname normally
//     known as "www.example.com." should be just "www."
F_NONNULL
static ltree_node_t* ltree_find_or_add_dname(const zone_t* zone, const uint8_t* dname)
{
    gdnsd_assert(zone->root);
    gdnsd_assert(dname_status(dname) == DNAME_VALID);

    // Construct a label stack from dname
    const uint8_t* lstack[127];
    unsigned lcount = dname_to_lstack(dname, lstack);

    ltree_node_t* current = zone->root;
    while (lcount--)
        current = ltree_node_find_or_add_child(zone->arena, current, lstack[lcount]);

    return current;
}

#define MK_RRSET_GET(_typ, _dtyp) \
F_NONNULL F_PURE \
static ltree_rrset_ ## _typ ## _t* ltree_node_get_rrset_ ## _typ (const ltree_node_t* node) {\
    ltree_rrset_t* rrsets = node->rrsets;\
    while (rrsets) {\
        if (rrsets->gen.type == _dtyp)\
            return &(rrsets)-> _typ;\
        rrsets = rrsets->gen.next;\
    }\
    return NULL;\
}

MK_RRSET_GET(a, DNS_TYPE_A)
MK_RRSET_GET(aaaa, DNS_TYPE_AAAA)
MK_RRSET_GET(soa, DNS_TYPE_SOA)
MK_RRSET_GET(ns, DNS_TYPE_NS)
MK_RRSET_GET(ptr, DNS_TYPE_PTR)
MK_RRSET_GET(mx, DNS_TYPE_MX)
MK_RRSET_GET(srv, DNS_TYPE_SRV)
MK_RRSET_GET(naptr, DNS_TYPE_NAPTR)
MK_RRSET_GET(txt, DNS_TYPE_TXT)

#define MK_RRSET_ADD(_typ, _dtyp) \
F_NONNULL \
static ltree_rrset_ ## _typ ## _t* ltree_node_add_rrset_ ## _typ (ltree_node_t* node) {\
    ltree_rrset_t** store_at = &node->rrsets;\
    while (*store_at)\
        store_at = &(*store_at)->gen.next;\
    ltree_rrset_ ## _typ ## _t* nrr = xcalloc(sizeof(*nrr));\
    *store_at = (ltree_rrset_t*)nrr;\
    (*store_at)->gen.type = _dtyp;\
    return nrr;\
}

MK_RRSET_ADD(a, DNS_TYPE_A)
MK_RRSET_ADD(aaaa, DNS_TYPE_AAAA)
MK_RRSET_ADD(soa, DNS_TYPE_SOA)
MK_RRSET_ADD(cname, DNS_TYPE_CNAME)
MK_RRSET_ADD(dync, DNS_TYPE_DYNC)
MK_RRSET_ADD(ns, DNS_TYPE_NS)
MK_RRSET_ADD(ptr, DNS_TYPE_PTR)
MK_RRSET_ADD(mx, DNS_TYPE_MX)
MK_RRSET_ADD(srv, DNS_TYPE_SRV)
MK_RRSET_ADD(naptr, DNS_TYPE_NAPTR)
MK_RRSET_ADD(txt, DNS_TYPE_TXT)

// for clamping TTLs in ltree_add_rec_*
static unsigned clamp_ttl(const zone_t* zone, const uint8_t* dname, const char* rrtype, const unsigned ttl)
{
    if (ttl > gcfg->max_ttl) {
        log_zwarn("Name '%s%s': %s TTL %u too large, clamped to max_ttl setting of %u",
                  logf_dname(dname), logf_dname(zone->dname), rrtype, ttl, gcfg->max_ttl);
        return gcfg->max_ttl;
    } else if (ttl < gcfg->min_ttl) {
        log_zwarn("Name '%s%s': %s TTL %u too small, clamped to min_ttl setting of %u",
                  logf_dname(dname), logf_dname(zone->dname), rrtype, ttl, gcfg->min_ttl);
        return gcfg->min_ttl;
    }
    return ttl;
}

bool ltree_add_rec_a(const zone_t* zone, const uint8_t* dname, const uint32_t addr, unsigned ttl, const bool ooz)
{
    ltree_node_t* node;
    if (ooz) {
        log_zwarn("'%s A' in zone '%s': pointless out of zone glue will not be supported in a future version, please delete the record!", logf_dname(dname), logf_dname(zone->dname));
        ltree_node_t* ooz_node = ltree_node_find_or_add_child(zone->arena, zone->root, ooz_glue_label);
        node = ltree_node_find_or_add_child(zone->arena, ooz_node, dname);
    } else {
        node = ltree_find_or_add_dname(zone, dname);
    }

    ttl = clamp_ttl(zone, dname, "A", ttl);

    ltree_rrset_a_t* rrset = ltree_node_get_rrset_a(node);
    if (!rrset) {
        rrset = ltree_node_add_rrset_a(node);
        rrset->gen.count = 1;
        rrset->gen.ttl = htonl(ttl);
        rrset->v4a[0] = addr;
    } else {
        if (!rrset->gen.count) // DYNA here already
            log_zfatal("Name '%s%s': DYNA cannot co-exist at the same name as A", logf_dname(dname), logf_dname(zone->dname));
        if (ntohl(rrset->gen.ttl) != ttl)
            log_zwarn("Name '%s%s': All TTLs for A records at the same name should agree (using %u)", logf_dname(dname), logf_dname(zone->dname), ntohl(rrset->gen.ttl));
        if (rrset->gen.count == UINT16_MAX)
            log_zfatal("Name '%s%s': Too many RRs of type A", logf_dname(dname), logf_dname(zone->dname));

        if (rrset->gen.count <= LTREE_V4A_SIZE) {
            if (rrset->gen.count == LTREE_V4A_SIZE) { // upgrade to addrs, copy old addrs
                uint32_t* new_v4 = xmalloc_n(LTREE_V4A_SIZE + 1, sizeof(*new_v4));
                memcpy(new_v4, rrset->v4a, sizeof(*new_v4) * LTREE_V4A_SIZE);
                new_v4[LTREE_V4A_SIZE] = addr;
                rrset->addrs = new_v4;
                rrset->gen.count = LTREE_V4A_SIZE + 1;
            } else {
                rrset->v4a[rrset->gen.count++] = addr;
            }
        } else {
            rrset->addrs = xrealloc_n(rrset->addrs, 1U + rrset->gen.count, sizeof(*rrset->addrs));
            rrset->addrs[rrset->gen.count++] = addr;
        }
    }

    return false;
}

bool ltree_add_rec_aaaa(const zone_t* zone, const uint8_t* dname, const uint8_t* addr, unsigned ttl, const bool ooz)
{
    ltree_node_t* node;
    if (ooz) {
        log_zwarn("'%s AAAA' in zone '%s': pointless out of zone glue will not be supported in a future version, please delete the record!", logf_dname(dname), logf_dname(zone->dname));
        ltree_node_t* ooz_node = ltree_node_find_or_add_child(zone->arena, zone->root, ooz_glue_label);
        node = ltree_node_find_or_add_child(zone->arena, ooz_node, dname);
    } else {
        node = ltree_find_or_add_dname(zone, dname);
    }

    ttl = clamp_ttl(zone, dname, "AAAA", ttl);

    ltree_rrset_aaaa_t* rrset = ltree_node_get_rrset_aaaa(node);
    if (!rrset) {
        rrset = ltree_node_add_rrset_aaaa(node);
        rrset->addrs = xmalloc(16);
        memcpy(rrset->addrs, addr, 16);
        rrset->gen.count = 1;
        rrset->gen.ttl = htonl(ttl);
    } else {
        if (!rrset->gen.count) // DYNA here already
            log_zfatal("Name '%s%s': DYNA cannot co-exist at the same name as AAAA", logf_dname(dname), logf_dname(zone->dname));
        if (ntohl(rrset->gen.ttl) != ttl)
            log_zwarn("Name '%s%s': All TTLs for AAAA records at the same name should agree (using %u)", logf_dname(dname), logf_dname(zone->dname), ntohl(rrset->gen.ttl));
        if (rrset->gen.count == UINT16_MAX)
            log_zfatal("Name '%s%s': Too many RRs of type AAAA", logf_dname(dname), logf_dname(zone->dname));
        rrset->addrs = xrealloc_n(rrset->addrs, 1U + rrset->gen.count, 16U);
        memcpy(rrset->addrs + (rrset->gen.count++ * 16U), addr, 16U);
    }

    return false;
}

bool ltree_add_rec_dynaddr(const zone_t* zone, const uint8_t* dname, const char* rhs, unsigned ttl, unsigned ttl_min)
{
    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    ltree_rrset_a_t* rrset_a = ltree_node_get_rrset_a(node);
    ltree_rrset_aaaa_t* rrset_aaaa = ltree_node_get_rrset_aaaa(node);
    if (rrset_a || rrset_aaaa) {
        if (rrset_a && rrset_a->gen.count)
            log_zfatal("Name '%s%s': DYNA cannot co-exist at the same name as A", logf_dname(dname), logf_dname(zone->dname));
        if (rrset_aaaa && rrset_aaaa->gen.count)
            log_zfatal("Name '%s%s': DYNA cannot co-exist at the same name as AAAA", logf_dname(dname), logf_dname(zone->dname));
        log_zfatal("Name '%s%s': DYNA defined twice for the same name", logf_dname(dname), logf_dname(zone->dname));
    }

    ttl = clamp_ttl(zone, dname, "DYNA", ttl);

    if (ttl_min < gcfg->min_ttl) {
        log_zwarn("Name '%s%s': DYNA Min-TTL /%u too small, clamped to min_ttl setting of %u", logf_dname(dname), logf_dname(zone->dname), ttl_min, gcfg->min_ttl);
        ttl_min = gcfg->min_ttl;
    }
    if (ttl_min > ttl) {
        log_zwarn("Name '%s%s': DYNA Min-TTL /%u larger than Max-TTL %u, clamping to Max-TTL", logf_dname(dname), logf_dname(zone->dname), ttl_min, ttl);
        ttl_min = ttl;
    }

    rrset_a = ltree_node_add_rrset_a(node);
    rrset_a->gen.ttl = htonl(ttl);
    rrset_a->dyn.ttl_min = ttl_min;
    rrset_a->dyn.resource = 0;
    rrset_aaaa = ltree_node_add_rrset_aaaa(node);
    rrset_aaaa->gen.ttl = htonl(ttl);
    rrset_aaaa->dyn.ttl_min = ttl_min;
    rrset_aaaa->dyn.resource = 0;

    const unsigned rhs_size = strlen(rhs) + 1;
    if (rhs_size > 256)
        log_zfatal("Name '%s%s': DYNA plugin!resource string cannot exceed 255 chars", logf_dname(dname), logf_dname(zone->dname));
    char plugin_name[256];
    memcpy(plugin_name, rhs, rhs_size);
    char* resource_name = strchr(plugin_name, '!');
    if (resource_name)
        *resource_name++ = '\0';

    const plugin_t* const p = gdnsd_plugin_find(plugin_name);
    if (likely(p)) {
        if (!p->resolve)
            log_zfatal("Name '%s%s': DYNA RR refers to a non-resolver plugin", logf_dname(dname), logf_dname(zone->dname));
        rrset_a->dyn.func = p->resolve;
        rrset_aaaa->dyn.func = p->resolve;
        if (p->map_res) {
            const int res = p->map_res(resource_name, NULL);
            if (res < 0)
                log_zfatal("Name '%s%s': resolver plugin '%s' rejected resource name '%s'", logf_dname(dname), logf_dname(zone->dname), plugin_name, resource_name);
            rrset_a->dyn.resource = (unsigned)res;
            rrset_aaaa->dyn.resource = (unsigned)res;
        }
        return false;
    }

    log_zfatal("Name '%s%s': DYNA RR refers to plugin '%s', which is not loaded", logf_dname(dname), logf_dname(zone->dname), plugin_name);
}

bool ltree_add_rec_cname(const zone_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl)
{
    ttl = clamp_ttl(zone, dname, "CNAME", ttl);

    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);
    if (node->rrsets)
        log_zfatal("Name '%s%s': CNAME not allowed alongside other data", logf_dname(dname), logf_dname(zone->dname));
    ltree_rrset_cname_t* rrset = ltree_node_add_rrset_cname(node);
    rrset->dname = lta_dnamedup(zone->arena, rhs);
    rrset->gen.ttl = htonl(ttl);
    rrset->gen.count = 1;

    return false;
}

bool ltree_add_rec_dync(const zone_t* zone, const uint8_t* dname, const char* rhs, unsigned ttl, unsigned ttl_min)
{
    ttl = clamp_ttl(zone, dname, "DYNC", ttl);

    if (ttl_min < gcfg->min_ttl) {
        log_zwarn("Name '%s%s': DYNC Min-TTL /%u too small, clamped to min_ttl setting of %u", logf_dname(dname), logf_dname(zone->dname), ttl_min, gcfg->min_ttl);
        ttl_min = gcfg->min_ttl;
    }
    if (ttl_min > ttl) {
        log_zwarn("Name '%s%s': DYNC Min-TTL /%u larger than Max-TTL %u, clamping to Max-TTL", logf_dname(dname), logf_dname(zone->dname), ttl_min, ttl);
        ttl_min = ttl;
    }

    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);
    if (node->rrsets)
        log_zfatal("Name '%s%s': DYNC not allowed alongside other data", logf_dname(dname), logf_dname(zone->dname));
    ltree_rrset_dync_t* rrset = ltree_node_add_rrset_dync(node);
    rrset->gen.ttl = htonl(ttl);
    rrset->ttl_min = ttl_min;

    const unsigned rhs_size = strlen(rhs) + 1;
    if (rhs_size > 256)
        log_zfatal("Name '%s%s': DYNC plugin!resource string cannot exceed 255 chars", logf_dname(dname), logf_dname(zone->dname));
    char plugin_name[256];
    memcpy(plugin_name, rhs, rhs_size);
    char* resource_name = strchr(plugin_name, '!');
    if (resource_name)
        *resource_name++ = '\0';

    const plugin_t* const p = gdnsd_plugin_find(plugin_name);
    if (!p)
        log_zfatal("Name '%s%s': DYNC refers to plugin '%s', which is not loaded", logf_dname(dname), logf_dname(zone->dname), plugin_name);
    if (!p->resolve)
        log_zfatal("Name '%s%s': DYNC RR refers to a non-resolver plugin", logf_dname(dname), logf_dname(zone->dname));
    rrset->func = p->resolve;

    rrset->resource = 0;
    if (p->map_res) {
        const int res = p->map_res(resource_name, zone->dname);
        if (res < 0)
            log_zfatal("Name '%s%s': plugin '%s' rejected DYNC resource '%s'", logf_dname(dname), logf_dname(zone->dname), plugin_name, resource_name);
        rrset->resource = (unsigned)res;
    }

    return false;
}

// It's like C++ templating, but sadly even uglier ...
//  This macro assumes "ltree_node_t* node" and "uint8_t* dname" in
//  the current context, and creates "rrset" and "new_rdata" of
//  the appropriate types
// _szassume is a size assumption.  If we expect 2+ to be the common
//  case for the rrset's count, set it to 2, otherwise 1.
#define INSERT_NEXT_RR(_typ, _nam, _pnam, _szassume) \
    ltree_rdata_ ## _typ ## _t* new_rdata;\
    ltree_rrset_ ## _typ ## _t* rrset = ltree_node_get_rrset_ ## _nam (node);\
{\
    if (!rrset) {\
        rrset = ltree_node_add_rrset_ ## _nam (node);\
        rrset->gen.count = 1;\
        rrset->gen.ttl = htonl(ttl);\
        new_rdata = rrset->rdata = xmalloc_n(_szassume, sizeof(*new_rdata));\
    } else {\
        if (ntohl(rrset->gen.ttl) != ttl)\
            log_zwarn("Name '%s%s': All TTLs for type %s should match (using %u)", logf_dname(dname), logf_dname(zone->dname), _pnam, ntohl(rrset->gen.ttl));\
        if (rrset->gen.count == UINT16_MAX)\
            log_zfatal("Name '%s%s': Too many RRs of type %s", logf_dname(dname), logf_dname(zone->dname), _pnam);\
        if (_szassume == 1 || rrset->gen.count >= _szassume) \
            rrset->rdata = xrealloc_n(rrset->rdata, 1U + rrset->gen.count, sizeof(*rrset->rdata));\
        new_rdata = &rrset->rdata[rrset->gen.count++];\
    }\
}

bool ltree_add_rec_ptr(const zone_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl)
{
    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    ttl = clamp_ttl(zone, dname, "PTR", ttl);
    INSERT_NEXT_RR(ptr, ptr, "PTR", 1);
    *new_rdata = lta_dnamedup(zone->arena, rhs);
    if (dname_isinzone(zone->dname, rhs))
        log_zwarn("Name '%s%s': PTR record points to same-zone name '%s', which is usually a mistake (missing terminal dot?)", logf_dname(dname), logf_dname(zone->dname), logf_dname(rhs));
    return false;
}

bool ltree_add_rec_ns(const zone_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl)
{
    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    // If this is a delegation by definition, (NS rec not at zone root), flag it
    //   and check for wildcard.
    if (node != zone->root) {
        LTN_SET_FLAG_ZCUT(node);
        if (node->label[0] == 1 && node->label[1] == '*')
            log_zfatal("Name '%s%s': Cannot delegate via wildcards", logf_dname(dname), logf_dname(zone->dname));
    }

    ttl = clamp_ttl(zone, dname, "NS", ttl);
    INSERT_NEXT_RR(ns, ns, "NS", 2)
    if (rrset->gen.count > MAX_NS_COUNT)
        log_zfatal("Name '%s%s': Too many NS records in one NS RRset (%u > %u)", logf_dname(dname), logf_dname(zone->dname), rrset->gen.count, MAX_NS_COUNT);
    new_rdata->dname = lta_dnamedup(zone->arena, rhs);
    new_rdata->glue_v4 = NULL;
    new_rdata->glue_v6 = NULL;
    return false;
}

bool ltree_add_rec_mx(const zone_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl, const unsigned pref)
{
    if (pref > 65535U)
        log_zfatal("Name '%s%s': MX preference value %u too large", logf_dname(dname), logf_dname(zone->dname), pref);

    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    ttl = clamp_ttl(zone, dname, "MX", ttl);
    INSERT_NEXT_RR(mx, mx, "MX", 2)
    new_rdata->dname = lta_dnamedup(zone->arena, rhs);
    new_rdata->pref = htons(pref);
    return false;
}

bool ltree_add_rec_srv_args(const zone_t* zone, const uint8_t* dname, lt_srv_args args)
{
    if (args.priority > 65535U)
        log_zfatal("Name '%s%s': SRV priority value %u too large", logf_dname(dname), logf_dname(zone->dname), args.priority);
    if (args.weight > 65535U)
        log_zfatal("Name '%s%s': SRV weight value %u too large", logf_dname(dname), logf_dname(zone->dname), args.weight);
    if (args.port > 65535U)
        log_zfatal("Name '%s%s': SRV port value %u too large", logf_dname(dname), logf_dname(zone->dname), args.port);

    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    const unsigned ttl = clamp_ttl(zone, dname, "SRV", args.ttl);
    INSERT_NEXT_RR(srv, srv, "SRV", 1)
    new_rdata->dname = lta_dnamedup(zone->arena, args.rhs);
    new_rdata->priority = htons(args.priority);
    new_rdata->weight = htons(args.weight);
    new_rdata->port = htons(args.port);
    return false;
}

bool ltree_add_rec_naptr_args(const zone_t* zone, const uint8_t* dname, lt_naptr_args args)
{
    if (args.order > 65535U)
        log_zfatal("Name '%s%s': NAPTR order value %u too large", logf_dname(dname), logf_dname(zone->dname), args.order);
    if (args.pref > 65535U)
        log_zfatal("Name '%s%s': NAPTR preference value %u too large", logf_dname(dname), logf_dname(zone->dname), args.pref);

    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    const unsigned ttl = clamp_ttl(zone, dname, "NAPTR", args.ttl);
    INSERT_NEXT_RR(naptr, naptr, "NAPTR", 1)
    new_rdata->dname = lta_dnamedup(zone->arena, args.rhs);
    new_rdata->order = htons(args.order);
    new_rdata->pref = htons(args.pref);
    new_rdata->text_len = args.text_len;
    new_rdata->text = args.text;
    return false;
}

bool ltree_add_rec_txt(const zone_t* zone, const uint8_t* dname, const unsigned text_len, uint8_t* text, unsigned ttl)
{

    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    // RFC 2181 disallows mixed TTLs within a single RR-set, so to avoid other
    // runtime complexity we choose to set all static _acme-challenge TXT
    // record TTLs to the same value configured for dynamic ones injected by
    // gdnsdctl, which is controlled by the config setting
    // acme_challenge_dns_ttl, defaulting to zero.  Note also that in this
    // case, no clamping to min_ttl applies (it's impossible for max_ttl to
    // conflict with acme_challenge_dns_ttl due to their limits).

    if (dname_is_acme_chal(dname) && ttl != gcfg->acme_challenge_dns_ttl) {
        log_zwarn("Name '%s%s': ACME challenge TXT record TTL %u overriden to %u from 'acme_challenge_dns_ttl' config setting", logf_dname(dname), logf_dname(zone->dname), ttl, gcfg->acme_challenge_dns_ttl);
        ttl = gcfg->acme_challenge_dns_ttl;
    } else {
        ttl = clamp_ttl(zone, dname, "TXT", ttl);
    }

    INSERT_NEXT_RR(txt, txt, "TXT", 1)
    new_rdata->text_len = text_len;
    new_rdata->text = text;
    return false;
}

bool ltree_add_rec_soa_args(const zone_t* zone, const uint8_t* dname, lt_soa_args args)
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

    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    // Parsers only allow SOA at zone root
    gdnsd_assert(zone->root == node);

    if (ltree_node_get_rrset_soa(node))
        log_zfatal("Zone '%s': SOA defined twice", logf_dname(dname));

    ltree_rrset_soa_t* soa = ltree_node_add_rrset_soa(node);
    soa->email = lta_dnamedup(zone->arena, args.email);
    soa->master = lta_dnamedup(zone->arena, args.master);

    soa->gen.ttl = htonl(args.ttl);
    soa->times[0] = htonl(args.serial);
    soa->times[1] = htonl(args.refresh);
    soa->times[2] = htonl(args.retry);
    soa->times[3] = htonl(args.expire);
    soa->times[4] = htonl(args.ncache);

    return false;
}

// It is critical that get/add_rrset_rfc3597 are not called with
//  rrtype set to the number of other known, explicitly supported types...
F_NONNULL F_PURE
static ltree_rrset_rfc3597_t* ltree_node_get_rrset_rfc3597(const ltree_node_t* node, const unsigned rrtype)
{
    ltree_rrset_t* rrsets = node->rrsets;
    while (rrsets) {
        if (rrsets->gen.type == rrtype)
            return &(rrsets)->rfc3597;
        rrsets = rrsets->gen.next;
    }
    return NULL;
}

F_NONNULL
static ltree_rrset_rfc3597_t* ltree_node_add_rrset_rfc3597(ltree_node_t* node, const unsigned rrtype)
{
    ltree_rrset_t** store_at = &node->rrsets;
    while (*store_at)
        store_at = &(*store_at)->gen.next;
    ltree_rrset_rfc3597_t* nrr = xcalloc(sizeof(*nrr));
    *store_at = (ltree_rrset_t*)nrr;
    (*store_at)->gen.type = rrtype;
    return nrr;
}

bool ltree_add_rec_rfc3597(const zone_t* zone, const uint8_t* dname, const unsigned rrtype, unsigned ttl, const unsigned rdlen, uint8_t* rd)
{
    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

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
        log_zfatal("Name '%s%s': RFC3597 TYPE%u not allowed, please use the explicit support built in for this RR type", logf_dname(dname), logf_dname(zone->dname), rrtype);

    if (rrtype == DNS_TYPE_HINFO
            || rrtype == DNS_TYPE_DYNC
            || (rrtype > 127 && rrtype < 256)
            || rrtype == 0)
        log_zfatal("Name '%s%s': RFC3597 TYPE%u not allowed", logf_dname(dname), logf_dname(zone->dname), rrtype);

    ltree_rrset_rfc3597_t* rrset = ltree_node_get_rrset_rfc3597(node, rrtype);

    ltree_rdata_rfc3597_t* new_rdata;

    if (!rrset) {
        rrset = ltree_node_add_rrset_rfc3597(node, rrtype);
        rrset->gen.count = 1;
        rrset->gen.ttl = htonl(ttl);
        new_rdata = rrset->rdata = xmalloc(sizeof(*new_rdata));
    } else {
        if (ntohl(rrset->gen.ttl) != ttl)
            log_zwarn("Name '%s%s': All TTLs for type RFC3597 TYPE%u should match (using %u)", logf_dname(dname), logf_dname(zone->dname), rrtype, ntohl(rrset->gen.ttl));
        if (rrset->gen.count == UINT16_MAX)
            log_zfatal("Name '%s%s': Too many RFC3597 RRs of type TYPE%u", logf_dname(dname), logf_dname(zone->dname), rrtype);
        rrset->rdata = xrealloc_n(rrset->rdata, 1U + rrset->gen.count, sizeof(*rrset->rdata));
        new_rdata = &rrset->rdata[rrset->gen.count++];
    }

    new_rdata->rdlen = rdlen;
    new_rdata->rd = rd;
    return false;
}

F_NONNULLX(1, 2, 3)
static ltree_dname_status_t ltree_search_dname_zone(const uint8_t* dname, const zone_t* zone, ltree_node_t** node_out, ltree_node_t** deleg_out)
{
    gdnsd_assert(*dname != 0);
    gdnsd_assert(*dname != 2); // these are always illegal dnames

    ltree_dname_status_t rval = DNAME_NOAUTH;
    ltree_node_t* rv_node = NULL;
    if (dname_isinzone(zone->dname, dname)) {
        rval = DNAME_AUTH;
        uint8_t local_dname[256];
        gdnsd_dname_copy(local_dname, dname);
        gdnsd_dname_drop_zone(local_dname, zone->dname);

        // construct label ptr stack
        const uint8_t* lstack[127];
        unsigned lcount = dname_to_lstack(local_dname, lstack);

        ltree_node_t* current = zone->root;
        gdnsd_assert(zone->root);

        while (!rv_node && current) {
            if (LTN_GET_FLAG_ZCUT(current) && current != zone->root) {
                rval = DNAME_DELEG;
                if (deleg_out)
                    *deleg_out = current;
            }

            if (!lcount) {
                // exact match of full label count
                rv_node = current;
            } else {
                lcount--;
                const uint8_t* child_label = lstack[lcount];
                ltree_node_t* next = ltree_node_find_child(current, child_label);
                // If in auth space and no deeper match, try wildcard
                if (!next && rval == DNAME_AUTH) {
                    static const uint8_t label_wild[2] =  { '\001', '*' };
                    rv_node = ltree_node_find_child(current, label_wild);
                }
                current = next;
            }
        }
    }

    *node_out = rv_node;
    return rval;
}

// retval: true, all is well
//         false, the target points at an authoritative name in the same zone which doesn't exist
F_NONNULL
static bool check_valid_addr(const uint8_t* dname, const zone_t* zone)
{
    gdnsd_assert(*dname);

    ltree_node_t* node;
    const ltree_dname_status_t status = ltree_search_dname_zone(dname, zone, &node, NULL);
    if (status == DNAME_AUTH && (!node || (!ltree_node_get_rrset_a(node) && !ltree_node_get_rrset_aaaa(node))))
        return false;

    return true;
}

// Phase 1 check of ltree after all records added:
// Walks the entire ltree, sanity-checking very basic things.

// Note p1_proc_ns is idempotent (other than the zfatal cases, which would
// terminate loading the zone anyways), in that it will only re-check the same
// data, re-set the same ->glue and GUSED flag, etc.  This is important,
// because the phase1 check can call it more than once on a given NS record,
// because it has to do this before checking a CNAME-into-delegation, and it
// can't known if it was yet done by the rest of the ltree walk or not.
F_WUNUSED F_NONNULL
static bool p1_proc_ns(const zone_t* zone, const bool in_deleg, ltree_rdata_ns_t* this_ns, const uint8_t** lstack, const unsigned depth)
{
    ltree_node_t* ns_target = NULL;
    ltree_dname_status_t target_status = ltree_search_dname_zone(this_ns->dname, zone, &ns_target, NULL);

    ltree_rrset_a_t* target_a = NULL;
    ltree_rrset_aaaa_t* target_aaaa = NULL;

    // if NOAUTH, look for explicit out-of-zone glue
    if (target_status == DNAME_NOAUTH) {
        gdnsd_assert(!ns_target);
        const ltree_node_t* ooz = ltree_node_find_child(zone->root, ooz_glue_label);
        if (ooz)
            ns_target = ltree_node_find_child(ooz, this_ns->dname);
    }

    if (ns_target) {
        target_a = ltree_node_get_rrset_a(ns_target);
        target_aaaa = ltree_node_get_rrset_aaaa(ns_target);
    }

    if (target_status != DNAME_NOAUTH) {
        // if !NOAUTH, target must be in auth or deleg space for this
        //   same zone, and we *must* have a legal address for it
        if (!target_a && !target_aaaa)
            log_zfatal("Missing A and/or AAAA records for target nameserver in '%s%s NS %s'",
                       logf_lstack(lstack, depth, zone->dname), logf_dname(this_ns->dname));
        // Explicitly disallowing NS->DYNA avoids a number of pitfalls.  Most
        // importantly, it evades the question-marks around practices with this
        // in RFC7871, but also it makes delegation max response sizes much
        // more predictable, and they're otherwise our worst-case scenario for
        // predicting overlong responses.
        if ((target_a && !target_a->gen.count) || (target_aaaa && !target_aaaa->gen.count))
            log_zfatal("Target nameserver in '%s%s NS %s' cannot have DYNA addresses",
                       logf_lstack(lstack, depth, zone->dname), logf_dname(this_ns->dname));
    }

    // use target_addr found via either path above, if it's OOZ glue or
    // deleg-space glue and this is a delegation.  If someone happens to put
    // their zone root nameservers in deleg space or define OOZ glue for them,
    // we're not going to help with that (and it's not going to help anyways,
    // it's the delegator above them that needs to emit that glue in the OOZ
    // case, and the delegated-NS case is just nuts...).
    if ((target_a || target_aaaa) && target_status != DNAME_AUTH && in_deleg) {
        gdnsd_assert(ns_target);
        this_ns->glue_v4 = target_a;
        this_ns->glue_v6 = target_aaaa;
        LTN_SET_FLAG_GUSED(ns_target);
    }

    return false;
}

// p1_rrset_size() does response sizing
//
// Size checking is for whether this node can generate oversized (>16K)
// responses.  The dns processing code uses fixed 16K buffers for output
// packets and assumes (e.g.  in compression-related code, where that cutoff
// comes into play) that no packet data can possibly exist at offsets >= 16384.
//
// In general, the method here is to find the largest single rrset defined in
// the node.  We also have to add on various fixed quantities to account for
// headers, the query, and maximal edns option outputs.  In delegation and
// wildcard cases, we also have to assume the query name consumed the full 255
// byte maximum.  When checking delegation NS RR-sets we also have to account
// for their glued address data in the additional section.
//
// Note that this check is more conservative than it has to be, because making
// some parts more precise is complicated:
//
// * It doesn't consider the savings from arbitrary heuristic compression of
// right-hand-side domainnames of RR-sets (e.g. compression of mail server
// hostnames on the right side of an MX RR-set against the query name or each
// other, or the right side of a CNAME as part of a chain), even though the
// runtime code does attempt to save space with such compression.  It does
// assume the obvious easy compression of left-hand-side names against the
// query name or the zone name within it.  We could run a real query using the
// runtime compression code as a final check before rejecting a node for being
// too big, but for now I'm voting to avoid that complexity unless someone
// using data big enough to matter complains.
//
// * In the case of addresses from DYNA RR sets, they're all counted as if they
// always emit the maximum recorded address counts possible from any DYNA
// (which is globally tracked during config parsing at startup), even if a
// given particular node's DYNA would never return that full amount.
//
// Note: The fixed part on the left of the RRs is counted as 12 bytes: 2 for
// compressed LHS name, 2 type, 2 class, 4 ttl, 2 rdlen

F_WUNUSED F_NONNULL
static size_t p1_rrset_size_ns(const ltree_rrset_t* rrset)
{
    gdnsd_assert(rrset->gen.type == DNS_TYPE_NS);
    size_t set_size = 0;
    for (unsigned i = 0; i < rrset->gen.count; i++) {
        set_size += (12U + *rrset->ns.rdata[i].dname);
        if (rrset->ns.rdata[i].glue_v4)
            set_size += rrset->ns.rdata[i].glue_v4->gen.count * (12U + 4U);
        if (rrset->ns.rdata[i].glue_v6)
            set_size += rrset->ns.rdata[i].glue_v6->gen.count * (12U + 16U);
    }
    return set_size;
}

F_WUNUSED F_NONNULL
static size_t p1_rrset_size(const ltree_rrset_t* rrset, const bool in_deleg)
{
    size_t set_size = 0;

    switch (rrset->gen.type) {
    case DNS_TYPE_SOA:
        set_size = (12U + *rrset->soa.master + *rrset->soa.email + 20U);
        break;
    case DNS_TYPE_CNAME:
        gdnsd_assert(0);
        break;
    case DNS_TYPE_DYNC:
        set_size = (12U + 255U);
        break;
    case DNS_TYPE_A:
        // Inside delegation cuts, we avoid counting up addresses.  They're
        // only glue addresses, and they'll be counted with any delegation
        // NS sets that reference them (possibly even the one at this node,
        // which would be redundant if we counted them here)
        if (rrset->gen.count) {
            if (!in_deleg)
                set_size = rrset->gen.count * (12U + 4U);
        } else {
            // These could be in_deleg as well, but they'll either be
            // unused glue or they'll fail the zone when a cut refs them
            set_size = dyna_max_response;
        }
        break;
    case DNS_TYPE_AAAA:
        // Exactly as above for AAAA
        if (rrset->gen.count) {
            if (!in_deleg)
                set_size = rrset->gen.count * (12U + 16U);
        } else {
            set_size = dyna_max_response;
        }
        break;
    case DNS_TYPE_NS:
        set_size = p1_rrset_size_ns(rrset);
        break;
    case DNS_TYPE_PTR:
        for (unsigned i = 0; i < rrset->gen.count; i++)
            set_size += (12U + *rrset->ptr.rdata[i]);
        break;
    case DNS_TYPE_MX:
        for (unsigned i = 0; i < rrset->gen.count; i++)
            set_size += (12U + 2U + *rrset->mx.rdata[i].dname);
        break;
    case DNS_TYPE_SRV:
        for (unsigned i = 0; i < rrset->gen.count; i++)
            set_size += (12U + 2U + 2U + 2U + *rrset->srv.rdata[i].dname);
        break;
    case DNS_TYPE_NAPTR:
        for (unsigned i = 0; i < rrset->gen.count; i++)
            set_size += (12U + 2U + 2U + rrset->naptr.rdata[i].text_len + *rrset->naptr.rdata[i].dname);
        break;
    case DNS_TYPE_TXT:
        for (unsigned i = 0; i < rrset->gen.count; i++)
            set_size += (12U + rrset->txt.rdata[i].text_len);
        break;
    default:
        for (unsigned i = 0; i < rrset->gen.count; i++)
            set_size += (12U + rrset->rfc3597.rdata[i].rdlen);
        break;
    }

    return set_size;
}

F_WUNUSED F_NONNULL
static bool p1_check_deleg(const uint8_t** lstack, const ltree_node_t* node, const zone_t* zone, const unsigned depth, const bool in_deleg, const bool at_deleg)
{
    if (in_deleg) {
        gdnsd_assert(depth > 0);
        if (lstack[depth - 1][0] == 1 && lstack[depth - 1][1] == '*')
            log_zfatal("Domainname '%s%s': Wildcards not allowed for delegation/glue data",
                       logf_lstack(lstack, depth, zone->dname));

        const ltree_rrset_t* rrset_dchk = node->rrsets;
        while (rrset_dchk) {
            if (!(rrset_dchk->gen.type == DNS_TYPE_A || rrset_dchk->gen.type == DNS_TYPE_AAAA || (rrset_dchk->gen.type == DNS_TYPE_NS && at_deleg)))
                log_zfatal("Domainname '%s%s' is inside a delegated subzone, and can only have NS and/or address records as appropriate",
                           logf_lstack(lstack, depth, zone->dname));
            rrset_dchk = rrset_dchk->gen.next;
        }
    }

    return false;
}

F_WUNUSED F_NONNULL
static size_t p1_rsize_base(const uint8_t** lstack, const ltree_node_t* node, const zone_t* zone, const unsigned depth, const bool at_deleg)
{
    // First, the fixed portions:
    // sizeof(wire_dns_header_t): basic header bytes before query
    // 4U: the fixed parts of the query (qtype and qclass)
    // 11U: edns OPT RR with no options
    // 6U: edns tcp-keepalive response
    size_t rsize = sizeof(wire_dns_header_t) + 4U + 11U + 6U;

    // 24U: edns edns-client-subnet option at max response length (full ipv6 bytes)
    if (gcfg->edns_client_subnet)
        rsize += 24U;

    // Optional NSID if configured (4U is 2 bytes optcode + 2 bytes datalen)
    if (gcfg->nsid.len)
        rsize += (4U + gcfg->nsid.len);

    // EDNS cookies (our output is fixed 8 byte server cookies)
    if (!gcfg->disable_cookies)
        rsize += 20U;

    // QNAME:
    // For delegations and wildcards, assume maximum possible matching qname
    // for others, use the exact matching query name length
    if (at_deleg || (node->label && node->label[0] == 1 && node->label[1] == '*')) {
        rsize += 255U;
    } else {
        rsize += *zone->dname;
        unsigned depwalk = depth;
        while (depwalk--)
            rsize += (1U + *lstack[depwalk]);
    }

    return rsize;
}

F_NONNULL
static bool p1_check_cname(const uint8_t** lstack, const ltree_node_t* node, const zone_t* zone, const unsigned depth)
{
    const ltree_rrset_t* rrset = node->rrsets;
    if (rrset && rrset->gen.next) {
        if (rrset->gen.type == DNS_TYPE_CNAME)
            log_zfatal("Name '%s%s': CNAME not allowed alongside other data",
                       logf_lstack(lstack, depth, zone->dname));
        if (rrset->gen.type == DNS_TYPE_DYNC)
            log_zfatal("Name '%s%s': DYNC not allowed alongside other data",
                       logf_lstack(lstack, depth, zone->dname));
    }
    return false;
}

F_WUNUSED F_NONNULL
static bool p1_chase_cname(const ltree_rrset_t** rrset_p, size_t* rsize_rrs_p, size_t* rsize_p, const uint8_t** lstack, const zone_t* zone, const unsigned depth)
{
    const ltree_rrset_t* rrset = *rrset_p;
    gdnsd_assert(rrset);
    gdnsd_assert(rrset->gen.type == DNS_TYPE_CNAME);

    const ltree_rrset_cname_t* node_cname = &rrset->cname;
    ltree_node_t* cn_target = NULL;
    ltree_node_t* deleg_cut = NULL;
    ltree_dname_status_t cnstat = ltree_search_dname_zone(node_cname->dname, zone, &cn_target, &deleg_cut);

    if (cnstat == DNAME_AUTH) {
        if (!cn_target) {
            log_zwarn("CNAME '%s%s' points to known same-zone NXDOMAIN '%s'",
                      logf_lstack(lstack, depth, zone->dname), logf_dname(node_cname->dname));
        } else if (!cn_target->rrsets) {
            log_zwarn("CNAME '%s%s' points to '%s' in the same zone, which has no data",
                      logf_lstack(lstack, depth, zone->dname), logf_dname(node_cname->dname));
        }
    }

    // Add the output size for the initial CNAME
    *rsize_p += (12U + *node_cname->dname);

    // Chase further local CNAME->CNAME chains, adding sizes for them and checking max depth
    unsigned cn_depth = 1;
    while (cn_target && cnstat == DNAME_AUTH && cn_target->rrsets && cn_target->rrsets->gen.type == DNS_TYPE_CNAME) {
        if (++cn_depth > MAX_CNAME_DEPTH) {
            log_zfatal("CNAME '%s%s' leads to a CNAME chain at least %u RRs deep, assuming infinity or insanity and failing",
                       logf_lstack(lstack, depth, zone->dname), MAX_CNAME_DEPTH);
            break;
        }
        node_cname = &cn_target->rrsets->cname;
        *rsize_p += (12U + *node_cname->dname);
        cnstat = ltree_search_dname_zone(node_cname->dname, zone, &cn_target, &deleg_cut);
    }

    rrset = NULL; // we've processed the CNAME (+any chained ones), don't process it below

    if (cnstat == DNAME_AUTH) {
        // If the end of the CNAME chain pointed in auth space, we'll
        // need to add on space for the maximum possible rr-set from the
        // defined ones (with the zone soa as part of the max calc, for
        // negative responses, which are always possible):
        if (cn_target && cn_target->rrsets)
            rrset = cn_target->rrsets;
        const ltree_rrset_soa_t* soa = ltree_node_get_rrset_soa(zone->root);
        gdnsd_assert(soa); // checked in zroot phase1
        // Put zone-level soa into the max rrset calc:
        *rsize_rrs_p += (12U + *soa->master + *soa->email + 20U);
    } else if (cnstat == DNAME_DELEG) {
        // Size the delegation response below
        gdnsd_assert(deleg_cut && deleg_cut->rrsets);
        rrset = deleg_cut->rrsets;
    }

    *rrset_p = rrset;
    return false;
}

F_WUNUSED F_NONNULL
static bool p1_check_mx_srv(const ltree_rrset_t* rrset, const uint8_t** lstack, const zone_t* zone, const unsigned depth)
{
    if (rrset->gen.type == DNS_TYPE_MX)
        for (unsigned i = 0; i < rrset->gen.count; i++)
            if (!check_valid_addr(rrset->mx.rdata[i].dname, zone))
                log_zwarn("In rrset '%s%s MX', same-zone target '%s' has no addresses",
                          logf_lstack(lstack, depth, zone->dname),
                          logf_dname(rrset->mx.rdata[i].dname));
    if (rrset->gen.type == DNS_TYPE_SRV)
        for (unsigned i = 0; i < rrset->gen.count; i++)
            if (!check_valid_addr(rrset->srv.rdata[i].dname, zone))
                log_zwarn("In rrset '%s%s SRV', same-zone target '%s' has no addresses",
                          logf_lstack(lstack, depth, zone->dname),
                          logf_dname(rrset->srv.rdata[i].dname));

    return false;
}

F_WUNUSED F_NONNULL
static bool ltree_postproc_phase1(const uint8_t** lstack, const ltree_node_t* node, const zone_t* zone, const unsigned depth, const bool in_deleg)
{
    const bool at_deleg = LTN_GET_FLAG_ZCUT(node) && node != zone->root;

    if (p1_check_deleg(lstack, node, zone, depth, in_deleg, at_deleg))
        return true;

    // Base size for the query itself and applicable EDNS options
    size_t rsize = p1_rsize_base(lstack, node, zone, depth, at_deleg);

    // Check for CNAME/DYNC not having other types tacked on after they were added
    if (p1_check_cname(lstack, node, zone, depth))
        return true;

    // Whether the checks at the bottom are via-cname or direct
    bool via_cname = false;

    // This tracks either the sum or the maximum of the RRs down below and is
    // later added to rsize, which tracks amounts that only sum
    size_t rsize_rrs = 0;

    const ltree_rrset_t* rrset = node->rrsets;

    // CNAME handling, which can change "rrset" to point at the final destination of an in-zone chain
    if (rrset && rrset->gen.type == DNS_TYPE_CNAME) {
        via_cname = true;
        if (p1_chase_cname(&rrset, &rsize_rrs, &rsize, lstack, zone, depth))
            return true;
    }

    // Iterate the rrsets of the target node and either max or sum their sizes
    // into rsize_rrs as appropriate (max if chained into here via CNAME, sum
    // for ANY otherwise).
    while (rrset) {
        // Check NS->A and set glue (which is needed for sizing below)
        if (rrset->gen.type == DNS_TYPE_NS)
            for (unsigned i = 0; i < rrset->gen.count; i++)
                if (p1_proc_ns(zone, in_deleg, &(rrset->ns.rdata[i]), lstack, depth))
                    return true;

        // Only check MX/SRV targets when !via_cname, so we don't warn about
        // them multiple times each:
        if (!via_cname && p1_check_mx_srv(rrset, lstack, zone, depth))
            return true;

        const size_t set_size = p1_rrset_size(rrset, in_deleg);
        if (set_size > rsize_rrs)
            rsize_rrs = set_size;
        rrset = rrset->gen.next;
    }

    rsize += rsize_rrs;
    if (rsize > MAX_RESPONSE_DATA)
        log_zfatal("Domainname '%s%s' has too much data (%zu > %u)",
                   logf_lstack(lstack, depth, zone->dname), rsize, MAX_RESPONSE_DATA);

    return false;
}

// Phase 2:
//  Checks on unused glue RRs underneath delegations
F_WUNUSED F_NONNULL
static bool ltree_postproc_phase2(const uint8_t** lstack, const ltree_node_t* node, const zone_t* zone, const unsigned depth, const bool in_deleg)
{
    if (in_deleg && (ltree_node_get_rrset_a(node) || ltree_node_get_rrset_aaaa(node)) && !LTN_GET_FLAG_GUSED(node))
        log_zwarn("Delegation glue address(es) at domainname '%s%s' are unused and ignored", logf_lstack(lstack, depth, zone->dname));
    return false;
}

F_WUNUSED F_NONNULLX(1, 2, 3)
static bool ltree_proc_inner(bool (*fn)(const uint8_t**, const ltree_node_t*, const zone_t*, const unsigned, const bool), const uint8_t** lstack, const ltree_node_t* node, const zone_t* zone, const unsigned depth, bool in_deleg)
{
    if (LTN_GET_FLAG_ZCUT(node) && node != zone->root) {
        gdnsd_assert(node->label);
        if (in_deleg)
            log_zfatal("Delegation '%s%s' is within another delegation", logf_lstack(lstack, depth, zone->dname));
        in_deleg = true;
    }

    if (unlikely(fn(lstack, node, zone, depth, in_deleg)))
        return true;

    // Recurse into children
    const size_t ccount = LTN_GET_CCOUNT(node);
    if (ccount) {
        gdnsd_assert(node->child_table);
        const uint32_t cmask = count2mask_sz(ccount);
        for (uint32_t i = 0; i <= cmask; i++) {
            const ltree_node_t* child = node->child_table[i].node;
            if (child) {
                // only root-of-DNS node (root-of-tree) has a NULL label
                gdnsd_assert(child->label);
                lstack[depth] = child->label;
                if (unlikely(ltree_proc_inner(fn, lstack, child, zone, depth + 1, in_deleg)))
                    return true;
            }
        }
    }

    return false;
}

F_WUNUSED F_NONNULL
static bool ltree_postproc(const zone_t* zone, bool (*fn)(const uint8_t**, const ltree_node_t*, const zone_t*, const unsigned, const bool))
{
    // label stack:
    //  used to reconstruct full domainnames
    //  for error/warning message output
    const uint8_t* lstack[127];

    return ltree_proc_inner(fn, lstack, zone->root, zone, 0, false);
}

F_WUNUSED F_NONNULL
static bool ltree_postproc_zroot_phase1(zone_t* zone)
{
    const ltree_node_t* zroot = zone->root;
    gdnsd_assert(zroot);

    const ltree_rrset_soa_t* zroot_soa = NULL;
    const ltree_rrset_ns_t* zroot_ns = NULL;

    const ltree_rrset_t* rrset = zroot->rrsets;
    while (rrset) {
        switch (rrset->gen.type) {
        case DNS_TYPE_SOA:
            zroot_soa = &rrset->soa;
            break;
        case DNS_TYPE_NS:
            zroot_ns  = &rrset->ns;
            break;
        default:
            break;
        }
        rrset = rrset->gen.next;
    }

    if (!zroot_soa)
        log_zfatal("Zone '%s' has no SOA record", logf_dname(zone->dname));
    if (!zroot_ns)
        log_zfatal("Zone '%s' has no NS records", logf_dname(zone->dname));
    bool ok = false;
    gdnsd_assert(zroot_ns->gen.count);
    if (zroot_ns->gen.count < 2)
        log_zwarn("Zone '%s' only has one NS record, this is (probably) bad practice", logf_dname(zone->dname));
    for (unsigned i = 0; i < zroot_ns->gen.count; i++) {
        if (!gdnsd_dname_cmp(zroot_soa->master, zroot_ns->rdata[i].dname)) {
            ok = true;
            break;
        }
    }
    if (!ok)
        log_zwarn("Zone '%s': SOA Master does not match any NS records for this zone", logf_dname(zone->dname));

    // copy SOA Serial field up to zone_t
    zone->serial = ntohl(zroot_soa->times[0]);
    return false;
}

F_NONNULL
static bool ltree_postproc_zroot_phase2(const zone_t* zone)
{
    const ltree_node_t* ooz = ltree_node_find_child(zone->root, ooz_glue_label);
    if (ooz) {
        const size_t ccount = LTN_GET_CCOUNT(ooz);
        gdnsd_assert(ccount); // only created if we have to add child nodes
        const uint32_t mask = count2mask_sz(ccount);
        for (unsigned i = 0; i <= mask; i++) {
            const ltree_node_t* ooz_node = ooz->child_table[i].node;
            if (ooz_node) {
                // This block of asserts effectively says: an ooz node must
                // have exactly either one or two rrsets, and they must both be
                // type A or AAAA, and they must differ in type if there's two.
                gdnsd_assert(ooz_node->rrsets);
                gdnsd_assert(ooz_node->rrsets->gen.type == DNS_TYPE_A || ooz_node->rrsets->gen.type == DNS_TYPE_AAAA);
                const ltree_rrset_t* next_rrsets = ooz_node->rrsets->gen.next;
                if (next_rrsets) {
                    gdnsd_assert(next_rrsets->gen.type == DNS_TYPE_A || next_rrsets->gen.type == DNS_TYPE_AAAA);
                    gdnsd_assert(next_rrsets->gen.type != ooz_node->rrsets->gen.type);
                    gdnsd_assert(!next_rrsets->gen.next);
                }

                if (!LTN_GET_FLAG_GUSED(ooz_node))
                    log_zwarn("In zone '%s', explicit out-of-zone glue address(es) at domainname '%s' are unused and ignored", logf_dname(zone->dname), logf_dname(ooz_node->label));
            }
        }
    }

    return false;
}

bool ltree_postproc_zone(zone_t* zone)
{
    gdnsd_assert(zone->dname);
    gdnsd_assert(zone->root);

    // zroot phase1 is a readonly check of zone basics
    //   (e.g. NS/SOA existence), also sets zone->serial
    if (unlikely(ltree_postproc_zroot_phase1(zone)))
        return true;

    // tree phase1 does a ton of readonly per-node checks
    //   (e.g. junk inside delegations, CNAME depth, CNAME
    //    and DYNC do not have partner rrsets, response sizing)
    // It also sets glue pointers for NS->A/AAAA
    if (unlikely(ltree_postproc(zone, ltree_postproc_phase1)))
        return true;

    // zroot phase2 checks for unused out-of-zone glue addresses,
    if (unlikely(ltree_postproc_zroot_phase2(zone)))
        return true;

    // tree phase2 looks for unused delegation glue addresses
    if (unlikely(ltree_postproc(zone, ltree_postproc_phase2)))
        return true;
    return false;
}

static void ltree_destroy(ltree_node_t* node)
{
    ltree_rrset_t* rrset = node->rrsets;
    while (rrset) {
        ltree_rrset_t* next = rrset->gen.next;
        switch (rrset->gen.type) {
        case DNS_TYPE_A:
            if (rrset->gen.count > LTREE_V4A_SIZE)
                free(rrset->a.addrs);
            break;
        case DNS_TYPE_AAAA:
            if (rrset->gen.count)
                free(rrset->aaaa.addrs);
            break;
        case DNS_TYPE_NAPTR:
            for (unsigned i = 0; i < rrset->gen.count; i++)
                free(rrset->naptr.rdata[i].text);
            free(rrset->naptr.rdata);
            break;
        case DNS_TYPE_TXT:
            for (unsigned i = 0; i < rrset->gen.count; i++)
                free(rrset->txt.rdata[i].text);
            free(rrset->txt.rdata);
            break;
        case DNS_TYPE_NS:
            free(rrset->ns.rdata);
            break;
        case DNS_TYPE_MX:
            free(rrset->mx.rdata);
            break;
        case DNS_TYPE_PTR:
            free(rrset->ptr.rdata);
            break;
        case DNS_TYPE_SRV:
            free(rrset->srv.rdata);
            break;
        case DNS_TYPE_SOA:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_DYNC:
            break;
        default:
            for (unsigned i = 0; i < rrset->gen.count; i++)
                free(rrset->rfc3597.rdata[i].rd);
            free(rrset->rfc3597.rdata);
            break;
        }
        free(rrset);
        rrset = next;
    }

    if (node->child_table) {
        const size_t mask = count2mask_sz(LTN_GET_CCOUNT(node));
        for (size_t i = 0; i <= mask; i++)
            if (node->child_table[i].node)
                ltree_destroy(node->child_table[i].node);
        free(node->child_table);
    }

    free(node);
}

void ltree_destroy_zone(zone_t* zone)
{
    ltree_destroy(zone->root);
    free(zone->dname);
    free(zone);
}

// -- meta-stuff for zone loading/reloading, etc:

void* ltree_zones_reloader_thread(void* init_asvoid)
{
    gdnsd_thread_setname("gdnsd-zreload");
    const bool init = (bool)init_asvoid;
    if (init) {
        gdnsd_assert(!root_tree);
        gdnsd_assert(!root_arena);
    } else {
        gdnsd_assert(root_tree);
        gdnsd_assert(root_arena);
        gdnsd_thread_reduce_prio();
    }

    uintptr_t rv = 0;

    ltarena_t* new_root_arena = lta_new();
    ltree_node_t* new_root_tree = xcalloc(sizeof(*new_root_tree));

    // These do not fail if their data directory doesn't exist
    const bool rfc1035_failed = zsrc_rfc1035_load_zones(new_root_tree, new_root_arena);

    if (rfc1035_failed) {
        ltree_destroy(new_root_tree);
        lta_destroy(new_root_arena);
        rv = 1; // the zsrc already logged why
    } else {
        ltree_node_t* old_root_tree = root_tree;
        rcu_assign_pointer(root_tree, new_root_tree);
        synchronize_rcu();
        if (old_root_tree) {
            ltree_destroy(old_root_tree);
            gdnsd_assert(root_arena);
            lta_destroy(root_arena);
        } else {
            gdnsd_assert(!root_arena);
        }
        root_arena = new_root_arena;
        lta_close(root_arena);
    }

    if (!init)
        notify_reload_zones_done();

    return (void*)rv;
}

static void ltree_cleanup(void)
{
    // Should we clean up any still-running reload thread?
    if (root_tree) {
        ltree_destroy(root_tree);
        root_tree = NULL;
        gdnsd_assert(root_arena);
        lta_destroy(root_arena);
        root_arena = NULL;
    } else {
        gdnsd_assert(!root_arena);
    }
}

void ltree_init(void)
{
    dyna_max_response = gdnsd_result_get_max_response();
    zsrc_rfc1035_init();
    gdnsd_atexit(ltree_cleanup);
}

/****** zone_t code ********/

zone_t* ltree_new_zone(const char* zname)
{
    // Convert to terminated-dname format and check for problems
    uint8_t dname[256];
    dname_status_t status = dname_from_string(dname, zname, strlen(zname));

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

    zone_t* z = xcalloc(sizeof(*z));
    z->root = xcalloc(sizeof(*z->root));
    z->dname = dname_dup(dname);
    z->arena = lta_new();
    LTN_SET_FLAG_ZCUT(z->root);
    // condition here leaves the label as NULL if this is the root zone
    if (dname[0] != 1U)
        z->root->label = lta_labeldup(z->arena, &dname[1]);

    return z;
}

bool ltree_merge_zone(ltree_node_t* new_root_tree, ltarena_t* new_root_arena, zone_t* new_zone)
{
    gdnsd_assert(new_zone->root);
    gdnsd_assert(LTN_GET_FLAG_ZCUT(new_zone->root));
    gdnsd_assert(!new_root_tree->label); // merge target is global root, no label

    const uint8_t* lstack[127];
    unsigned lcount = dname_to_lstack(new_zone->dname, lstack);

    ltree_node_t* n = new_root_tree;
    while (lcount) {
        if (LTN_GET_FLAG_ZCUT(n)) {
            log_err("Zone '%s' is a sub-zone of an existing zone", logf_dname(new_zone->dname));
            return true;
        }
        n = ltree_node_find_or_add_child(new_root_arena, n, lstack[--lcount]);
        gdnsd_assert(n);
    }

    if (LTN_GET_FLAG_ZCUT(n)) {
        log_err("Zone '%s' is a duplicate of an existing zone", logf_dname(new_zone->dname));
        return true;
    }

    if (LTN_GET_CCOUNT(n)) {
        log_err("Zone '%s' is a super-zone of one or more existing zones", logf_dname(new_zone->dname));
        return true;
    }
    gdnsd_assert(!n->child_table);
    gdnsd_assert(!n->rrsets);
    memcpy(n, new_zone->root, sizeof(*n));
    free(new_zone->root);
    log_info("Zone %s with serial %u loaded", logf_dname(new_zone->dname), new_zone->serial);
    free(new_zone->dname);
    lta_merge(new_root_arena, new_zone->arena);
    free(new_zone);
    return false;
}
