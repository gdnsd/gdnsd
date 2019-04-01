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
#include <gdnsd/grcu.h>
#include "plugins/plugapi.h"

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

// special label used to hide out-of-zone glue
//  inside zone root node child lists
static const uint8_t ooz_glue_label[1] = { 0 };

// initialized to realistic value by ltree_init(), is the total response size
// of all A+AAAA RRs from a DYNA that returns the maximal configured set (of
// all global plugin configurations).
static size_t dyna_max_response = 65536U;

// root_tree is RCU-managed and accessed by reader threads.
GRCU_PUB_DEF(root_tree, NULL);

// root_arena doesn't need RCU and is local here, but holds strings referenced
// by root_tree, so needs to be deleted after it
static struct ltarena* root_arena = NULL;

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
    } while (0)

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

F_RETNN F_NONNULL
static struct ltree_node* ltree_node_find_or_add_child(struct ltarena* arena, struct ltree_node* node, const uint8_t* child_label)
{
    const uint32_t ccount = node->ccount;
    const uintptr_t kh = ltree_hash(child_label);
    uint32_t probe_dist = 0;
    uint32_t mask = 0;
    if (ccount) {
        mask = count2mask_u32_lf80(ccount);
        do {
            const uint32_t slot = ((uint32_t)kh + probe_dist) & mask;
            const struct ltree_hslot* s = &node->child_table[slot];
            if (!s->node || ((slot - s->hash) & mask) < probe_dist)
                break;
            if (s->hash == kh && likely(!label_cmp(s->node->label, child_label)))
                return s->node;
            probe_dist++;
        } while (1);
    }
    // XXX this should be a zfatal, but bringing the context for that down to
    // here is tricky.  This is a serious issue though, as it causes the whole
    // daemon to die during what should be a reliable zone-reload operation.
    // The upside is that this case is unlikely to be reachable by reasonable
    // for real zones (even .com delegation zone wouldn't hit this on 32-bit!).
    // This will get fixed up later I hope, when it's easier to do so.
    if (unlikely((ccount + (ccount >> 2U)) == LTREE_NODE_MAX_SLOTS))
        log_fatal("Too many domainnames at one level!");
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
    ins->label = lta_labeldup(arena, child_label);
    ltree_node_insert(node, ins, kh, probe_dist, mask);
    node->ccount++;
    return ins;
}

// "dname" should be an FQDN format-wise, but:
//   (a) Must be in-zone for the given zone
//   (b) Must have the zone portion cut off the end,
//     e.g. for zone "example.com.", the dname normally
//     known as "www.example.com." should be just "www."
F_NONNULL F_RETNN
static struct ltree_node* ltree_find_or_add_dname(const struct zone* zone, const uint8_t* dname)
{
    gdnsd_assume(zone->root);
    gdnsd_assert(dname_get_status(dname) == DNAME_VALID);

    // Construct a label stack from dname
    const uint8_t* lstack[127];
    unsigned lcount = dname_to_lstack(dname, lstack);

    struct ltree_node* current = zone->root;
    while (lcount--)
        current = ltree_node_find_or_add_child(zone->arena, current, lstack[lcount]);

    return current;
}

#define MK_RRSET_GET(_typ, _dtyp) \
F_NONNULL F_PURE \
static struct ltree_rrset_ ## _typ * ltree_node_get_rrset_ ## _typ (const struct ltree_node* node) {\
    union ltree_rrset* rrsets = node->rrsets;\
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
static struct ltree_rrset_ ## _typ * ltree_node_add_rrset_ ## _typ (struct ltree_node* node) {\
    union ltree_rrset** store_at = &node->rrsets;\
    while (*store_at)\
        store_at = &(*store_at)->gen.next;\
    struct ltree_rrset_ ## _typ * nrr = xcalloc(sizeof(*nrr));\
    *store_at = (union ltree_rrset*)nrr;\
    nrr->gen.type = _dtyp;\
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
static unsigned clamp_ttl(const struct zone* zone, const uint8_t* dname, const char* rrtype, const unsigned ttl)
{
    if (ttl > gcfg->max_ttl) {
        log_warn("Name '%s%s': %s TTL %u too large, clamped to max_ttl setting of %u",
                 logf_dname(dname), logf_dname(zone->dname), rrtype, ttl, gcfg->max_ttl);
        return gcfg->max_ttl;
    } else if (ttl < gcfg->min_ttl) {
        log_warn("Name '%s%s': %s TTL %u too small, clamped to min_ttl setting of %u",
                 logf_dname(dname), logf_dname(zone->dname), rrtype, ttl, gcfg->min_ttl);
        return gcfg->min_ttl;
    }
    return ttl;
}

bool ltree_add_rec_a(const struct zone* zone, const uint8_t* dname, const uint32_t addr, unsigned ttl, const bool ooz)
{
    struct ltree_node* node;
    if (ooz) {
        log_zwarn("'%s A' in zone '%s': pointless out of zone glue will not be supported in a future version, please delete the record!", logf_dname(dname), logf_dname(zone->dname));
        struct ltree_node* ooz_node = ltree_node_find_or_add_child(zone->arena, zone->root, ooz_glue_label);
        node = ltree_node_find_or_add_child(zone->arena, ooz_node, dname);
    } else {
        node = ltree_find_or_add_dname(zone, dname);
    }

    ttl = clamp_ttl(zone, dname, "A", ttl);

    struct ltree_rrset_a* rrset = ltree_node_get_rrset_a(node);
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

bool ltree_add_rec_aaaa(const struct zone* zone, const uint8_t* dname, const uint8_t* addr, unsigned ttl, const bool ooz)
{
    struct ltree_node* node;
    if (ooz) {
        log_zwarn("'%s AAAA' in zone '%s': pointless out of zone glue will not be supported in a future version, please delete the record!", logf_dname(dname), logf_dname(zone->dname));
        struct ltree_node* ooz_node = ltree_node_find_or_add_child(zone->arena, zone->root, ooz_glue_label);
        node = ltree_node_find_or_add_child(zone->arena, ooz_node, dname);
    } else {
        node = ltree_find_or_add_dname(zone, dname);
    }

    ttl = clamp_ttl(zone, dname, "AAAA", ttl);

    struct ltree_rrset_aaaa* rrset = ltree_node_get_rrset_aaaa(node);
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

bool ltree_add_rec_dynaddr(const struct zone* zone, const uint8_t* dname, const char* rhs, unsigned ttl, unsigned ttl_min)
{
    struct ltree_node* node = ltree_find_or_add_dname(zone, dname);

    struct ltree_rrset_a* rrset_a = ltree_node_get_rrset_a(node);
    struct ltree_rrset_aaaa* rrset_aaaa = ltree_node_get_rrset_aaaa(node);
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

    const struct plugin* const p = gdnsd_plugin_find(plugin_name);
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

bool ltree_add_rec_cname(const struct zone* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl)
{
    ttl = clamp_ttl(zone, dname, "CNAME", ttl);

    struct ltree_node* node = ltree_find_or_add_dname(zone, dname);
    if (node->rrsets)
        log_zfatal("Name '%s%s': CNAME not allowed alongside other data", logf_dname(dname), logf_dname(zone->dname));
    struct ltree_rrset_cname* rrset = ltree_node_add_rrset_cname(node);
    rrset->dname = lta_dnamedup(zone->arena, rhs);
    rrset->gen.ttl = htonl(ttl);
    rrset->gen.count = 1;

    return false;
}

bool ltree_add_rec_dync(const struct zone* zone, const uint8_t* dname, const char* rhs, unsigned ttl, unsigned ttl_min)
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

    struct ltree_node* node = ltree_find_or_add_dname(zone, dname);
    if (node->rrsets)
        log_zfatal("Name '%s%s': DYNC not allowed alongside other data", logf_dname(dname), logf_dname(zone->dname));
    struct ltree_rrset_dync* rrset = ltree_node_add_rrset_dync(node);
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

    const struct plugin* const p = gdnsd_plugin_find(plugin_name);
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
//  This macro assumes "struct ltree_node* node" and "uint8_t* dname" in
//  the current context, and creates "rrset" and "new_rdata" of
//  the appropriate types
// _szassume is a size assumption.  If we expect 2+ to be the common
//  case for the rrset's count, set it to 2, otherwise 1.
#define INSERT_NEXT_RR(_typ, _nam, _pnam, _szassume) \
    struct ltree_rdata_ ## _typ * new_rdata;\
    struct ltree_rrset_ ## _typ * rrset = ltree_node_get_rrset_ ## _nam (node);\
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

bool ltree_add_rec_ptr(const struct zone* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl)
{
    struct ltree_node* node = ltree_find_or_add_dname(zone, dname);

    ttl = clamp_ttl(zone, dname, "PTR", ttl);
    INSERT_NEXT_RR(ptr, ptr, "PTR", 1);
    new_rdata->dname = lta_dnamedup(zone->arena, rhs);
    if (dname_isinzone(zone->dname, rhs))
        log_zwarn("Name '%s%s': PTR record points to same-zone name '%s', which is usually a mistake (missing terminal dot?)", logf_dname(dname), logf_dname(zone->dname), logf_dname(rhs));
    return false;
}

bool ltree_add_rec_ns(const struct zone* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl)
{
    struct ltree_node* node = ltree_find_or_add_dname(zone, dname);

    // If this is a delegation by definition, (NS rec not at zone root), flag it
    //   and check for wildcard.
    if (node != zone->root) {
        node->zone_cut = true;
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

bool ltree_add_rec_mx(const struct zone* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl, const unsigned pref)
{
    if (pref > 65535U)
        log_zfatal("Name '%s%s': MX preference value %u too large", logf_dname(dname), logf_dname(zone->dname), pref);

    struct ltree_node* node = ltree_find_or_add_dname(zone, dname);

    ttl = clamp_ttl(zone, dname, "MX", ttl);
    INSERT_NEXT_RR(mx, mx, "MX", 2)
    new_rdata->dname = lta_dnamedup(zone->arena, rhs);
    new_rdata->pref = htons(pref);
    return false;
}

bool ltree_add_rec_srv_args(const struct zone* zone, const uint8_t* dname, struct lt_srv_args args)
{
    if (args.priority > 65535U)
        log_zfatal("Name '%s%s': SRV priority value %u too large", logf_dname(dname), logf_dname(zone->dname), args.priority);
    if (args.weight > 65535U)
        log_zfatal("Name '%s%s': SRV weight value %u too large", logf_dname(dname), logf_dname(zone->dname), args.weight);
    if (args.port > 65535U)
        log_zfatal("Name '%s%s': SRV port value %u too large", logf_dname(dname), logf_dname(zone->dname), args.port);

    struct ltree_node* node = ltree_find_or_add_dname(zone, dname);

    const unsigned ttl = clamp_ttl(zone, dname, "SRV", args.ttl);
    INSERT_NEXT_RR(srv, srv, "SRV", 1)
    new_rdata->dname = lta_dnamedup(zone->arena, args.rhs);
    new_rdata->priority = htons(args.priority);
    new_rdata->weight = htons(args.weight);
    new_rdata->port = htons(args.port);
    return false;
}

bool ltree_add_rec_naptr_args(const struct zone* zone, const uint8_t* dname, struct lt_naptr_args args)
{
    if (args.order > 65535U)
        log_zfatal("Name '%s%s': NAPTR order value %u too large", logf_dname(dname), logf_dname(zone->dname), args.order);
    if (args.pref > 65535U)
        log_zfatal("Name '%s%s': NAPTR preference value %u too large", logf_dname(dname), logf_dname(zone->dname), args.pref);

    struct ltree_node* node = ltree_find_or_add_dname(zone, dname);

    const unsigned ttl = clamp_ttl(zone, dname, "NAPTR", args.ttl);
    INSERT_NEXT_RR(naptr, naptr, "NAPTR", 1)
    new_rdata->dname = lta_dnamedup(zone->arena, args.rhs);
    new_rdata->order = htons(args.order);
    new_rdata->pref = htons(args.pref);
    new_rdata->text_len = args.text_len;
    new_rdata->text = args.text;
    return false;
}

bool ltree_add_rec_txt(const struct zone* zone, const uint8_t* dname, const unsigned text_len, uint8_t* text, unsigned ttl)
{

    struct ltree_node* node = ltree_find_or_add_dname(zone, dname);

    // RFC 2181 disallows mixed TTLs within a single RR-set, so to avoid other
    // runtime complexity we choose to set all static _acme-challenge TXT
    // record TTLs to the same value configured for dynamic ones injected by
    // gdnsdctl, which is controlled by the config setting
    // acme_challenge_dns_ttl, defaulting to zero.  Note also that in this
    // case, no clamping to min_ttl applies (it's impossible for max_ttl to
    // conflict with acme_challenge_dns_ttl due to their limits).

    if (dname_is_acme_chal(dname)) {
        if (ttl != gcfg->acme_challenge_dns_ttl) {
            log_zwarn("Name '%s%s': ACME challenge TXT record TTL %u overridden to %u from 'acme_challenge_dns_ttl' config setting", logf_dname(dname), logf_dname(zone->dname), ttl, gcfg->acme_challenge_dns_ttl);
            ttl = gcfg->acme_challenge_dns_ttl;
        }
    } else {
        ttl = clamp_ttl(zone, dname, "TXT", ttl);
    }

    INSERT_NEXT_RR(txt, txt, "TXT", 1)
    new_rdata->text_len = text_len;
    new_rdata->text = text;
    return false;
}

bool ltree_add_rec_soa_args(const struct zone* zone, const uint8_t* dname, struct lt_soa_args args)
{
    // Here we clamp the negative TTL using min_ttl and max_ncache_ttl
    if (args.ncache > gcfg->max_ncache_ttl) {
        log_zwarn("Zone '%s': SOA negative-cache field %u too large, clamped to max_ncache_ttl setting of %u", logf_dname(zone->dname), args.ncache, gcfg->max_ncache_ttl);
        args.ncache = gcfg->max_ncache_ttl;
    } else if (args.ncache < gcfg->min_ttl) {
        log_zwarn("Zone '%s': SOA negative-cache field %u too small, clamped to min_ttl setting of %u", logf_dname(zone->dname), args.ncache, gcfg->min_ttl);
        args.ncache = gcfg->min_ttl;
    }

    // And here, we clamp the real RR TTL using min_ttl and the ncache value derived above
    if (args.ttl > args.ncache) {
        log_zwarn("Zone '%s': SOA TTL %u > ncache field %u, clamped to ncache value", logf_dname(zone->dname), args.ttl, args.ncache);
        args.ttl = args.ncache;
    } else if (args.ttl < gcfg->min_ttl) {
        log_zwarn("Zone '%s': SOA TTL %u too small, clamped to min_ttl setting of %u", logf_dname(zone->dname), args.ttl, gcfg->min_ttl);
        args.ttl = gcfg->min_ttl;
    }

    struct ltree_node* node = ltree_find_or_add_dname(zone, dname);

    // Parsers only allow SOA at zone root
    gdnsd_assume(zone->root == node);

    if (ltree_node_get_rrset_soa(node))
        log_zfatal("Zone '%s': SOA defined twice", logf_dname(zone->dname));

    struct ltree_rrset_soa* soa = ltree_node_add_rrset_soa(node);
    soa->rname = lta_dnamedup(zone->arena, args.rname);
    soa->mname = lta_dnamedup(zone->arena, args.mname);

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
static struct ltree_rrset_rfc3597* ltree_node_get_rrset_rfc3597(const struct ltree_node* node, const unsigned rrtype)
{
    union ltree_rrset* rrsets = node->rrsets;
    while (rrsets) {
        if (rrsets->gen.type == rrtype)
            return &(rrsets)->rfc3597;
        rrsets = rrsets->gen.next;
    }
    return NULL;
}

F_NONNULL
static struct ltree_rrset_rfc3597* ltree_node_add_rrset_rfc3597(struct ltree_node* node, const unsigned rrtype)
{
    union ltree_rrset** store_at = &node->rrsets;
    while (*store_at)
        store_at = &(*store_at)->gen.next;
    struct ltree_rrset_rfc3597* nrr = xcalloc(sizeof(*nrr));
    *store_at = (union ltree_rrset*)nrr;
    nrr->gen.type = (uint16_t)rrtype;
    return nrr;
}

bool ltree_add_rec_rfc3597(const struct zone* zone, const uint8_t* dname, const unsigned rrtype, unsigned ttl, const unsigned rdlen, uint8_t* rd)
{
    // For various error/log outputs, some of which are indirect
    char type_desc[64];
    int snp_rv = snprintf(type_desc, 64, "RFC3597 TYPE%u", rrtype);
    gdnsd_assert(snp_rv > 0 && snp_rv < 64);

    struct ltree_node* node = ltree_find_or_add_dname(zone, dname);

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
        log_zfatal("Name '%s%s': %s not allowed, please use the explicit support built in for this RR type", logf_dname(dname), logf_dname(zone->dname), type_desc);

    if (rrtype == DNS_TYPE_HINFO
            || rrtype == DNS_TYPE_DYNC
            || (rrtype > 127 && rrtype < 256)
            || rrtype == 0)
        log_zfatal("Name '%s%s': %s not allowed", logf_dname(dname), logf_dname(zone->dname), type_desc);

    ttl = clamp_ttl(zone, dname, type_desc, ttl);

    struct ltree_rrset_rfc3597* rrset = ltree_node_get_rrset_rfc3597(node, rrtype);

    struct ltree_rdata_rfc3597* new_rdata;

    if (!rrset) {
        rrset = ltree_node_add_rrset_rfc3597(node, rrtype);
        rrset->gen.count = 1;
        rrset->gen.ttl = htonl(ttl);
        new_rdata = rrset->rdata = xmalloc(sizeof(*new_rdata));
    } else {
        if (ntohl(rrset->gen.ttl) != ttl)
            log_zwarn("Name '%s%s': All TTLs for %s should match (using %u)", logf_dname(dname), logf_dname(zone->dname), type_desc, ntohl(rrset->gen.ttl));
        if (rrset->gen.count == UINT16_MAX)
            log_zfatal("Name '%s%s': Too many RRs for %s", logf_dname(dname), logf_dname(zone->dname), type_desc);
        rrset->rdata = xrealloc_n(rrset->rdata, 1U + rrset->gen.count, sizeof(*rrset->rdata));
        new_rdata = &rrset->rdata[rrset->gen.count++];
    }

    new_rdata->rdlen = rdlen;
    new_rdata->rd = rd;
    return false;
}

F_NONNULL
static enum ltree_dnstatus ltree_search_dname_zone(const uint8_t* dname, const struct zone* zone, struct ltree_node** node_out)
{
    gdnsd_assume(*dname != 0);
    gdnsd_assume(*dname != 2); // these are always illegal dnames

    enum ltree_dnstatus rval = DNAME_NOAUTH;
    struct ltree_node* rv_node = NULL;
    if (dname_isinzone(zone->dname, dname)) {
        rval = DNAME_AUTH;
        uint8_t local_dname[256];
        gdnsd_dname_copy(local_dname, dname);
        gdnsd_dname_drop_zone(local_dname, zone->dname);

        // construct label ptr stack
        const uint8_t* lstack[127];
        unsigned lcount = dname_to_lstack(local_dname, lstack);

        struct ltree_node* current = zone->root;
        gdnsd_assume(zone->root);

        while (!rv_node && current) {
            if (current->zone_cut && current != zone->root)
                rval = DNAME_DELEG;

            if (!lcount) {
                // exact match of full label count
                rv_node = current;
            } else {
                lcount--;
                const uint8_t* child_label = lstack[lcount];
                struct ltree_node* next = ltree_node_find_child(current, child_label);
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
static bool check_valid_addr(const uint8_t* dname, const struct zone* zone)
{
    gdnsd_assume(*dname);

    struct ltree_node* node;
    const enum ltree_dnstatus status = ltree_search_dname_zone(dname, zone, &node);
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
static bool p1_proc_ns(const struct zone* zone, struct ltree_rdata_ns* this_ns, const uint8_t** lstack, const unsigned depth)
{
    struct ltree_node* ns_target = NULL;
    enum ltree_dnstatus target_status = ltree_search_dname_zone(this_ns->dname, zone, &ns_target);

    // Don't attach glue for names in auth space, only delegation space and ooz
    if (target_status == DNAME_AUTH)
        return false;

    struct ltree_rrset_a* target_a = NULL;
    struct ltree_rrset_aaaa* target_aaaa = NULL;

    // if NOAUTH, look for explicit out-of-zone glue
    if (target_status == DNAME_NOAUTH) {
        gdnsd_assume(!ns_target);
        const struct ltree_node* ooz = ltree_node_find_child(zone->root, ooz_glue_label);
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

    // use target_addr found via either path above for all cases.
    if (target_a || target_aaaa) {
        gdnsd_assume(ns_target);
        this_ns->glue_v4 = target_a;
        this_ns->glue_v6 = target_aaaa;
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
// other), even though the runtime code does attempt to save space with such
// compression.  It does assume the obvious easy compression of left-hand-side
// names against the query name or the zone name within it.  We could run a
// real query using the runtime compression code as a final check before
// rejecting a node for being too big, but for now I'm voting to avoid that
// complexity unless someone using data big enough to matter complains.
//
// * In the case of addresses from DYNA RR sets, they're all counted as if they
// always emit the maximum recorded address counts possible from any DYNA
// (which is globally tracked during config parsing at startup), even if a
// given particular node's DYNA would never return that full amount.
//
// Note: The fixed part on the left of the RRs is counted as 12 bytes: 2 for
// compressed LHS name, 2 type, 2 class, 4 ttl, 2 rdlen

F_WUNUSED F_NONNULL
static size_t p1_rrset_size_ns(const union ltree_rrset* rrset)
{
    gdnsd_assume(rrset->gen.type == DNS_TYPE_NS);
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
static size_t p1_rrset_size(const union ltree_rrset* rrset, const bool in_deleg)
{
    size_t set_size = 0;

    switch (rrset->gen.type) {
    case DNS_TYPE_SOA:
        set_size = (12U + *rrset->soa.mname + *rrset->soa.rname + 20U);
        break;
    case DNS_TYPE_CNAME:
        set_size = (12U + *rrset->cname.dname);
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
            set_size += (12U + *rrset->ptr.rdata[i].dname);
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
static bool p1_check_deleg(const uint8_t** lstack, const struct ltree_node* node, const struct zone* zone, const unsigned depth, const bool in_deleg, const bool at_deleg)
{
    if (in_deleg) {
        gdnsd_assume(depth > 0);
        if (lstack[depth - 1][0] == 1 && lstack[depth - 1][1] == '*')
            log_zfatal("Domainname '%s%s': Wildcards not allowed for delegation/glue data",
                       logf_lstack(lstack, depth, zone->dname));

        const union ltree_rrset* rrset_dchk = node->rrsets;
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
static size_t p1_rsize_base(const uint8_t** lstack, const struct ltree_node* node, const struct zone* zone, const unsigned depth, const bool at_deleg)
{
    // First, the fixed portions:
    // sizeof(struct wire_dns_hdr): basic header bytes before query
    // 4U: the fixed parts of the query (qtype and qclass)
    // 11U: edns OPT RR with no options
    // 6U: edns tcp-keepalive response
    size_t rsize = sizeof(struct wire_dns_hdr) + 4U + 11U + 6U;

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
static bool p1_check_cname(const uint8_t** lstack, const struct ltree_node* node, const struct zone* zone, const unsigned depth)
{
    const union ltree_rrset* rrset = node->rrsets;
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
static bool p1_check_cname_target(const union ltree_rrset* rrset, const uint8_t** lstack, const struct zone* zone, const unsigned depth)
{
    if (rrset->gen.type == DNS_TYPE_CNAME) {
        const struct ltree_rrset_cname* node_cname = &rrset->cname;
        struct ltree_node* cn_target = NULL;
        enum ltree_dnstatus cnstat = ltree_search_dname_zone(node_cname->dname, zone, &cn_target);
        if (cnstat == DNAME_AUTH) {
            if (!cn_target) {
                log_zwarn("CNAME '%s%s' points to known same-zone NXDOMAIN '%s'",
                          logf_lstack(lstack, depth, zone->dname), logf_dname(node_cname->dname));
            } else if (!cn_target->rrsets) {
                log_zwarn("CNAME '%s%s' points to '%s' in the same zone, which has no data",
                          logf_lstack(lstack, depth, zone->dname), logf_dname(node_cname->dname));
            }
        }
    }

    return false;
}

F_WUNUSED F_NONNULL
static bool p1_check_mx_srv(const union ltree_rrset* rrset, const uint8_t** lstack, const struct zone* zone, const unsigned depth)
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
static bool ltree_postproc_phase1(const uint8_t** lstack, const struct ltree_node* node, const struct zone* zone, const unsigned depth, const bool in_deleg)
{
    const bool at_deleg = node->zone_cut && node != zone->root;

    if (p1_check_deleg(lstack, node, zone, depth, in_deleg, at_deleg))
        return true;

    // Base size for the query itself and applicable EDNS options
    size_t rsize = p1_rsize_base(lstack, node, zone, depth, at_deleg);

    // Check for CNAME/DYNC not having other types tacked on after they were added
    if (p1_check_cname(lstack, node, zone, depth))
        return true;

    // This tracks either the sum or the maximum of the RRs down below and is
    // later added to rsize, which tracks amounts that only sum
    size_t rsize_rrs = 0;

    const union ltree_rrset* rrset = node->rrsets;

    // Iterate the rrsets of the target node and find the maximally-sized one
    while (rrset) {
        // Check NS->A and set glue (which is needed for sizing below)
        if (rrset->gen.type == DNS_TYPE_NS)
            for (unsigned i = 0; i < rrset->gen.count; i++)
                if (p1_proc_ns(zone, &(rrset->ns.rdata[i]), lstack, depth))
                    return true;

        // Check MX/SRV targets for warnings
        if (p1_check_mx_srv(rrset, lstack, zone, depth))
            return true;

        // Check CNAME targets as well
        if (p1_check_cname_target(rrset, lstack, zone, depth))
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

F_WUNUSED F_NONNULLX(1, 2, 3)
static bool ltree_proc_inner(bool (*fn)(const uint8_t**, const struct ltree_node*, const struct zone*, const unsigned, const bool), const uint8_t** lstack, const struct ltree_node* node, const struct zone* zone, const unsigned depth, bool in_deleg)
{
    if (node->zone_cut && node != zone->root) {
        gdnsd_assume(node->label);
        if (in_deleg)
            log_zfatal("Delegation '%s%s' is within another delegation", logf_lstack(lstack, depth, zone->dname));
        in_deleg = true;
    }

    if (unlikely(fn(lstack, node, zone, depth, in_deleg)))
        return true;

    // Recurse into children
    const uint32_t ccount = node->ccount;
    if (ccount) {
        gdnsd_assume(node->child_table);
        const uint32_t cmask = count2mask_u32_lf80(ccount);
        for (uint32_t i = 0; i <= cmask; i++) {
            const struct ltree_node* child = node->child_table[i].node;
            if (child) {
                // only root-of-DNS node (root-of-tree) has a NULL label
                gdnsd_assume(child->label);
                lstack[depth] = child->label;
                if (unlikely(ltree_proc_inner(fn, lstack, child, zone, depth + 1, in_deleg)))
                    return true;
            }
        }
    }

    return false;
}

F_WUNUSED F_NONNULL
static bool ltree_postproc(const struct zone* zone, bool (*fn)(const uint8_t**, const struct ltree_node*, const struct zone*, const unsigned, const bool))
{
    // label stack:
    //  used to reconstruct full domainnames
    //  for error/warning message output
    const uint8_t* lstack[127];

    return ltree_proc_inner(fn, lstack, zone->root, zone, 0, false);
}

F_WUNUSED F_NONNULL
static bool ltree_postproc_zroot_phase1(struct zone* zone)
{
    const struct ltree_node* zroot = zone->root;
    gdnsd_assume(zroot);

    const struct ltree_rrset_soa* zroot_soa = NULL;
    const struct ltree_rrset_ns* zroot_ns = NULL;

    const union ltree_rrset* rrset = zroot->rrsets;
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
    gdnsd_assume(zroot_ns->gen.count);
    if (zroot_ns->gen.count < 2)
        log_zwarn("Zone '%s' only has one NS record, this is (probably) bad practice", logf_dname(zone->dname));
    for (unsigned i = 0; i < zroot_ns->gen.count; i++) {
        if (!gdnsd_dname_cmp(zroot_soa->mname, zroot_ns->rdata[i].dname)) {
            ok = true;
            break;
        }
    }
    if (!ok)
        log_zwarn("Zone '%s': SOA MNAME does not match any NS records for this zone", logf_dname(zone->dname));

    // copy SOA Serial field up to struct zone
    zone->serial = ntohl(zroot_soa->times[0]);
    return false;
}

F_NONNULL
static bool ltree_postproc_zroot_phase2(const struct zone* zone)
{
    const struct ltree_node* ooz = ltree_node_find_child(zone->root, ooz_glue_label);
    if (ooz) {
        gdnsd_assume(ooz->ccount); // only created if we have to add child nodes
        const uint32_t mask = count2mask_u32_lf80(ooz->ccount);
        for (unsigned i = 0; i <= mask; i++) {
            const struct ltree_node* ooz_node = ooz->child_table[i].node;
            if (ooz_node) {
                // This block of asserts effectively says: an ooz node must
                // have exactly either one or two rrsets, and they must both be
                // type A or AAAA, and they must differ in type if there's two.
                gdnsd_assume(ooz_node->rrsets);
                gdnsd_assert(ooz_node->rrsets->gen.type == DNS_TYPE_A || ooz_node->rrsets->gen.type == DNS_TYPE_AAAA);
                const union ltree_rrset* next_rrsets = ooz_node->rrsets->gen.next;
                if (next_rrsets) {
                    gdnsd_assert(next_rrsets->gen.type == DNS_TYPE_A || next_rrsets->gen.type == DNS_TYPE_AAAA);
                    gdnsd_assert(next_rrsets->gen.type != ooz_node->rrsets->gen.type);
                    gdnsd_assert(!next_rrsets->gen.next);
                }
            }
        }
    }

    return false;
}

bool ltree_postproc_zone(struct zone* zone)
{
    gdnsd_assume(zone->dname);
    gdnsd_assume(zone->root);

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

    return false;
}

static void ltree_destroy(struct ltree_node* node)
{
    union ltree_rrset* rrset = node->rrsets;
    while (rrset) {
        union ltree_rrset* next = rrset->gen.next;
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
        const uint32_t mask = count2mask_u32_lf80(node->ccount);
        for (uint32_t i = 0; i <= mask; i++)
            if (node->child_table[i].node)
                ltree_destroy(node->child_table[i].node);
        free(node->child_table);
    }

    free(node);
}

void ltree_destroy_zone(struct zone* zone)
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
        gdnsd_assert(!GRCU_OWN_READ(root_tree));
        gdnsd_assume(!root_arena);
    } else {
        gdnsd_assert(GRCU_OWN_READ(root_tree));
        gdnsd_assume(root_arena);
        gdnsd_thread_reduce_prio();
    }

    uintptr_t rv = 0;

    struct ltarena* new_root_arena = lta_new();
    struct ltree_node* new_root_tree = xcalloc(sizeof(*new_root_tree));

    // These do not fail if their data directory doesn't exist
    const bool rfc1035_failed = zsrc_rfc1035_load_zones(new_root_tree, new_root_arena);

    if (rfc1035_failed) {
        ltree_destroy(new_root_tree);
        lta_destroy(new_root_arena);
        rv = 1; // the zsrc already logged why
    } else {
        struct ltree_node* old_root_tree = GRCU_OWN_READ(root_tree);
        grcu_assign_pointer(root_tree, new_root_tree);
        grcu_synchronize_rcu();
        if (old_root_tree) {
            ltree_destroy(old_root_tree);
            gdnsd_assume(root_arena);
            lta_destroy(root_arena);
        } else {
            gdnsd_assume(!root_arena);
        }
        root_arena = new_root_arena;
        lta_close(root_arena);
    }

    if (!init)
        notify_reload_zones_done();

    return (void*)rv;
}

void ltree_init(void)
{
    gdnsd_shorthash_init(); // idempotent
    dyna_max_response = gdnsd_result_get_max_response();
    zsrc_rfc1035_init();
}

/****** struct zone code ********/

struct zone* ltree_new_zone(const char* zname)
{
    // Convert to terminated-dname format and check for problems
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

    struct zone* z = xcalloc(sizeof(*z));
    z->root = xcalloc(sizeof(*z->root));
    z->dname = dname_dup(dname);
    z->arena = lta_new();
    z->root->zone_cut = true;
    // condition here leaves the label as NULL if this is the root zone
    if (dname[0] != 1U)
        z->root->label = lta_labeldup(z->arena, &dname[1]);

    return z;
}

bool ltree_merge_zone(struct ltree_node* new_root_tree, struct ltarena* new_root_arena, struct zone* new_zone)
{
    gdnsd_assume(new_zone->root);
    gdnsd_assume(new_zone->root->zone_cut);
    gdnsd_assume(!new_root_tree->label); // merge target is global root, no label

    const uint8_t* lstack[127];
    unsigned lcount = dname_to_lstack(new_zone->dname, lstack);

    struct ltree_node* n = new_root_tree;
    while (lcount) {
        if (n->zone_cut) {
            log_err("Zone '%s' is a sub-zone of an existing zone", logf_dname(new_zone->dname));
            return true;
        }
        n = ltree_node_find_or_add_child(new_root_arena, n, lstack[--lcount]);
        gdnsd_assume(n);
    }

    if (n->zone_cut) {
        log_err("Zone '%s' is a duplicate of an existing zone", logf_dname(new_zone->dname));
        return true;
    }

    if (n->ccount) {
        log_err("Zone '%s' is a super-zone of one or more existing zones", logf_dname(new_zone->dname));
        return true;
    }
    gdnsd_assume(!n->child_table);
    gdnsd_assume(!n->rrsets);
    memcpy(n, new_zone->root, sizeof(*n));
    free(new_zone->root);
    log_info("Zone %s with serial %u loaded", logf_dname(new_zone->dname), new_zone->serial);
    free(new_zone->dname);
    lta_merge(new_root_arena, new_zone->arena);
    free(new_zone);
    return false;
}
