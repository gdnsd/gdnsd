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

#include "ltree.h"

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "conf.h"
#include "dnspacket.h"
#include "ltarena.h"

// This is the global singleton ltree_root
ltree_node_t* ltree_root = NULL;

// Global ltarena for all of ltree, for now
static ltarena_t* lta = NULL;

// This controls some bits about ltree reload/destruct,
//   because in the rootserver case lta/ltree_root
//   above alias the per-zone lta/root for the
//   authoritative root zone
static bool rootserver = false;

// special label used to hide out-of-zone glue
//  inside zone root node child lists
static const uint8_t ooz_glue_label[1] = { 0 };

#define log_strict(...)\
    do {\
        if(gconfig.strict_data)\
            log_fatal("strict_data: " __VA_ARGS__);\
        else\
            log_warn("strict_data: " __VA_ARGS__);\
    } while(0)

// don't use this directly, use macro below
// this logs the lstack labels as a partial domainname (possibly empty),
// intended to be completed with the zone name via the macro below
static const char* _logf_lstack(const uint8_t** lstack, int depth) {
    char* dnbuf = dmn_fmtbuf_alloc(1024);
    char* dnptr = dnbuf;

    while(depth) {
        depth--;
        const uint8_t llen = *(lstack[depth]);
        for(unsigned i = 1; i <= llen; i++) {
            unsigned char x = lstack[depth][i];
            if(x > 0x20 && x < 0x7F) {
                *dnptr++ = x;
            }
            else {
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
    _logf_lstack(_lstack, _depth), logf_dname(_zdname)

#ifndef HAVE_BUILTIN_CLZ

F_CONST
static inline uint32_t count2mask(uint32_t x) {
    x |= 1U;
    x |= x >> 1U;
    x |= x >> 2U;
    x |= x >> 4U;
    x |= x >> 8U;
    x |= x >> 16U;
    return x;
}

#else

F_CONST
static inline uint32_t count2mask(const uint32_t x) {
    // This variant is about twice as fast as the above, but
    //  only available w/ GCC 3.4 and above.
    return ((1U << (31U - __builtin_clz(x|1U))) << 1U) - 1U;
}

#endif

F_NONNULL
static void ltree_childtable_grow(ltree_node_t* node) {
    dmn_assert(node);

    const uint32_t old_max_slot = count2mask(node->child_hash_mask);
    const uint32_t new_hash_mask = (old_max_slot << 1) | 1;
    ltree_node_t** new_table = calloc(new_hash_mask + 1, sizeof(ltree_node_t*));
    for(uint32_t i = 0; i <= old_max_slot; i++) {
        ltree_node_t* entry = node->child_table[i];
        while(entry) {
            ltree_node_t* next_entry = entry->next;
            entry->next = NULL;

            const uint32_t child_hash = label_djb_hash(entry->label, new_hash_mask);
            ltree_node_t* slot = new_table[child_hash];

            if(slot) {
                while(slot->next)
                    slot = slot->next;
                slot->next = entry;
            }
            else {
                new_table[child_hash] = entry;
            }

            entry = next_entry;
        }
    }

    free(node->child_table);

    node->child_table = new_table;
}

F_NONNULL F_PURE
static ltree_node_t* ltree_node_find_child(const ltree_node_t* node, const uint8_t* child_label) {
    dmn_assert(node); dmn_assert(child_label);

    const uint32_t child_mask = count2mask(node->child_hash_mask);
    const uint32_t child_hash = label_djb_hash(child_label, child_mask);
    ltree_node_t* rv = NULL;

    if(node->child_table) {
        ltree_node_t* child = node->child_table[child_hash];
        while(child) {
            if(!memcmp(child->label, child_label, *child_label + 1)) {
                rv = child;
                break;
            }
            child = child->next;
        }
    }

    return rv;
}

F_NONNULL
static ltree_node_t* ltree_node_find_or_add_child(ltarena_t* arena, ltree_node_t* node, const uint8_t* child_label) {
    dmn_assert(node); dmn_assert(child_label);

    const uint32_t child_mask = count2mask(node->child_hash_mask);
    const uint32_t child_hash = label_djb_hash(child_label, child_mask);

    if(!node->child_table) {
        dmn_assert(!node->child_hash_mask);
        node->child_table = calloc(2, sizeof(ltree_node_t*));
    }

    ltree_node_t* child = node->child_table[child_hash];
    while(child) {
        if(!memcmp(child->label, child_label, *child_label + 1))
            return child;
        child = child->next;
    }

    child = calloc(1, sizeof(ltree_node_t));
    child->label = lta_labeldup(arena, child_label);
    child->next = node->child_table[child_hash];
    node->child_table[child_hash] = child;

    if(node->child_hash_mask == child_mask)
        ltree_childtable_grow(node);
    node->child_hash_mask++;

    return child;
}

// "dname" should be an FQDN format-wise, but:
//   (a) Must be in-zone for the given zone
//   (b) Must have the zone portion cut off the end,
//     e.g. for zone "example.com.", the dname normally
//     known as "www.example.com." should be just "www."
F_NONNULL
static ltree_node_t* ltree_find_or_add_dname(const zoneinfo_t* zone, const uint8_t* dname) {
    dmn_assert(zone); dmn_assert(dname);
    dmn_assert(zone->root); dmn_assert(zone->dname);
    dmn_assert(dname_status(dname) == DNAME_VALID);

    // Construct a label stack from dname
    const uint8_t* lstack[127];
    unsigned lcount = dname_to_lstack(dname, lstack);

    ltree_node_t* current = zone->root;
    while(lcount--)
        current = ltree_node_find_or_add_child(zone->arena, current, lstack[lcount]);

    return current;
}

// as above, but for creating zone roots under a non-authoritative root tree.
//   we use the global root-level "lta" up until the zone root itself, when
//   we switch to the zone's own storage
F_NONNULL
static ltree_node_t* ltree_find_or_add_dname_zroot(zoneinfo_t* zone) {
    dmn_assert(zone);
    dmn_assert(zone->arena); dmn_assert(zone->dname);
    dmn_assert(*zone->dname); // not root of DNS
    dmn_assert(lta); dmn_assert(ltree_root); // lta/ltree_root already set up
    dmn_assert(lta != zone->arena); // not root zone

    // Construct a label stack from dname
    const uint8_t* dname = zone->dname;
    const uint8_t* lstack[127];
    unsigned lcount = dname_to_lstack(dname, lstack);
    dmn_assert(lcount); // which means, we didn't call this on the root dname itself

    ltree_node_t* current = ltree_root;
    while(lcount > 1)
        current = ltree_node_find_or_add_child(lta, current, lstack[--lcount]);
    current = ltree_node_find_or_add_child(zone->arena, current, lstack[0]);

    return current;
}

#define MK_RRSET_GET(_typ, _nam, _dtyp) \
F_NONNULL F_PURE \
static ltree_rrset_ ## _typ ## _t* ltree_node_get_rrset_ ## _nam (const ltree_node_t* node) {\
    dmn_assert(node);\
    ltree_rrset_t* rrsets = node->rrsets;\
    while(rrsets) {\
        if(rrsets->gen.type == _dtyp)\
            return &(rrsets)-> _typ;\
        rrsets = rrsets->gen.next;\
    }\
    return NULL;\
}

MK_RRSET_GET(addr, addr, DNS_TYPE_A)
MK_RRSET_GET(soa, soa, DNS_TYPE_SOA)
MK_RRSET_GET(cname, cname, DNS_TYPE_CNAME)
MK_RRSET_GET(ns, ns, DNS_TYPE_NS)
MK_RRSET_GET(ptr, ptr, DNS_TYPE_PTR)
MK_RRSET_GET(mx, mx, DNS_TYPE_MX)
MK_RRSET_GET(srv, srv, DNS_TYPE_SRV)
MK_RRSET_GET(naptr, naptr, DNS_TYPE_NAPTR)
MK_RRSET_GET(txt, txt, DNS_TYPE_TXT)
MK_RRSET_GET(txt, spf, DNS_TYPE_SPF)

#define MK_RRSET_ADD(_typ, _nam, _dtyp) \
F_NONNULL \
static ltree_rrset_ ## _typ ## _t* ltree_node_add_rrset_ ## _nam (ltree_node_t* node) {\
    dmn_assert(node); \
    ltree_rrset_t** store_at = &node->rrsets;\
    while(*store_at)\
        store_at = &(*store_at)->gen.next;\
    *store_at = calloc(1, sizeof(ltree_rrset_ ## _typ ## _t));\
    (*store_at)->gen.type = _dtyp;\
    return &(*store_at)-> _typ;\
}

MK_RRSET_ADD(addr, addr, DNS_TYPE_A)
MK_RRSET_ADD(soa, soa, DNS_TYPE_SOA)
MK_RRSET_ADD(cname, cname, DNS_TYPE_CNAME)
MK_RRSET_ADD(ns, ns, DNS_TYPE_NS)
MK_RRSET_ADD(ptr, ptr, DNS_TYPE_PTR)
MK_RRSET_ADD(mx, mx, DNS_TYPE_MX)
MK_RRSET_ADD(srv, srv, DNS_TYPE_SRV)
MK_RRSET_ADD(naptr, naptr, DNS_TYPE_NAPTR)
MK_RRSET_ADD(txt, txt, DNS_TYPE_TXT)
MK_RRSET_ADD(txt, spf, DNS_TYPE_SPF)

void ltree_add_rec_a(const zoneinfo_t* zone, const uint8_t* dname, uint32_t addr, unsigned ttl, unsigned limit_v4, const bool ooz) {
    dmn_assert(zone); dmn_assert(dname);

    ltree_node_t* node;
    if(ooz) {
        ltree_node_t* ooz_node = ltree_node_find_or_add_child(zone->arena, zone->root, ooz_glue_label);
        node = ltree_node_find_or_add_child(zone->arena, ooz_node, dname);
    }
    else {
        node = ltree_find_or_add_dname(zone, dname);
    }

    ltree_rrset_addr_t* rrset = ltree_node_get_rrset_addr(node);
    if(!rrset) {
        rrset = ltree_node_add_rrset_addr(node);
        rrset->addrs.v4 = malloc(sizeof(uint32_t));
        rrset->addrs.v4[0] = addr;
        rrset->gen.count_v4 = 1;
        rrset->gen.ttl = htonl(ttl);
        rrset->limit_v4 = limit_v4;
    }
    else {
        if(!rrset->gen.is_static)
            log_fatal("Name '%s': DYNA cannot co-exist at the same name as A and/or AAAA", logf_dname(dname));
        if(rrset->gen.ttl != htonl(ttl))
            log_strict("Name '%s': All TTLs for A and/or AAAA records at the same name must agree", logf_dname(dname));
        if(rrset->gen.count_v4 == UINT8_MAX)
            log_fatal("Name '%s': Too many RRs of type A", logf_dname(dname));
        if(rrset->gen.count_v4 > 0 && rrset->limit_v4 != limit_v4)
            log_strict("Name '%s': All $ADDR_LIMIT_4 for A-records at the same name must agree", logf_dname(dname));
        rrset->limit_v4 = limit_v4;
        rrset->addrs.v4 = realloc(rrset->addrs.v4, sizeof(uint32_t) * (1 + rrset->gen.count_v4));
        rrset->addrs.v4[rrset->gen.count_v4++] = addr;
    }
}

void ltree_add_rec_aaaa(const zoneinfo_t* zone, const uint8_t* dname, const uint8_t* addr, unsigned ttl, unsigned limit_v6, const bool ooz) {
    dmn_assert(zone); dmn_assert(dname); dmn_assert(addr);

    ltree_node_t* node;
    if(ooz) {
        ltree_node_t* ooz_node = ltree_node_find_or_add_child(zone->arena, zone->root, ooz_glue_label);
        node = ltree_node_find_or_add_child(zone->arena, ooz_node, dname);
    }
    else {
        node = ltree_find_or_add_dname(zone, dname);
    }

    ltree_rrset_addr_t* rrset = ltree_node_get_rrset_addr(node);
    if(!rrset) {
        rrset = ltree_node_add_rrset_addr(node);
        rrset->addrs.v6 = malloc(16);
        memcpy(rrset->addrs.v6, addr, 16);
        rrset->gen.count_v6 = 1;
        rrset->gen.ttl = htonl(ttl);
        rrset->limit_v6 = limit_v6;
    }
    else {
        if(!rrset->gen.is_static)
            log_fatal("Name '%s': DYNA cannot co-exist at the same name as A and/or AAAA", logf_dname(dname));
        if(rrset->gen.ttl != htonl(ttl))
            log_strict("Name '%s': All TTLs for A and/or AAAA records at the same name must agree", logf_dname(dname));
        if(rrset->gen.count_v6 == UINT8_MAX)
            log_fatal("Name '%s': Too many RRs of type AAAA", logf_dname(dname));
        if(rrset->gen.count_v6 > 0 && rrset->limit_v6 != limit_v6)
            log_strict("Name '%s': All $ADDR_LIMIT_6 for AAAA-records at the same name must agree", logf_dname(dname));
        rrset->limit_v6 = limit_v6;
        rrset->addrs.v6 = realloc(rrset->addrs.v6, 16 * (1 + rrset->gen.count_v6));
        memcpy(rrset->addrs.v6 + (rrset->gen.count_v6++ * 16), addr, 16);
    }
}

void ltree_add_rec_dynaddr(const zoneinfo_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl, unsigned limit_v4, unsigned limit_v6, const bool ooz) {
    dmn_assert(zone); dmn_assert(dname); dmn_assert(rhs);

    ltree_node_t* node;
    if(ooz) {
        ltree_node_t* ooz_node = ltree_node_find_or_add_child(zone->arena, zone->root, ooz_glue_label);
        node = ltree_node_find_or_add_child(zone->arena, ooz_node, dname);
    }
    else {
        node = ltree_find_or_add_dname(zone, dname);
    }

    ltree_rrset_addr_t* rrset;
    if((rrset = ltree_node_get_rrset_addr(node))) {
        if(rrset->gen.is_static)
            log_fatal("Name '%s': DYNA cannot co-exist at the same name as A and/or AAAA", logf_dname(dname));
        else
            log_fatal("Name '%s': DYNA defined twice for the same name", logf_dname(dname));
    }
    rrset = ltree_node_add_rrset_addr(node);
    rrset->gen.ttl = htonl(ttl);
    rrset->limit_v4 = limit_v4;
    rrset->limit_v6 = limit_v6;

    char* plugin_name = strdup((const char*)rhs);
    char* resource_name;
    if((resource_name = strchr(plugin_name, '!')))
        *resource_name++ = '\0';

    const plugin_t* const p = gdnsd_plugin_find(plugin_name);
    if(p) {
        if(!p->resolve_dynaddr) {
            log_fatal("Name '%s': DYNA refers to a plugin which does not support dynamic address resolution", logf_dname(dname));
        }
        else {
            rrset->dyn.resource = p->map_resource_dyna ? p->map_resource_dyna(resource_name) : 0;
            rrset->dyn.func = p->resolve_dynaddr;
            free(plugin_name);
        }
        return;
    }

    log_fatal("Name '%s': DYNA RR refers to plugin '%s', which is not loaded", logf_dname(dname), plugin_name);
}

void ltree_add_rec_cname(const zoneinfo_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl) {
    dmn_assert(zone); dmn_assert(dname); dmn_assert(rhs);

    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    // This zone root check is redundant given some other checks
    //   in the processing phases, but it's still a nice explicit
    //   early bailout point.
    if(node->flags & LTNFLAG_ZROOT)
        log_fatal("Name '%s': No CNAME allowed at a zone root", logf_dname(dname));

    if(ltree_node_get_rrset_cname(node))
        log_fatal("Name '%s': Only one CNAME or DYNC record can exist for a given name", logf_dname(dname));

    ltree_rrset_cname_t* rrset = ltree_node_add_rrset_cname(node);
    rrset->dname = lta_dnamedup(zone->arena, rhs);
    rrset->gen.ttl = htonl(ttl);
    rrset->gen.is_static = true;
}

void ltree_add_rec_dyncname(const zoneinfo_t* zone, const uint8_t* dname, const uint8_t* rhs, const uint8_t* origin, unsigned ttl) {
    dmn_assert(zone); dmn_assert(dname); dmn_assert(rhs);

    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    // This zone root check is redundant given some other checks
    //   in the processing phases, but it's still a nice explicit
    //   early bailout point.
    if(node->flags & LTNFLAG_ZROOT)
        log_fatal("Name '%s': No CNAME allowed at a zone root", logf_dname(dname));

    if(ltree_node_get_rrset_cname(node))
        log_fatal("Name '%s': Only one CNAME or DYNC record can exist for a given name", logf_dname(dname));

    ltree_rrset_cname_t* rrset = ltree_node_add_rrset_cname(node);
    rrset->dyn.origin = lta_dnamedup(zone->arena, origin);
    rrset->gen.ttl = htonl(ttl);

    char* plugin_name = strdup((const char*)rhs);
    char* resource_name;
    if((resource_name = strchr(plugin_name, '!')))
        *resource_name++ = '\0';

    const plugin_t* const p = gdnsd_plugin_find(plugin_name);
    if(p) {
        if(!p->resolve_dyncname) {
            log_fatal("Name '%s': DYNC refers to a plugin which does not support dynamic CNAME resolution", logf_dname(dname));
        }
        else {
            // we pass rrset->dyn.origin instead of origin here, in case the plugin author saves the pointer
            //  (which he probably shouldn't, but can't hurt to make life easier)
            rrset->dyn.resource = p->map_resource_dync ? p->map_resource_dync(resource_name, rrset->dyn.origin) : 0;
            rrset->dyn.func = p->resolve_dyncname;
            free(plugin_name);
            return;
        }
    }

    log_fatal("Name '%s': DYNC refers to plugin '%s', which is not loaded", logf_dname(dname), plugin_name);
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
    if(!rrset) {\
        rrset = ltree_node_add_rrset_ ## _nam (node);\
        rrset->gen.count = 1;\
        rrset->gen.ttl = htonl(ttl);\
        new_rdata = rrset->rdata = malloc(sizeof(ltree_rdata_ ## _typ ## _t) * _szassume);\
    }\
    else {\
        if(rrset->gen.ttl != htonl(ttl))\
            log_strict("Name '%s': All TTLs for type %s must match", logf_dname(dname), _pnam);\
        if(rrset->gen.count == UINT16_MAX)\
            log_fatal("Name '%s': Too many RRs of type %s", logf_dname(dname), _pnam);\
        if(_szassume == 1 || rrset->gen.count >= _szassume) \
            rrset->rdata = realloc(rrset->rdata, (1 + rrset->gen.count) * sizeof(ltree_rdata_ ## _typ ## _t));\
        new_rdata = &rrset->rdata[rrset->gen.count++];\
    }\
}

void ltree_add_rec_ptr(const zoneinfo_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl) {
    dmn_assert(zone); dmn_assert(dname); dmn_assert(rhs);

    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    INSERT_NEXT_RR(ptr, ptr, "PTR", 1);
    new_rdata->dname = lta_dnamedup(zone->arena, rhs);
    new_rdata->ad = NULL;
}

void ltree_add_rec_ns(const zoneinfo_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl) {
    dmn_assert(zone); dmn_assert(dname); dmn_assert(rhs);

    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    if(node->label[0] == 1 && node->label[1] == '*')
        log_fatal("Name '%s': Cannot delegate via wildcards", logf_dname(dname));

    // If this is a delegation by definition, (NS rec not at zone root), flag it
    if(!(node->flags & LTNFLAG_ZROOT))
        node->flags |= LTNFLAG_DELEG;

    INSERT_NEXT_RR(ns, ns, "NS", 2)
    new_rdata->dname = lta_dnamedup(zone->arena, rhs);
    new_rdata->ad = NULL;
}

void ltree_add_rec_mx(const zoneinfo_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl, unsigned pref) {
    dmn_assert(zone); dmn_assert(dname); dmn_assert(rhs);

    if(pref > 65535U) log_fatal("Name '%s': MX preference value %u too large", logf_dname(dname), pref);

    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    INSERT_NEXT_RR(mx, mx, "MX", 2)
    new_rdata->dname = lta_dnamedup(zone->arena, rhs);
    new_rdata->pref = htons(pref);
    new_rdata->ad = NULL;
}

void ltree_add_rec_srv(const zoneinfo_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl, unsigned priority, unsigned weight, unsigned port) {
    dmn_assert(zone); dmn_assert(dname); dmn_assert(rhs);

    if(priority > 65535U) log_fatal("Name '%s': SRV priority value %u too large", logf_dname(dname), priority);
    if(weight > 65535U) log_fatal("Name '%s': SRV weight value %u too large", logf_dname(dname), weight);
    if(port > 65535U) log_fatal("Name '%s': SRV port value %u too large", logf_dname(dname), port);

    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    INSERT_NEXT_RR(srv, srv, "SRV", 1)
    new_rdata->dname = lta_dnamedup(zone->arena, rhs);
    new_rdata->priority = htons(priority);
    new_rdata->weight = htons(weight);
    new_rdata->port = htons(port);
    new_rdata->ad = NULL;
}

/* RFC 2195 was obsoleted by RFC 3403 for defining the NAPTR RR
 * As 3403 is much looser about the contents of the 3 text fields,
 * there's not much validation we can do on them.
 *
 * All we can really say for sure anymore is:
 *   1) Flags must be [0-9A-Za-z]*
 *   2) Regexp (the final text field) and Replacement (the RHS domainname)
 *     are apparently mutually exclusive as of RFC3403, and it is an error
 *     to define both in one NAPTR RR.  The "undefined" value for Regexp is the empty
 *     string, and the "undefined" value for Replacement is the root of DNS ('\0').
 */
F_NONNULL
static void naptr_validate_flags(const uint8_t* dname, const uint8_t* flags) {
    dmn_assert(dname); dmn_assert(flags);

    unsigned len = *flags++;
    while(len--) {
        unsigned c = *flags++;
        if(    (c > 0x7AU)              // > 'Z'
            || (c > 0x5BU && c < 0x61U) // > 'z' && < 'A'
            || (c > 0x39U && c < 0x41U) // > '9' && < 'a'
            || (c < 0x30U))             // < '0'
            log_warn("Name '%s': NAPTR has illegal flag char '%c'", logf_dname(dname), c);
    }
}

void ltree_add_rec_naptr(const zoneinfo_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl, unsigned order, unsigned pref, unsigned num_texts V_UNUSED, uint8_t** texts) {
    dmn_assert(zone); dmn_assert(dname); dmn_assert(rhs); dmn_assert(texts); dmn_assert(num_texts == 3);

    if(order > 65535U) log_fatal("Name '%s': NAPTR order value %u too large", logf_dname(dname), order);
    if(pref > 65535U) log_fatal("Name '%s': NAPTR preference value %u too large", logf_dname(dname), pref);
    naptr_validate_flags(dname, texts[NAPTR_TEXTS_FLAGS]);

    if(rhs[1] != 0 && texts[NAPTR_TEXTS_REGEXP][0])
        log_warn("Name '%s': NAPTR does not allow defining both Regexp and Replacement in a single RR", logf_dname(dname));

    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    INSERT_NEXT_RR(naptr, naptr, "NAPTR", 1)
    new_rdata->dname = lta_dnamedup(zone->arena, rhs);
    new_rdata->order = htons(order);
    new_rdata->pref = htons(pref);
    memcpy(new_rdata->texts, texts, sizeof(new_rdata->texts));
    new_rdata->ad = NULL;
}

// We copy the array of pointers, but alias the actual data (which is malloc'd for
//   us per call in the parser).
void ltree_add_rec_txt(const zoneinfo_t* zone, const uint8_t* dname, unsigned num_texts, uint8_t** texts, unsigned ttl) {
    dmn_assert(zone); dmn_assert(dname); dmn_assert(texts); dmn_assert(num_texts);

    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    INSERT_NEXT_RR(txt, txt, "TXT", 1)
    const unsigned tsize = (num_texts + 1) * sizeof(uint8_t*);
    *new_rdata = malloc(tsize);
    memcpy(*new_rdata, texts, tsize);
}

void ltree_add_rec_spf(const zoneinfo_t* zone, const uint8_t* dname, unsigned num_texts, uint8_t** texts, unsigned ttl) {
    dmn_assert(zone); dmn_assert(dname); dmn_assert(texts); dmn_assert(num_texts);

    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    INSERT_NEXT_RR(txt, spf, "SPF", 1)
    const unsigned tsize = (num_texts + 1) * sizeof(uint8_t*);
    *new_rdata = malloc(tsize);
    memcpy(*new_rdata, texts, tsize);
}

// This handles 'foo SPF+ "v=spf1 ..."' and makes both TXT and SPF recs for it
void ltree_add_rec_spftxt(const zoneinfo_t* zone, const uint8_t* dname, unsigned num_texts, uint8_t** texts, unsigned ttl) {
    dmn_assert(zone); dmn_assert(dname); dmn_assert(texts); dmn_assert(num_texts);

    // duplicate the raw text storage, so that destruction isn't confusing
    uint8_t* tcopy[num_texts + 1];
    for(unsigned i = 0; i < num_texts; i++) {
        const unsigned tlen = *texts[i] + 1;
        tcopy[i] = malloc(tlen);
        memcpy(tcopy[i], texts[i], tlen);
    }
    tcopy[num_texts] = NULL;

    ltree_add_rec_txt(zone, dname, num_texts, texts, ttl);
    ltree_add_rec_spf(zone, dname, num_texts, tcopy, ttl);
}

void ltree_add_rec_soa(const zoneinfo_t* zone, const uint8_t* dname, const uint8_t* master, const uint8_t* email, unsigned ttl, unsigned serial, unsigned refresh, unsigned retry, unsigned expire, unsigned ncache) {
    dmn_assert(zone); dmn_assert(dname); dmn_assert(master); dmn_assert(email);

    if(ncache > 10800U)
        log_strict("Zone '%s': SOA negative-cache field too large (%u, must be <= 10800)", logf_dname(dname), ncache);

    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    if(ltree_node_get_rrset_soa(node))
        log_fatal("Zone '%s': SOA defined twice", logf_dname(dname));

    ltree_rrset_soa_t* soa = ltree_node_add_rrset_soa(node);
    soa->email = lta_dnamedup(zone->arena, email);
    soa->master = lta_dnamedup(zone->arena, master);

    soa->gen.ttl = htonl(ttl);
    soa->times[0] = htonl(serial);
    soa->times[1] = htonl(refresh);
    soa->times[2] = htonl(retry);
    soa->times[3] = htonl(expire);
    soa->times[4] = htonl(ncache);
}

// It is critical that get/add_rrset_rfc3597 are not called with
//  rrtype set to the number of other known, explicitly supported types...
F_NONNULL
static ltree_rrset_rfc3597_t* ltree_node_get_rrset_rfc3597(const ltree_node_t* node, unsigned rrtype) {
    dmn_assert(node);
    ltree_rrset_t* rrsets = node->rrsets;
    while(rrsets) {
        if(rrsets->gen.type == rrtype)
            return &(rrsets)->rfc3597;
        rrsets = rrsets->gen.next;
    }
    return NULL;
}

F_NONNULL
static ltree_rrset_rfc3597_t* ltree_node_add_rrset_rfc3597(ltree_node_t* node, unsigned rrtype) {
    dmn_assert(node);
    ltree_rrset_t** store_at = &node->rrsets;
    while(*store_at)
        store_at = &(*store_at)->gen.next;
    *store_at = calloc(1, sizeof(ltree_rrset_rfc3597_t));
    (*store_at)->gen.type = rrtype;
    return &(*store_at)->rfc3597;
}


void ltree_add_rec_rfc3597(const zoneinfo_t* zone, const uint8_t* dname, unsigned rrtype, unsigned ttl, unsigned rdlen, uint8_t* rd) {
    dmn_assert(zone); dmn_assert(dname);

    ltree_node_t* node = ltree_find_or_add_dname(zone, dname);

    if(  rrtype == DNS_TYPE_A
      || rrtype == DNS_TYPE_AAAA
      || rrtype == DNS_TYPE_SOA
      || rrtype == DNS_TYPE_CNAME
      || rrtype == DNS_TYPE_NS
      || rrtype == DNS_TYPE_PTR
      || rrtype == DNS_TYPE_MX
      || rrtype == DNS_TYPE_SRV
      || rrtype == DNS_TYPE_NAPTR
      || rrtype == DNS_TYPE_TXT
      || rrtype == DNS_TYPE_SPF)
        log_fatal("Name '%s': RFC3597 TYPE%u not allowed, please use the explicit support built in for this RR type", logf_dname(dname), rrtype);

    if(  rrtype == DNS_TYPE_AXFR
      || rrtype == DNS_TYPE_IXFR
      || rrtype == DNS_TYPE_ANY)
        log_fatal("Name '%s': RFC3597 TYPE%u not allowed", logf_dname(dname), rrtype);

    ltree_rrset_rfc3597_t* rrset = ltree_node_get_rrset_rfc3597(node, rrtype);

    ltree_rdata_rfc3597_t* new_rdata;

    if(!rrset) {
        rrset = ltree_node_add_rrset_rfc3597(node, rrtype);
        rrset->gen.count = 1;
        rrset->gen.ttl = htonl(ttl);
        new_rdata = rrset->rdata = malloc(sizeof(ltree_rdata_rfc3597_t));
    }
    else {
        if(rrset->gen.ttl != htonl(ttl))
            log_strict("Name '%s': All TTLs for type RFC3597 TYPE%u must match", logf_dname(dname), rrtype);
        if(rrset->gen.count == UINT16_MAX)
            log_fatal("Name '%s': Too many RFC3597 RRs of type TYPE%u", logf_dname(dname), rrtype);
        rrset->rdata = realloc(rrset->rdata, (1 + rrset->gen.count) * sizeof(ltree_rdata_rfc3597_t));
        new_rdata = &rrset->rdata[rrset->gen.count++];
    }

    new_rdata->rdlen = rdlen;
    new_rdata->rd = rd;
}

F_NONNULL
static ltree_dname_status_t ltree_search_dname_zone(const uint8_t* dname, const zoneinfo_t* zone, ltree_node_t** node_out) {
    dmn_assert(dname); dmn_assert(zone); dmn_assert(node_out);
    dmn_assert(*dname != 0); dmn_assert(*dname != 2); // these are always illegal dnames

    ltree_dname_status_t rval = DNAME_NOAUTH;
    ltree_node_t* rv_node = NULL;
    if(dname_isinzone(zone->dname, dname)) {
        rval = DNAME_AUTH;
        uint8_t local_dname[256];
        gdnsd_dname_copy(local_dname, dname);
        gdnsd_dname_drop_zone(local_dname, zone->dname);

        // construct label ptr stack
        const uint8_t* lstack[127];
        unsigned lcount = dname_to_lstack(local_dname, lstack);

        ltree_node_t* current = zone->root;

        do {
            top_loop:;
            if(current->flags & LTNFLAG_DELEG)
                rval = DNAME_DELEG;

            if(!lcount || !current->child_table) {
                if(!lcount) rv_node = current;
                break;
            }

            lcount--;
            const uint8_t* child_label = lstack[lcount];
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
        if(!rv_node && rval == DNAME_AUTH && current->child_table) {
            ltree_node_t* entry = current->child_table[label_djb_hash((const uint8_t*)"\001*", current->child_hash_mask)];
            while(entry) {
                if(entry->label[0] == '\001' && entry->label[1] == '*') {
                    rv_node = entry;
                    break;
                }
                entry = entry->next;
            }
        }
    }

    *node_out = rv_node;
    return rval;
}

// retval: true, all is well (although we didn't necessarily set an address)
//         false, the target points at an authoritative name in the same zone which doesn't exist
F_NONNULL
static bool set_valid_addr(const uint8_t* dname, const zoneinfo_t* zone, ltree_rrset_addr_t** addr_out) {
    dmn_assert(dname); dmn_assert(*dname); dmn_assert(zone); dmn_assert(addr_out);

    ltree_node_t* node;
    const ltree_dname_status_t status = ltree_search_dname_zone(dname, zone, &node);

    *addr_out = NULL;
    if(status == DNAME_AUTH)
        if(!node || !(*addr_out = ltree_node_get_rrset_addr(node)))
            return false;

    return true;
}

// Input must be a binstr (first byte is len, rest is the data),
//  "c" must be an uppercase ASCII character.
// retval indicates whether the string contains this character
//   (in upper or lower case form).
F_NONNULL F_PURE
static bool binstr_hasichr(const uint8_t* bstr, const uint8_t c) {
    dmn_assert(bstr); dmn_assert(c > 0x40 && c < 0x5B);
    unsigned len = *bstr++;
    while(len--) {
        if(((*bstr++) & (~0x20)) == c)
            return true;
    }
    return false;
}

// For static addresses, if no limit was specified, set it
//  to the count for simplicity.  If limit is greater than
//  count, limit limit to the count.  This is done at runtime
//  for DYNA.
static void fix_addr_limits(ltree_rrset_addr_t* node_addr) {
        if(!node_addr->limit_v4 || node_addr->limit_v4 > node_addr->gen.count_v4)
            node_addr->limit_v4 = node_addr->gen.count_v4;
        if(!node_addr->limit_v6 || node_addr->limit_v6 > node_addr->gen.count_v6)
            node_addr->limit_v6 = node_addr->gen.count_v6;
}

// If this zone root has out-of-zone glue, do the above address limit fixups on it
static void ooz_fix_addr_limits(ltree_node_t* zroot) {
    ltree_node_t* ooz = ltree_node_find_child(zroot, ooz_glue_label);
    if(ooz) {
        for(unsigned i = 0; i <= ooz->child_hash_mask; i++) {
            ltree_node_t* ooz_node = ooz->child_table[i];
            while(ooz_node) {
                dmn_assert(ooz_node->rrsets);
                dmn_assert(ooz_node->rrsets->gen.type == DNS_TYPE_A);
                dmn_assert(!ooz_node->rrsets->gen.next);
                fix_addr_limits(&ooz_node->rrsets->addr);
                ooz_node = ooz_node->next;
            }
        }
    }
}

static void p1_proc_cname(const zoneinfo_t* zone, const ltree_rrset_cname_t* node_cname, const uint8_t** lstack, const unsigned depth) {
    ltree_node_t* cn_target;
    ltree_dname_status_t cnstat = ltree_search_dname_zone(node_cname->dname, zone, &cn_target);
    if(cnstat == DNAME_AUTH) {
        if(!cn_target) {
            log_strict("CNAME '%s%s' points to known same-zone NXDOMAIN '%s'",
                logf_lstack(lstack, depth, zone->dname), logf_dname(node_cname->dname));
        }
        else if(!cn_target->rrsets) {
            log_strict("CNAME '%s%s' points to '%s' in the same zone, which has no data",
                logf_lstack(lstack, depth, zone->dname), logf_dname(node_cname->dname));
        }
    }

    unsigned cn_depth = 1;
    while(cn_target && cnstat == DNAME_AUTH && cn_target->rrsets && cn_target->rrsets->gen.type == DNS_TYPE_CNAME && cn_target->rrsets->gen.is_static) {
        if(++cn_depth > gconfig.max_cname_depth) {
            log_fatal("CNAME '%s%s' leads to a CNAME chain longer than %u (max_cname_depth)", logf_lstack(lstack, depth, zone->dname), gconfig.max_cname_depth);
            break;
        }
        ltree_rrset_cname_t* cur_cname = &cn_target->rrsets->cname;
        cnstat = ltree_search_dname_zone(cur_cname->dname, zone, &cn_target);
    }
}

F_NONNULL
static void p1_proc_ns(const zoneinfo_t* zone, const bool in_deleg, ltree_rdata_ns_t* this_ns, const uint8_t** lstack, const unsigned depth) {
    dmn_assert(zone); dmn_assert(this_ns);
    dmn_assert(!this_ns->ad);

    ltree_node_t* ns_target = NULL;
    ltree_rrset_addr_t* target_addr = NULL;
    ltree_dname_status_t ns_status = ltree_search_dname_zone(this_ns->dname, zone, &ns_target);

    // if NOAUTH, look for explicit out-of-zone glue
    if(ns_status == DNAME_NOAUTH) {
        ltree_node_t* ooz = ltree_node_find_child(zone->root, ooz_glue_label);
        if(ooz) {
            ns_target = ltree_node_find_child(ooz, this_ns->dname);
            if(ns_target) {
                dmn_assert(!ns_target->child_table);
                dmn_assert(ns_target->rrsets);
                dmn_assert(ns_target->rrsets->gen.type == DNS_TYPE_A);
                target_addr = &ns_target->rrsets->addr;
            }
        }
    }
    else {
        // if !NOAUTH, target must be in auth or deleg space for this
        //   same zone, and we *must* have a legal address for it
        dmn_assert(ns_status == DNAME_AUTH || ns_status == DNAME_DELEG);
        if(!ns_target || !(target_addr = ltree_node_get_rrset_addr(ns_target)))
            log_fatal("Missing A and/or AAAA records for target nameserver in '%s%s NS %s'",
                logf_lstack(lstack, depth, zone->dname), logf_dname(this_ns->dname));
    }

    // use target_addr found via either path above
    if(target_addr) {
        this_ns->ad = target_addr;
        // treat as glue if NS for delegation, and addr is in delegation or ooz
        if(ns_status != DNAME_AUTH) {
            if(in_deleg)
                AD_SET_GLUE(this_ns->ad);
            ns_target->flags |= LTNFLAG_GUSED;
        }
    }
}

// Phase 1:
// Walks the entire ltree, accomplishing two things in a single pass:
// 1) Sanity-check of referential and structural things
//    that could not be checked as records were being added.
// 2) Setting various inter-node pointers for the dnspacket code (and
//    Phase 2) to chase later.
F_NONNULL
static void ltree_postproc_phase1(const uint8_t** lstack, const ltree_node_t* node, const zoneinfo_t* zone, const unsigned depth, const bool in_deleg) {
    dmn_assert(lstack); dmn_assert(node); dmn_assert(zone);

    bool node_has_rfc3597 = false;
    ltree_rrset_addr_t* node_addr = NULL;
    ltree_rrset_cname_t* node_cname = NULL;
    ltree_rrset_ns_t* node_ns = NULL;
    ltree_rrset_ptr_t* node_ptr = NULL;
    ltree_rrset_mx_t* node_mx = NULL;
    ltree_rrset_srv_t* node_srv = NULL;
    ltree_rrset_naptr_t* node_naptr = NULL;
    ltree_rrset_txt_t* node_txt = NULL;
    ltree_rrset_txt_t* node_spf = NULL;

    {
        ltree_rrset_t* rrset = node->rrsets;
        while(rrset) {
            switch(rrset->gen.type) {
                case DNS_TYPE_A:     node_addr  = &rrset->addr; break;
                case DNS_TYPE_SOA:   /* phase1 doesn't use SOA */ break;
                case DNS_TYPE_CNAME: node_cname = &rrset->cname; break;
                case DNS_TYPE_NS:    node_ns    = &rrset->ns; break;
                case DNS_TYPE_PTR:   node_ptr   = &rrset->ptr; break;
                case DNS_TYPE_MX:    node_mx    = &rrset->mx; break;
                case DNS_TYPE_SRV:   node_srv   = &rrset->srv; break;
                case DNS_TYPE_NAPTR: node_naptr = &rrset->naptr; break;
                case DNS_TYPE_TXT:   node_txt   = &rrset->txt; break;
                case DNS_TYPE_SPF:   node_spf   = &rrset->txt; break;
                default:             node_has_rfc3597 = true; break;
            }
            rrset = rrset->gen.next;
        }
    }

    if(in_deleg) {
        dmn_assert(depth > 0);
        if(lstack[depth - 1][0] == 1 && lstack[depth - 1][1] == '*')
            log_fatal("Domainname '%s%s': Wildcards not allowed for delegation/glue data", logf_lstack(lstack, depth, zone->dname));

        if(node_cname
           || node_ptr
           || node_mx
           || node_srv
           || node_naptr
           || node_txt
           || node_spf
           || (node_ns && !(node->flags & LTNFLAG_DELEG))
           || node_has_rfc3597)
            log_fatal("Delegated sub-zone '%s%s' can only have NS and/or address records as appropriate", logf_lstack(lstack, depth, zone->dname));
    }

    if(node_cname) {
        dmn_assert(!(node->flags & LTNFLAG_ZROOT)); // Because we checked this earlier in add_rec_cname
        if(node->rrsets->gen.next)
            log_fatal("CNAME not allowed alongside other data at domainname '%s%s'", logf_lstack(lstack, depth, zone->dname));
        if(node_cname->gen.is_static)
            p1_proc_cname(zone, node_cname, lstack, depth);
        return; // CNAME can't co-exist with others, so we're done here
    }

    if(node_addr && node_addr->gen.is_static)
        fix_addr_limits(node_addr);

    if(node_ns)
        for(unsigned i = 0; i < node_ns->gen.count; i++)
            p1_proc_ns(zone, in_deleg, &(node_ns->rdata[i]), lstack, depth);

    if(node_ptr)
        for(unsigned i = 0; i < node_ptr->gen.count; i++)
            if(!set_valid_addr(node_ptr->rdata[i].dname, zone, &(node_ptr->rdata[i].ad)))
                log_strict("In rrset '%s%s PTR', same-zone target '%s' has no addresses", logf_lstack(lstack, depth, zone->dname), logf_dname(node_ptr->rdata[i].dname));

    if(node_mx)
        for(unsigned i = 0; i < node_mx->gen.count; i++)
            if(!set_valid_addr(node_mx->rdata[i].dname, zone, &(node_mx->rdata[i].ad)))
                log_strict("In rrset '%s%s MX', same-zone target '%s' has no addresses", logf_lstack(lstack, depth, zone->dname), logf_dname(node_mx->rdata[i].dname));

    if(node_srv)
        for(unsigned i = 0; i < node_srv->gen.count; i++)
            if(!set_valid_addr(node_srv->rdata[i].dname, zone, &(node_srv->rdata[i].ad)))
                log_strict("In rrset '%s%s SRV', same-zone target '%s' has no addresses", logf_lstack(lstack, depth, zone->dname), logf_dname(node_srv->rdata[i].dname));

    if(node_naptr) {
        for(unsigned i = 0; i < node_naptr->gen.count; i++) {
            if(binstr_hasichr(node_naptr->rdata[i].texts[NAPTR_TEXTS_FLAGS], 'A')) {
                if(!set_valid_addr(node_naptr->rdata[i].dname, zone, &(node_naptr->rdata[i].ad)))
                    log_strict("In rrset '%s%s NAPTR', same-zone A-target '%s' has no A or AAAA records", logf_lstack(lstack, depth, zone->dname), logf_dname(node_naptr->rdata[i].dname));
           }
        }
    }
}

// Phase 2:
//  Checks on unused glue RRs underneath delegations
//  Checks the total count of glue RRs per delegation
//  Checks TTL matching between NS and glue RRs
F_NONNULL
static void ltree_postproc_phase2(const uint8_t** lstack, const ltree_node_t* node, const zoneinfo_t* zone, const unsigned depth, const bool in_deleg) {
    dmn_assert(lstack); dmn_assert(node); dmn_assert(zone);

    if(in_deleg) {
        dmn_assert(!ltree_node_get_rrset_cname(node));
        if(ltree_node_get_rrset_addr(node) && !(node->flags & LTNFLAG_GUSED))
            log_warn("Delegation glue address(es) at domainname '%s%s' are unused and ignored", logf_lstack(lstack, depth, zone->dname));
        if(node->flags & LTNFLAG_DELEG) {
            ltree_rrset_ns_t* ns = ltree_node_get_rrset_ns(node);
            dmn_assert(ns);
            const unsigned nsct = ns->gen.count;
            ltree_rdata_ns_t* nsrd = ns->rdata;
            dmn_assert(nsct);
            dmn_assert(nsrd);
            unsigned num_glue = 0;
            for(unsigned i = 0; i < nsct; i++) {
                if(AD_IS_GLUE(nsrd[i].ad))
                    num_glue++;
            }
            if(num_glue > gconfig.max_addtl_rrsets)
                log_fatal("Delegation point '%s%s' has '%u' glued NS RRs, which is greater than the configured max_addtl_rrsets (%u)", logf_lstack(lstack, depth, zone->dname), num_glue, gconfig.max_addtl_rrsets);
        }
    }
}

F_NONNULLX(1, 2, 3)
static void _ltree_proc_inner(void (*fn)(const uint8_t**, const ltree_node_t*, const zoneinfo_t*, const unsigned, const bool), const uint8_t** lstack, ltree_node_t* node, const zoneinfo_t* zone, const unsigned depth, bool in_deleg) {
    dmn_assert(fn); dmn_assert(lstack); dmn_assert(node);

    if(node->flags & LTNFLAG_DELEG) {
        dmn_assert(!(node->flags & LTNFLAG_ZROOT));
        if(in_deleg)
            log_fatal("Delegation '%s%s' is within another delegation", logf_lstack(lstack, depth, zone->dname));
        in_deleg = true;
    }

    fn(lstack, node, zone, depth, in_deleg);

    // Recurse into children
    if(node->child_table) {
        const uint32_t cmask = node->child_hash_mask;
        for(uint32_t i = 0; i <= cmask; i++) {
            ltree_node_t* child = node->child_table[i];
            while(child) {
                lstack[depth] = child->label;
                _ltree_proc_inner(fn, lstack, child, zone, depth + 1, in_deleg);
                child = child->next;
            }
        }
    }
}

F_NONNULL
static void ltree_postproc_zone(const zoneinfo_t* zone, void (*fn)(const uint8_t**, const ltree_node_t*, const zoneinfo_t*, const unsigned, const bool)) {
    dmn_assert(zone); dmn_assert(fn);

    // label stack:
    //  used to reconstruct full domainnames
    //  for error/warning message output
    const uint8_t* lstack[127];

    _ltree_proc_inner(fn, lstack, zone->root, zone, 0, false);
}

F_NONNULL
static void ltree_postproc_zroot_phase1(const zoneinfo_t* zone) {
    dmn_assert(zone);

    ltree_node_t* zroot = zone->root;
    ltree_rrset_soa_t* zroot_soa = NULL;
    ltree_rrset_ns_t* zroot_ns = NULL;

    {
        ltree_rrset_t* rrset = zroot->rrsets;
        while(rrset) {
            switch(rrset->gen.type) {
                case DNS_TYPE_SOA:   zroot_soa   = &rrset->soa; break;
                case DNS_TYPE_NS:    zroot_ns    = &rrset->ns; break;
            }
            rrset = rrset->gen.next;
        }
    }

    dmn_assert(zroot->flags & LTNFLAG_ZROOT);
    if(!zroot_soa)
        log_fatal("Zone '%s' has no SOA record", logf_dname(zone->dname));
    if(!zroot_ns)
        log_fatal("Zone '%s' has no NS records", logf_dname(zone->dname));
    bool ok = false;
    dmn_assert(zroot_ns->gen.count);
    if(zroot_ns->gen.count < 2)
        log_warn("Zone '%s' only has one NS record, this is (probably) bad practice", logf_dname(zone->dname));
    for(unsigned i = 0; i < zroot_ns->gen.count; i++) {
        if(!memcmp(zroot_ns->rdata[i].dname, zroot_soa->master, *(zroot_soa->master) + 1)) {
            ok = true;
            break;
        }
    }
    if(!ok)
        log_warn("Zone '%s': SOA Master does not match any NS records for this zone", logf_dname(zone->dname));
}

static void ltree_postproc_zroot_phase2(const zoneinfo_t* zone) {
    ltree_node_t* ooz = ltree_node_find_child(zone->root, ooz_glue_label);
    if(ooz) {
        for(unsigned i = 0; i <= ooz->child_hash_mask; i++) {
            ltree_node_t* ooz_node = ooz->child_table[i];
            while(ooz_node) {
                if(!(ooz_node->flags & LTNFLAG_GUSED))
                    log_warn("In zone '%s', explicit out-of-zone glue address(es) at domainname '%s' are unused and ignored", logf_dname(zone->dname), logf_dname(ooz_node->label));
                ooz_node = ooz_node->next;
            }
        }
        ooz_fix_addr_limits(zone->root);
    }
}

F_NONNULL
static void ltree_fix_masks(ltree_node_t* node) {
    dmn_assert(node);
    const uint32_t cmask = count2mask(node->child_hash_mask);
    node->child_hash_mask = cmask;
    if(node->child_table) {
        for(uint32_t i = 0; i <= cmask; i++) {
            ltree_node_t* child = node->child_table[i];
            while(child) {
                ltree_fix_masks(child);
                child = child->next;
            }
        }
    }
}

// local forward decl
static void ltree_destroy(void);

// common processing for rootserver zone or normal zones
static void process_zone(zoneinfo_t* zone) {
    zone->root->flags = LTNFLAG_ZROOT;
    scan_zone(zone);
    lta_close(zone->arena);
    ltree_fix_masks(zone->root);

    // zroot phase1 is a readonly check of zone basics
    //   (e.g. NS/SOA existence)
    ltree_postproc_zroot_phase1(zone);
    // tree phase1 does a ton of readonly per-node checks
    //   (e.g. junk inside delegations, CNAME depth, CNAME
    //    does not have partner rrsets)
    // It also sets additional-data pointers from various
    //   other RR-types -> address rrsets, including
    //   flagging glue in the glue-address cases and
    //   marking it as used.  Ditto for additional data
    //   for local CNAME targets.
    ltree_postproc_zone(zone, ltree_postproc_phase1);

    // zroot phase2 checks for unused out-of-zone glue addresses,
    //   and also does the standard address limit>count fixups on them
    ltree_postproc_zroot_phase2(zone);
    // tree phase2 looks for unused delegation glue addresses,
    //   and delegation glue address sets that exceed max_addtl_rrsets
    ltree_postproc_zone(zone, ltree_postproc_phase2);
}

void ltree_load_zones(void) {
    dmn_assert(gconfig.num_zones);

    // Initialize the global (root-level) ltarena and ltree_root
    lta = lta_new();
    ltree_root = calloc(1, sizeof(ltree_node_t));
    ltree_root->label = lta_labeldup(lta, (uint8_t*)"");

    // rootserver case (if num_zones > 1, by definition duplication
    //   or subzoning will cause a quick failure if one of them is the root)
    if(gconfig.num_zones == 1 && gconfig.zones[0].dname[0] == 1 && gconfig.zones[0].dname[1] == 0) {
        rootserver = true;
        zoneinfo_t* auth_root = &gconfig.zones[0];
        auth_root->arena = lta;
        auth_root->root = ltree_root;
        process_zone(auth_root);
    }
    else {
       // normal zones under a non-authoritative root
       for(unsigned i = 0; i < gconfig.num_zones; i++) {
           zoneinfo_t* zone = &gconfig.zones[i];
           zone->arena = lta_new();
           zone->root = ltree_find_or_add_dname_zroot(zone);
           process_zone(zone);
       }
       // Close the top-level ltarena to further allocations.
       lta_close(lta);
       // Fixup masks in the non-auth areas above the zone roots
       // This also redundantly fixes the auth nodes themselves,
       //   but no point branching for it in the long run...
       ltree_fix_masks(ltree_root);
    }

#ifndef NDEBUG
    atexit(ltree_destroy);
#endif
}

static void ltree_node_destroy(ltree_node_t* node) {
    dmn_assert(node);
    ltree_rrset_t* rrset = node->rrsets;
    while(rrset) {
        ltree_rrset_t* next = rrset->gen.next;
        switch(rrset->gen.type) {
            case DNS_TYPE_A:
                if(rrset->gen.is_static) {
                    if(rrset->addr.addrs.v4)
                        free(rrset->addr.addrs.v4);
                    if(rrset->addr.addrs.v6)
                        free(rrset->addr.addrs.v6);
                }
                break;

            case DNS_TYPE_NAPTR:
                for(unsigned i = 0; i < rrset->gen.count; i++) {
                    free(rrset->naptr.rdata[i].texts[NAPTR_TEXTS_REGEXP]);
                    free(rrset->naptr.rdata[i].texts[NAPTR_TEXTS_SERVICES]);
                    free(rrset->naptr.rdata[i].texts[NAPTR_TEXTS_FLAGS]);
                }
                free(rrset->naptr.rdata);
                break;
            case DNS_TYPE_TXT:
            case DNS_TYPE_SPF:
                for(unsigned i = 0; i < rrset->gen.count; i++) {
                    uint8_t** tptr = rrset->txt.rdata[i];
                    uint8_t* t;
                    while((t = *tptr++))
                        free(t);
                    free(rrset->txt.rdata[i]);
                }
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
                break;
            default:
                for(unsigned i = 0; i < rrset->gen.count; i++)
                   free(rrset->rfc3597.rdata[i].rd);
                free(rrset->rfc3597.rdata);
                break;
        }
        free(rrset);
        rrset = next;
    }

    if(node->child_table) {
        const uint32_t cmask = count2mask(node->child_hash_mask);
        for(unsigned i = 0; i <= cmask; i++) {
            ltree_node_t* child = node->child_table[i];
            while(child) {
                ltree_node_t* next = child->next;
                ltree_node_destroy(child);
                child = next;
            }
        }
    }

    free(node->child_table);
    free(node);
}

static void ltree_destroy(void) {
    ltree_node_destroy(ltree_root);
    ltree_root = NULL;
    if(!rootserver)
        for(unsigned i = 0; i < gconfig.num_zones; i++)
            lta_destroy(gconfig.zones[i].arena);
    lta_destroy(lta);
    lta = NULL;
}
