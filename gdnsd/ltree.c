/* Copyright © 2011 Brandon L Black <blblack@gmail.com> and Jay Reitz <jreitz@gmail.com>
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
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "conf.h"
#include "dnspacket.h"
#include "ltarena.h"

// This is the global singleton ltree_root
ltree_node_t* ltree_root = NULL;

// special label used to hide out-of-zone glue
//  inside zone root node child lists
static const uint8_t ooz_glue_label[2] = { 0, 0 };

#define log_strict(...)\
    do {\
        if(gconfig.strict_data)\
            log_fatal("strict_data: " __VA_ARGS__);\
        else\
            log_warn("strict_data: " __VA_ARGS__);\
    } while(0)

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
static ltree_node_t* ltree_node_find_or_add_child(ltree_node_t* node, const uint8_t* child_label) {
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

    child = lta_malloc_p(sizeof(ltree_node_t));
    child->label = lta_labeldup(child_label);
    child->next = node->child_table[child_hash];
    node->child_table[child_hash] = child;

    if(node->child_hash_mask == child_mask)
        ltree_childtable_grow(node);
    node->child_hash_mask++;

    return child;
}

F_NONNULL
static ltree_node_t* ltree_find_or_add_dname(const uint8_t* dname, const bool init_zone_root) {
    dmn_assert(dname); dmn_assert(dname_status(dname) == DNAME_VALID);

    // Construct a label stack from dname
    const uint8_t* lstack[127];
    dname++; // skip overall len byte
    unsigned lcount = 0; // label count
    uint8_t llen; // current label len
    while((llen = *dname)) {
        dmn_assert(lcount < 127);
        lstack[lcount++] = dname++;
        dname += llen;
    }

    bool in_zone_root = false;
    if(ltree_root->flags & LTNFLAG_ZROOT) in_zone_root = true;
    ltree_node_t* current = ltree_root;

    while(lcount--) {
        ltree_node_t* next = ltree_node_find_or_add_child(current, lstack[lcount]);
        if(in_zone_root)
            next->flags |= LTNFLAG_AUTH;
        else if(next->flags & LTNFLAG_ZROOT)
            in_zone_root = true;
        current = next;
    }

    if(init_zone_root)
        current->flags = (LTNFLAG_ZROOT | LTNFLAG_AUTH);
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
    *store_at = lta_malloc_p(sizeof(ltree_rrset_ ## _typ ## _t));\
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

void ltree_add_rec_a(const uint8_t* dname, uint32_t addr, unsigned ttl, unsigned limit_v4, const uint8_t* ooz_zroot) {
    dmn_assert(dname);

    ltree_node_t* node;
    if(ooz_zroot) {
        ltree_node_t* zroot = ltree_find_or_add_dname(ooz_zroot, false);
        dmn_assert(zroot->flags & LTNFLAG_ZROOT);
        ltree_node_t* ooz = ltree_node_find_or_add_child(zroot, ooz_glue_label);
        node = ltree_node_find_or_add_child(ooz, dname);
    }
    else {
        node = ltree_find_or_add_dname(dname, false);
    }

    ltree_rrset_addr_t* rrset = ltree_node_get_rrset_addr(node);
    if(!rrset) {
        rrset = ltree_node_add_rrset_addr(node);
        rrset->a.addrs.v4 = malloc(sizeof(uint32_t));
        rrset->a.addrs.v4[0] = addr;
        rrset->gen.c.c.count_v4 = 1;
        rrset->gen.ttl = htonl(ttl);
        rrset->limit_v4 = limit_v4;
    }
    else {
        if(!rrset->gen.c.is_static)
            log_fatal("Name '%s': DYNA cannot co-exist at the same name as A and/or AAAA", logf_dname(dname));
        if(rrset->gen.ttl != htonl(ttl))
            log_strict("Name '%s': All TTLs for A and/or AAAA records at the same name must agree", logf_dname(dname));
        if(rrset->gen.c.c.count_v4 == UINT8_MAX)
            log_fatal("Name '%s': Too many RRs of type A", logf_dname(dname));
        if(rrset->gen.c.c.count_v4 > 0 && rrset->limit_v4 != limit_v4)
            log_strict("Name '%s': All $ADDR_LIMIT_4 for A-records at the same name must agree", logf_dname(dname));
        rrset->limit_v4 = limit_v4;
        rrset->a.addrs.v4 = realloc(rrset->a.addrs.v4, sizeof(uint32_t) * (1 + rrset->gen.c.c.count_v4));
        rrset->a.addrs.v4[rrset->gen.c.c.count_v4++] = addr;
    }
}

void ltree_add_rec_aaaa(const uint8_t* dname, const uint8_t* addr, unsigned ttl, unsigned limit_v6, const uint8_t* ooz_zroot) {
    dmn_assert(dname); dmn_assert(addr);

    ltree_node_t* node;
    if(ooz_zroot) {
        ltree_node_t* zroot = ltree_find_or_add_dname(ooz_zroot, false);
        dmn_assert(zroot->flags & LTNFLAG_ZROOT);
        ltree_node_t* ooz = ltree_node_find_or_add_child(zroot, ooz_glue_label);
        node = ltree_node_find_or_add_child(ooz, dname);
    }
    else {
        node = ltree_find_or_add_dname(dname, false);
    }

    ltree_rrset_addr_t* rrset = ltree_node_get_rrset_addr(node);
    if(!rrset) {
        rrset = ltree_node_add_rrset_addr(node);
        rrset->a.addrs.v6 = malloc(16);
        memcpy(rrset->a.addrs.v6, addr, 16);
        rrset->gen.c.c.count_v6 = 1;
        rrset->gen.ttl = htonl(ttl);
        rrset->limit_v6 = limit_v6;
    }
    else {
        if(!rrset->gen.c.is_static)
            log_fatal("Name '%s': DYNA cannot co-exist at the same name as A and/or AAAA", logf_dname(dname));
        if(rrset->gen.ttl != htonl(ttl))
            log_strict("Name '%s': All TTLs for A and/or AAAA records at the same name must agree", logf_dname(dname));
        if(rrset->gen.c.c.count_v6 == UINT8_MAX)
            log_fatal("Name '%s': Too many RRs of type AAAA", logf_dname(dname));
        if(rrset->gen.c.c.count_v6 > 0 && rrset->limit_v6 != limit_v6)
            log_strict("Name '%s': All $ADDR_LIMIT_6 for AAAA-records at the same name must agree", logf_dname(dname));
        rrset->limit_v6 = limit_v6;
        rrset->a.addrs.v6 = realloc(rrset->a.addrs.v6, 16 * (1 + rrset->gen.c.c.count_v6));
        memcpy(rrset->a.addrs.v6 + (rrset->gen.c.c.count_v6++ * 16), addr, 16);
    }
}

void ltree_add_rec_dynaddr(const uint8_t* dname, const uint8_t* rhs, unsigned ttl, unsigned limit_v4, unsigned limit_v6) {
    dmn_assert(dname); dmn_assert(rhs);

    ltree_node_t* node = ltree_find_or_add_dname(dname, false);

    ltree_rrset_addr_t* rrset;
    if((rrset = ltree_node_get_rrset_addr(node))) {
        if(rrset->gen.c.is_static)
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
            rrset->a.dyn.resource = p->map_resource_dyna ? p->map_resource_dyna(resource_name) : 0;
            rrset->a.dyn.func = p->resolve_dynaddr;
            free(plugin_name);
        }
        return;
    }

    log_fatal("Name '%s': DYNA RR refers to plugin '%s', which is not loaded", logf_dname(dname), plugin_name);
}

void ltree_add_rec_cname(const uint8_t* dname, const uint8_t* rhs, unsigned ttl) {
    dmn_assert(dname); dmn_assert(rhs);

    ltree_node_t* node = ltree_find_or_add_dname(dname, false);

    // This zone root check is redundant given some other checks
    //   in the processing phases, but it's still a nice explicit
    //   early bailout point.
    if(node->flags & LTNFLAG_ZROOT)
        log_fatal("Name '%s': No CNAME allowed at a zone root", logf_dname(dname));

    if(ltree_node_get_rrset_cname(node))
        log_fatal("Name '%s': Only one CNAME or DYNC record can exist for a given name", logf_dname(dname));

    ltree_rrset_cname_t* rrset = ltree_node_add_rrset_cname(node);
    rrset->c.dname = lta_dnamedup_hashed(rhs);
    rrset->gen.ttl = htonl(ttl);
    rrset->gen.c.is_static = true;
}

void ltree_add_rec_dyncname(const uint8_t* dname, const uint8_t* rhs, const uint8_t* origin, unsigned ttl) {
    dmn_assert(dname); dmn_assert(rhs);

    ltree_node_t* node = ltree_find_or_add_dname(dname, false);

    // This zone root check is redundant given some other checks
    //   in the processing phases, but it's still a nice explicit
    //   early bailout point.
    if(node->flags & LTNFLAG_ZROOT)
        log_fatal("Name '%s': No CNAME allowed at a zone root", logf_dname(dname));

    if(ltree_node_get_rrset_cname(node))
        log_fatal("Name '%s': Only one CNAME or DYNC record can exist for a given name", logf_dname(dname));
  
    ltree_rrset_cname_t* rrset = ltree_node_add_rrset_cname(node);
    rrset->c.dyn.origin = lta_dnamedup_hashed(origin);
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
            // we pass rrset->c.dyn.origin instead of origin here, in case the plugin author saves the pointer
            //  (which he probably shouldn't, but can't hurt to make life easier)
            rrset->c.dyn.resource = p->map_resource_dync ? p->map_resource_dync(resource_name, rrset->c.dyn.origin) : 0;
            rrset->c.dyn.func = p->resolve_dyncname;
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
#define INSERT_NEXT_RR(_typ, _nam, _pnam) \
    ltree_rdata_ ## _typ ## _t* new_rdata;\
    ltree_rrset_ ## _typ ## _t* rrset = ltree_node_get_rrset_ ## _nam (node);\
{\
    if(!rrset) {\
        rrset = ltree_node_add_rrset_ ## _nam (node);\
        rrset->gen.c.count = 1;\
        rrset->gen.ttl = htonl(ttl);\
        new_rdata = rrset->rdata = malloc(sizeof(ltree_rdata_ ## _typ ## _t));\
    }\
    else {\
        if(rrset->gen.ttl != htonl(ttl))\
            log_strict("Name '%s': All TTLs for type %s must match", logf_dname(dname), _pnam);\
        if(rrset->gen.c.count == UINT16_MAX)\
            log_fatal("Name '%s': Too many RRs of type %s", logf_dname(dname), _pnam);\
        rrset->rdata = realloc(rrset->rdata, (1 + rrset->gen.c.count) * sizeof(ltree_rdata_ ## _typ ## _t));\
        new_rdata = &rrset->rdata[rrset->gen.c.count++];\
    }\
}

void ltree_add_rec_ptr(const uint8_t* dname, const uint8_t* rhs, unsigned ttl) {
    dmn_assert(dname); dmn_assert(rhs);

    ltree_node_t* node = ltree_find_or_add_dname(dname, false);

    INSERT_NEXT_RR(ptr, ptr, "PTR");
    new_rdata->dname = lta_dnamedup_hashed(rhs);
    new_rdata->ad = NULL;
}

void ltree_add_rec_ns(const uint8_t* dname, const uint8_t* rhs, unsigned ttl) {
    dmn_assert(dname); dmn_assert(rhs);

    ltree_node_t* node = ltree_find_or_add_dname(dname, false);

    if(node->label[0] == 1 && node->label[1] == '*')
        log_fatal("Name '%s': Cannot delegate via wildcards", logf_dname(dname));

    // If this is a delegation by definition, (NS rec not at zone root), flag it
    if(!(node->flags & LTNFLAG_ZROOT))
        node->flags |= LTNFLAG_DELEG;

    INSERT_NEXT_RR(ns, ns, "NS")
    new_rdata->dname = lta_dnamedup_hashed(rhs);
    new_rdata->ad = NULL;
}

void ltree_add_rec_mx(const uint8_t* dname, const uint8_t* rhs, unsigned ttl, unsigned pref) {
    dmn_assert(dname); dmn_assert(rhs);

    if(pref > 65535U) log_fatal("Name '%s': MX preference value %u too large", logf_dname(dname), pref);

    ltree_node_t* node = ltree_find_or_add_dname(dname, false);

    INSERT_NEXT_RR(mx, mx, "MX")
    new_rdata->dname = lta_dnamedup_hashed(rhs);
    new_rdata->pref = htons(pref);
    new_rdata->ad = NULL;
}

void ltree_add_rec_srv(const uint8_t* dname, const uint8_t* rhs, unsigned ttl, unsigned priority, unsigned weight, unsigned port) {
    dmn_assert(dname); dmn_assert(rhs);

    if(priority > 65535U) log_fatal("Name '%s': SRV priority value %u too large", logf_dname(dname), priority);
    if(weight > 65535U) log_fatal("Name '%s': SRV weight value %u too large", logf_dname(dname), weight);
    if(port > 65535U) log_fatal("Name '%s': SRV port value %u too large", logf_dname(dname), port);

    ltree_node_t* node = ltree_find_or_add_dname(dname, false);

    INSERT_NEXT_RR(srv, srv, "SRV")
    new_rdata->dname = lta_dnamedup_hashed(rhs);
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
 *
 * However, we still scan for the flags 'S' or 'A' and add the appropriate
 *   Additional Records if we spot them (later, during phase1 of post processing).
 *   This is based on RFC2195 and normal usage on the internet, although they aren't
 *   explicitly mentioned in RFC 3403 anymore.
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
            log_strict("Name '%s': NAPTR has illegal flag char '%c'", logf_dname(dname), c);
    }
}

void ltree_add_rec_naptr(const uint8_t* dname, const uint8_t* rhs, unsigned ttl, unsigned order, unsigned pref, unsigned num_texts V_UNUSED, uint8_t** texts) {
    dmn_assert(dname); dmn_assert(rhs); dmn_assert(texts); dmn_assert(num_texts == 3);

    if(order > 65535U) log_fatal("Name '%s': NAPTR order value %u too large", logf_dname(dname), order);
    if(pref > 65535U) log_fatal("Name '%s': NAPTR preference value %u too large", logf_dname(dname), pref);
    naptr_validate_flags(dname, texts[NAPTR_TEXTS_FLAGS]);

    if(rhs[1] != 0 && texts[NAPTR_TEXTS_REGEXP][0])
        log_strict("Name '%s': NAPTR does not allow defining both Regexp and Replacement in a single RR", logf_dname(dname));

    ltree_node_t* node = ltree_find_or_add_dname(dname, false);

    INSERT_NEXT_RR(naptr, naptr, "NAPTR")
    new_rdata->dname = lta_dnamedup_hashed(rhs);
    new_rdata->order = htons(order);
    new_rdata->pref = htons(pref);
    memcpy(new_rdata->texts, texts, sizeof(new_rdata->texts));
    new_rdata->ad = NULL;
}

// We copy the array of pointers, but alias the actual data (which is malloc'd for
//   us per call in the parser).
void ltree_add_rec_txt(const uint8_t* dname, unsigned num_texts, uint8_t** texts, unsigned ttl) {
    dmn_assert(dname); dmn_assert(texts); dmn_assert(num_texts);

    ltree_node_t* node = ltree_find_or_add_dname(dname, false);

    INSERT_NEXT_RR(txt, txt, "TXT")
    *new_rdata = lta_malloc_p((num_texts + 1) * sizeof(uint8_t*));
    memcpy(*new_rdata, texts, (num_texts + 1) * sizeof(uint8_t*));
}

void ltree_add_rec_spf(const uint8_t* dname, unsigned num_texts, uint8_t** texts, unsigned ttl) {
    dmn_assert(dname); dmn_assert(texts); dmn_assert(num_texts);

    ltree_node_t* node = ltree_find_or_add_dname(dname, false);

    INSERT_NEXT_RR(txt, spf, "SPF")
    *new_rdata = lta_malloc_p((num_texts + 1) * sizeof(uint8_t*));
    memcpy(*new_rdata, texts, (num_texts + 1) * sizeof(uint8_t*));
}

// This handles 'foo SPF+ "v=spf1 ..."' and makes both TXT and SPF recs for it, conveniently
//  aliasing all the string storage
void ltree_add_rec_spftxt(const uint8_t* dname, unsigned texts_size, uint8_t** texts, unsigned ttl) {
    ltree_add_rec_txt(dname, texts_size, texts, ttl);
    ltree_add_rec_spf(dname, texts_size, texts, ttl);
}

void ltree_add_rec_soa(const uint8_t* dname, const uint8_t* master, const uint8_t* email, unsigned ttl, unsigned serial, unsigned refresh, unsigned retry, unsigned expire, unsigned ncache) {
    dmn_assert(dname); dmn_assert(master); dmn_assert(email);

    if(ncache > 10800U)
        log_strict("Zone '%s': SOA negative-cache field too large (%u, must be <= 10800)", logf_dname(dname), ncache);

    ltree_node_t* node = ltree_find_or_add_dname(dname, false);

    if(ltree_node_get_rrset_soa(node))
        log_fatal("Zone '%s': SOA defined twice", logf_dname(dname));

    ltree_rrset_soa_t* soa = ltree_node_add_rrset_soa(node);
    soa->email = lta_dnamedup_hashed(email);
    soa->master = lta_dnamedup_hashed(master);

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
    *store_at = lta_malloc_p(sizeof(ltree_rrset_rfc3597_t));
    (*store_at)->gen.type = rrtype;
    return &(*store_at)->rfc3597;
}


void ltree_add_rec_rfc3597(const uint8_t* dname, unsigned rrtype, unsigned ttl, unsigned rdlen, uint8_t* rd) {
    dmn_assert(dname);

    ltree_node_t* node = ltree_find_or_add_dname(dname, false);

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
        rrset->gen.c.count = 1;
        rrset->gen.ttl = htonl(ttl);
        new_rdata = rrset->rdata = malloc(sizeof(ltree_rdata_rfc3597_t));
    }
    else {
        if(rrset->gen.ttl != htonl(ttl))
            log_strict("Name '%s': All TTLs for type RFC3597 TYPE%u must match", logf_dname(dname), rrtype);
        if(rrset->gen.c.count == UINT16_MAX)
            log_fatal("Name '%s': Too many RFC3597 RRs of type TYPE%u", logf_dname(dname), rrtype);
        rrset->rdata = realloc(rrset->rdata, (1 + rrset->gen.c.count) * sizeof(ltree_rdata_rfc3597_t));
        new_rdata = &rrset->rdata[rrset->gen.c.count++];
    }

    new_rdata->rdlen = rdlen;
    new_rdata->rd = rd;
}

F_NONNULL
static ltree_dname_status_t ltree_search_dname(const uint8_t* restrict dname, const ltree_node_t* checkroot, bool* crossed_checkroot, ltree_node_t** restrict node_out) {
    dmn_assert(dname); dmn_assert(*dname != 0); dmn_assert(*dname != 2); dmn_assert(checkroot); dmn_assert(crossed_checkroot); dmn_assert(!*crossed_checkroot); dmn_assert(node_out);

    // construct label ptr stack
    const uint8_t* lptr_stack[127];
    unsigned label_idx = 0;

    {
        uint8_t llen;
        ++dname;
        while((llen = *dname)) {
            dmn_assert(label_idx < 127);
            lptr_stack[label_idx++] = dname++;
            dname += llen;
        }
    }

    ltree_dname_status_t rval = DNAME_NOAUTH;
    *node_out = NULL;

    ltree_node_t* current = ltree_root;

    do {
        top_loop:;
        if(current == checkroot)
            *crossed_checkroot = true;

        if(current->flags & LTNFLAG_ZROOT) {
            dmn_assert(current->flags & LTNFLAG_AUTH);
            rval = DNAME_AUTH;
        }
        else if(current->flags & LTNFLAG_DELEG) {
            rval = DNAME_DELEG;
        }

        if(!label_idx) {
            if(rval != DNAME_NOAUTH) *node_out = current;
            return rval;
        }

        if(!current->child_table) return rval;

        label_idx--;
        const uint8_t* child_label = lptr_stack[label_idx];
        ltree_node_t* entry = current->child_table[label_djb_hash(child_label, current->child_hash_mask)];

        while(entry) {
            if(!memcmp(entry->label, child_label, *child_label + 1)) {
                current = entry;
                goto top_loop;
            }
            entry = entry->next;
        }
    } while(0);

    // Getting here means no explicit match or other terminal condition found,
    //  but we still have a child_table in auth space that might contain a wildcard...
    if(rval == DNAME_AUTH) {
        dmn_assert(current->child_table);
        dmn_assert(current->flags);
        ltree_node_t* entry = current->child_table[label_djb_hash((const uint8_t*)"\001*", current->child_hash_mask)];

        while(entry) {
            if(entry->label[0] == '\001' && entry->label[1] == '*') {
                *node_out = entry;
                break;
            }
            entry = entry->next;
        }
    }

    return rval;
}

// retval: true, all is well (although we didn't necessarily set an address)
//         false, the target points at an authoritative name in the same zone which doesn't exist
F_NONNULL
static bool set_valid_addr(const uint8_t* dname, const ltree_node_t* zone_root, ltree_rrset_addr_t** addr_out) {
    dmn_assert(dname); dmn_assert(*dname); dmn_assert(zone_root); dmn_assert(addr_out);

    ltree_node_t* node;
    bool crossed_root = false;
    const ltree_dname_status_t status = ltree_search_dname(dname, zone_root, &crossed_root, &node);

    *addr_out = NULL;
    if(status == DNAME_AUTH && crossed_root)
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
        if(!node_addr->limit_v4 || node_addr->limit_v4 > node_addr->gen.c.c.count_v4)
            node_addr->limit_v4 = node_addr->gen.c.c.count_v4;
        if(!node_addr->limit_v6 || node_addr->limit_v6 > node_addr->gen.c.c.count_v6)
            node_addr->limit_v6 = node_addr->gen.c.c.count_v6;
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

static void p1_proc_cname(const ltree_node_t* zone_root, ltree_rrset_cname_t* node_cname, const uint8_t** lstack, const unsigned depth) {
    bool crossed_root = false;
    ltree_node_t* cn_target;
    ltree_dname_status_t cnstat = ltree_search_dname(node_cname->c.dname, zone_root, &crossed_root, &cn_target);
    if(cnstat == DNAME_AUTH) {
        if(!cn_target) {
            log_strict("CNAME '%s' points to known NXDOMAIN '%s'",
                logf_lstack(lstack, depth), logf_dname(node_cname->c.dname));
        }
        else if(!cn_target->rrsets) {
            log_strict("CNAME '%s' points to '%s' which has no data",
                logf_lstack(lstack, depth), logf_dname(node_cname->c.dname));
        }
    }

    unsigned cn_depth = 1;
    while(cnstat == DNAME_AUTH && cn_target && cn_target->rrsets && cn_target->rrsets->gen.type == DNS_TYPE_CNAME && cn_target->rrsets->gen.c.is_static) {
        if(++cn_depth > gconfig.max_cname_depth) {
            log_fatal("CNAME '%s' leads to a CNAME chain longer than %u (max_cname_depth)", logf_lstack(lstack, depth), gconfig.max_cname_depth);
            break;
        }
        ltree_rrset_cname_t* cur_cname = &cn_target->rrsets->cname;
        crossed_root = false;
        cnstat = ltree_search_dname(cur_cname->c.dname, zone_root, &crossed_root, &cn_target);
    }
}

F_NONNULL
static void p1_proc_ns(const ltree_node_t* zone_root, ltree_rdata_ns_t* this_ns, const uint8_t** lstack, const unsigned depth) {
    dmn_assert(zone_root); dmn_assert(this_ns);
    dmn_assert(!this_ns->ad);

    bool crossed_root = false;
    ltree_node_t* ns_target;
    ltree_rrset_addr_t* target_addr = NULL;
    ltree_rrset_addr_t* ooz_target_addr = NULL;
    ltree_dname_status_t ns_status = ltree_search_dname(this_ns->dname, zone_root, &crossed_root, &ns_target);

    // if !crossed_root, it's out-of-zone glue, so we first check for
    //   explicit ooz glue from the current zone's zonefile
    if(!crossed_root) {
        ltree_node_t* ooz = ltree_node_find_child(zone_root, ooz_glue_label);
        if(ooz) {
            ltree_node_t* ooz_glue = ltree_node_find_child(ooz, this_ns->dname);
            if(ooz_glue) {
                ooz_glue->flags |= LTNFLAG_GUSED;
                dmn_assert(ooz_glue->rrsets);
                dmn_assert(!ooz_glue->child_table);
                // no need to check DYNA, zonefile parser doesn't allow it
                ooz_target_addr = &ooz_glue->rrsets->addr;
                dmn_assert(ooz_target_addr->gen.type == DNS_TYPE_A);
                this_ns->ad = ooz_target_addr;
                // if the user bothered to spec these, they may really need them,
                //   so require truncation if they don't fit
                AD_SET_GLUE(this_ns->ad);
            }
        }
    }

    // orthogonally, the glue may be in some zone we serve a zonefile for
    if(ns_status == DNAME_AUTH || ns_status == DNAME_DELEG) {

        // if crossed_root, the NS target is in our zone (directly or delegated),
        //   and we *must* have legal glue for it
        if(crossed_root) {
            if(!ns_target || !(target_addr = ltree_node_get_rrset_addr(ns_target)))
                log_fatal("Missing A and/or AAAA records for target nameserver in '%s NS %s'",
                    logf_lstack(lstack, depth), logf_dname(this_ns->dname));
        }

        // Could also exist in another zonefile...
        // If the target name was in AUTH space, or exists as DELEG glue, do a
        //   log_strict check for existence
        else if(ns_status == DNAME_AUTH || ns_target) {
            if(!ns_target || !(target_addr = ltree_node_get_rrset_addr(ns_target)))
                log_strict("Missing cross-zone A and/or AAAA records for target nameserver in '%s NS %s'",
                    logf_lstack(lstack, depth), logf_dname(this_ns->dname));
        }

        // log_fatal check for DYNA, and then use the glue (without requiring TC unless it
        //   was truly a local in-bailiwick delegation glue).
        if(target_addr && !ooz_target_addr) {
            this_ns->ad = target_addr;
            if(ns_status == DNAME_DELEG) {
                if(crossed_root) AD_SET_GLUE(this_ns->ad);
                ns_target->flags |= LTNFLAG_GUSED;
            }
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
static void ltree_proc_phase1(const uint8_t** lstack, ltree_node_t* node, const ltree_node_t* zone_root, const unsigned depth, const bool in_deleg) {
    dmn_assert(node);

    bool node_has_rfc3597 = false;
    ltree_rrset_addr_t* node_addr = NULL;
    ltree_rrset_soa_t* node_soa = NULL;
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
                case DNS_TYPE_A:     node_addr	= &rrset->addr; break;
                case DNS_TYPE_SOA:   node_soa   = &rrset->soa; break;
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

    if(node->flags & LTNFLAG_ZROOT) {
        dmn_assert(node == zone_root);
        dmn_assert(!in_deleg);
        if(!node_soa)
            log_fatal("Zone '%s' has no SOA record", logf_lstack(lstack, depth));
        if(!node_ns)
            log_fatal("Zone '%s' has no NS records", logf_lstack(lstack, depth));
        bool ok = false;
        dmn_assert(node_ns->gen.c.count);
        for(unsigned i = 0; i < node_ns->gen.c.count; i++) {
            if(!memcmp(node_ns->rdata[i].dname, node_soa->master, *(node_soa->master) + 1)) {
                ok = true;
                break;
            }
        }
        if(!ok)
            log_strict("Zone '%s': SOA Master does not match any NS records for this zone", logf_lstack(lstack, depth));
        ooz_fix_addr_limits(node);
    }
    else {
        dmn_assert(node != zone_root);
    }

    if(in_deleg) {
        if(lstack[depth][0] == 1 && lstack[depth][1] == '*')
            log_fatal("Domainname '%s': Wildcards not allowed for delegation/glue data", logf_lstack(lstack, depth));

        if(node_cname
           || node_ptr
           || node_mx
           || node_srv
           || node_naptr
           || node_txt
           || node_spf
           || (node_ns && !(node->flags & LTNFLAG_DELEG))
           || node_has_rfc3597)
            log_fatal("Delegated name '%s' can only have NS and/or address records as appropriate", logf_lstack(lstack, depth));
    }

    if(node_cname) {
        dmn_assert(!(node->flags & LTNFLAG_ZROOT)); // Because we checked this earlier in add_rec_cname
        if(node->rrsets->gen.next)
            log_fatal("CNAME not allowed alongside other data at domainname '%s'", logf_lstack(lstack, depth));
        if(node_cname->gen.c.is_static)
            p1_proc_cname(zone_root, node_cname, lstack, depth);
        return; // CNAME can't co-exist with others, so we're done here
    }

    if(node_addr && node_addr->gen.c.is_static)
        fix_addr_limits(node_addr);

    if(node_ns)
        for(unsigned i = 0; i < node_ns->gen.c.count; i++)
            p1_proc_ns(zone_root, &(node_ns->rdata[i]), lstack, depth);

    if(node_ptr)
        for(unsigned i = 0; i < node_ptr->gen.c.count; i++)
            if(!set_valid_addr(node_ptr->rdata[i].dname, zone_root, &(node_ptr->rdata[i].ad)))
                log_strict("In rrset '%s PTR', same-zone target '%s' has no addresses", logf_lstack(lstack, depth), logf_dname(node_ptr->rdata[i].dname));

    if(node_mx)
        for(unsigned i = 0; i < node_mx->gen.c.count; i++)
            if(!set_valid_addr(node_mx->rdata[i].dname, zone_root, &(node_mx->rdata[i].ad)))
                log_strict("In rrset '%s MX', same-zone target '%s' has no addresses", logf_lstack(lstack, depth), logf_dname(node_mx->rdata[i].dname));

    if(node_srv)
        for(unsigned i = 0; i < node_srv->gen.c.count; i++)
            if(!set_valid_addr(node_srv->rdata[i].dname, zone_root, &(node_srv->rdata[i].ad)))
                log_strict("In rrset '%s SRV', same-zone target '%s' has no addresses", logf_lstack(lstack, depth), logf_dname(node_srv->rdata[i].dname));

    if(node_naptr) {
        for(unsigned i = 0; i < node_naptr->gen.c.count; i++) {
            if(binstr_hasichr(node_naptr->rdata[i].texts[NAPTR_TEXTS_FLAGS], 'A')) {
                if(!set_valid_addr(node_naptr->rdata[i].dname, zone_root, &(node_naptr->rdata[i].ad)))
                    log_strict("In rrset '%s NAPTR', same-zone A-target '%s' has no A or AAAA records", logf_lstack(lstack, depth), logf_dname(node_naptr->rdata[i].dname));
           }
        }
    }
}

F_NONNULL
static void p2_check_glue(const uint8_t** lstack, const ltree_rrset_ns_t* rrset_ns, const unsigned depth) {
    if(rrset_ns->gen.c.count > gconfig.max_addtl_rrsets)
        log_fatal("Delegation point '%s' has '%u' glued NS rrsets, which is greater than the configured max_addtl_rrsets (%u)", logf_lstack(lstack, depth), rrset_ns->gen.c.count, gconfig.max_addtl_rrsets);
}

static void ooz_check_glue(ltree_node_t* zroot) {
    ltree_node_t* ooz = ltree_node_find_child(zroot, ooz_glue_label);
    if(ooz) {
        for(unsigned i = 0; i <= ooz->child_hash_mask; i++) {
            ltree_node_t* ooz_node = ooz->child_table[i];
            while(ooz_node) {
                if(!(ooz_node->flags & LTNFLAG_GUSED))
                    log_strict("Glue address(es) at domainname '%s' are unused and ignored", logf_dname(ooz_node->label));
                ooz_node = ooz_node->next;
            }
        }
    }
}

// Phase 2:
//  Checks on unused glue RRs underneath delegations
//  Checks the total count of glue RRs per delegation
//  Checks TTL matching between NS and glue RRs
F_NONNULL
static void ltree_proc_phase2(const uint8_t** lstack, ltree_node_t* node, const ltree_node_t* zone_root, const unsigned depth, const bool in_deleg) {
    dmn_assert(node); dmn_assert(zone_root);

    if(in_deleg) {
        dmn_assert(!ltree_node_get_rrset_cname(node));
        if(ltree_node_get_rrset_addr(node) && !(node->flags & LTNFLAG_GUSED))
            log_strict("Glue address(es) at domainname '%s' are unused and ignored", logf_lstack(lstack, depth));
        if(node->flags & LTNFLAG_DELEG) {
            ltree_rrset_ns_t* ns = ltree_node_get_rrset_ns(node);
            dmn_assert(ns);
            p2_check_glue(lstack, ns, depth);
        }
    }

    if(node == zone_root)
        ooz_check_glue(node);
}

F_NONNULLX(1, 2)
static void _ltree_proc_inner(void (*fn)(const uint8_t**, ltree_node_t*, const ltree_node_t*, const unsigned, const bool), const uint8_t** lstack, ltree_node_t* node, const ltree_node_t* zone_root, unsigned depth, bool in_deleg) {
    dmn_assert(fn); dmn_assert(node);

    lstack[depth] = node->label;
    if(node->flags & LTNFLAG_ZROOT) {
        zone_root = node;
        in_deleg = false;
    }
    else if(node->flags & LTNFLAG_DELEG) {
        if(in_deleg)
            log_fatal("Delegation '%s' is directly within another delegation", logf_lstack(lstack, depth));
        in_deleg = true;
    }

    if(node->flags) fn(lstack, node, zone_root, depth, in_deleg);

    depth++;

    // Recurse into children
    if(node->child_table) {
        const uint32_t cmask = node->child_hash_mask;
        for(uint32_t i = 0; i <= cmask; i++) {
            ltree_node_t* child = node->child_table[i];
            while(child) {
                _ltree_proc_inner(fn, lstack, child, zone_root, depth, in_deleg);
                child = child->next;
            }
        }
    }
}

static void ltree_process(void (*fn)(const uint8_t**, ltree_node_t*, const ltree_node_t*, const unsigned, const bool)) {
    // label stack:
    //  used to reconstruct full domainnames
    //  for error/warning message output
    const uint8_t* lstack[128];

    dmn_assert(ltree_root);
    _ltree_proc_inner(fn, lstack, ltree_root, NULL, 0, false);
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

void ltree_load_zones(void) {
    // Initialize the ltarena and the root of the ltree
    lta_init();
    ltree_root = lta_malloc_p(sizeof(ltree_node_t));
    ltree_root->label = lta_labeldup((uint8_t*)"");

    for(unsigned i = 0; i < gconfig.num_zones; i++) {
        const zoneinfo_t* zone = &gconfig.zones[i];
        ltree_find_or_add_dname(zone->dname, true);
    }

    for(unsigned i = 0; i < gconfig.num_zones; i++) {
        const zoneinfo_t* zone = &gconfig.zones[i];
        scan_zone(zone);
    }

    // Close the ltarena to further allocations.  Mostly
    //  this frees the hash lta_dnamedup_hashed() uses.
    lta_close();

    log_debug("Post-processing all zone data");

    ltree_fix_masks(ltree_root); // Convert child_hash_mask from a count to a real mask
    ltree_process(&ltree_proc_phase1); // Create data links between nodes for
                                       // additional/glue, validate static CNAME chains

    ltree_process(&ltree_proc_phase2); // Glue-related checks that depend on full
                                       //  output of phase1

}
