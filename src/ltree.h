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

#ifndef GDNSD_LTREE_H
#define GDNSD_LTREE_H

// Basic data sanity limits applied to inputs from zone parsing:
// No more than 1024 RRs in an RRset
#define LTREE_RRSET_MAX_RRS 1024

/*

  ltree == "Label Tree", a representation of DNS data as a tree by domain
labels, e.g:
                        .
                       / \
                     com  net
                    /   \
                   /     \
               example   foo
                /   \
              www   ns1

  A whole ltree represents the whole of the DNS (for those zones defined in our
authoritative dataset, anyways) as a linked tree of per-label nodes starting at
the root.  During zone loading, detached per-zone trees are rooted at their
own zone root, and are later grafted onto the global ltree that starts at the
real root of the DNS.

  Each node in the ltree (struct ltree_node) contains a resizable hash table of
child nodes, as well as the data for its own local rrsets and a flags field for
identifying important properties like zone roots or delegation points.

  The zonefile parser (zscan.rl) constructs the label tree for a zone by making
ltree_add_rec_* calls into the ltree.c code.  After a zonefile has been parsed,
the ltree code does multiple phases of post-processing where it walks the
entire tree, doing many data validation checks and setting up inter-node
references for e.g. CNAMEs and NS->A glue.

  At runtime, the dnspacket.c code searches the ltree database directly via the
global root node, using its own local search function that understands the
ltree structure.

*/

#include "dnswire.h"

#include <gdnsd/compiler.h>
#include "plugins/plugapi.h"
#include <gdnsd/misc.h>

#include <stddef.h>
#include <inttypes.h>
#include <stdbool.h>

// Result type used by search functions in ltree.c and dnspacket.c
enum ltree_dnstatus {
    DNAME_NOAUTH = 0,
    DNAME_AUTH = 1,
    DNAME_DELEG = 2
};

union  ltree_rrset;
struct ltree_rrset_gen;
struct ltree_rrset_raw;
struct ltree_rrset_dynac;

// rrset structs

struct ltree_rrset_gen {
    union ltree_rrset* next;
    uint16_t type;
    uint16_t count; // zero indicates _dynac_t, only valid with DNS_TYPE_{A,AAAA,CNAME}
};

struct ltree_rrset_raw {
    struct ltree_rrset_gen gen;
    unsigned data_len;
    unsigned num_comp_offsets;
    unsigned num_addtl;
    uint8_t* data;
    uint16_t* comp_offsets;
};

struct ltree_rrset_dynac {
    struct ltree_rrset_gen gen;
    unsigned resource;
    uint32_t ttl_min;
    uint32_t ttl_max;
    gdnsd_resolve_cb_t func;
};

// This is never allocated, it's just used
//  for pointer types to cast between generic
//  rrset_t and the specific rrset_t's
union ltree_rrset {
    struct ltree_rrset_gen gen;
    struct ltree_rrset_raw raw;
    struct ltree_rrset_dynac dynac;
};

struct ltree_node;

struct ltree_hslot {
    uintptr_t hash;
    struct ltree_node* node;
};

struct ltree_node {
#if SIZEOF_UINTPTR_T == 8
#  define LTREE_NODE_MAX_SLOTS UINT32_MAX
    uint32_t ccount;
    struct {
        uint32_t zone_cut : 1;
    };
#elif SIZEOF_UINTPTR_T == 4
#  define LTREE_NODE_MAX_SLOTS (UINT32_MAX >> 1U)
    struct {
        uint32_t ccount : 31;
        uint32_t zone_cut : 1;
    };
#endif
    uint8_t* dname;
    struct ltree_hslot* child_table;
    // rrsets is a linked list.  In zone roots, the SOA rrset is always first.
    // In delegation nodes, the NS rrset is always first.
    union ltree_rrset* rrsets;
};

F_NONNULL
void ltree_destroy(struct ltree_node* node);
F_NONNULL
struct ltree_node* ltree_new_zone(const char* zname);
F_NONNULL
bool ltree_merge_zone(struct ltree_node* new_root_tree, struct ltree_node* new_zone);
void* ltree_zones_reloader_thread(void* init_asvoid);
F_WUNUSED F_NONNULL
bool ltree_postproc_zone(struct ltree_node* zroot);

// parameter structures for arguments to ltree_add_rec that otherwise
// have confusingly-long parameter lists
struct lt_soa_args {
    const uint8_t* mname;
    const uint8_t* rname;
    unsigned ttl;
    const unsigned serial;
    const unsigned refresh;
    const unsigned retry;
    const unsigned expire;
    unsigned ncache;
};

struct lt_srv_args {
    const uint8_t* rhs;
    const unsigned ttl;
    const unsigned priority;
    const unsigned weight;
    const unsigned port;
};

struct lt_naptr_args {
    const uint8_t* rhs;
    const unsigned ttl;
    const unsigned order;
    const unsigned pref;
    const unsigned text_len;
    uint8_t* text;
};

// Adding data to the ltree (called from parser)
F_WUNUSED F_NONNULL
bool ltree_add_rec_soa_args(struct ltree_node* zroot, const uint8_t* dname, struct lt_soa_args args);
#define ltree_add_rec_soa(_z,_d,...) ltree_add_rec_soa_args(_z,_d,(struct lt_soa_args){__VA_ARGS__})
F_WUNUSED F_NONNULL
bool ltree_add_rec_a(struct ltree_node* zroot, const uint8_t* dname, uint32_t addr, unsigned ttl);
F_WUNUSED F_NONNULL
bool ltree_add_rec_aaaa(struct ltree_node* zroot, const uint8_t* dname, const uint8_t* addr, unsigned ttl);
F_WUNUSED F_NONNULL
bool ltree_add_rec_dynaddr(struct ltree_node* zroot, const uint8_t* dname, const char* rhs, unsigned ttl_max, unsigned ttl_min);
F_WUNUSED F_NONNULL
bool ltree_add_rec_cname(struct ltree_node* zroot, const uint8_t* dname, const uint8_t* rhs, unsigned ttl);
F_WUNUSED F_NONNULL
bool ltree_add_rec_dync(struct ltree_node* zroot, const uint8_t* dname, const char* rhs, unsigned ttl_max, unsigned ttl_min);
F_WUNUSED F_NONNULL
bool ltree_add_rec_ptr(struct ltree_node* zroot, const uint8_t* dname, const uint8_t* rhs, unsigned ttl);
F_WUNUSED F_NONNULL
bool ltree_add_rec_ns(struct ltree_node* zroot, const uint8_t* dname, const uint8_t* rhs, unsigned ttl);
F_WUNUSED F_NONNULL
bool ltree_add_rec_mx(struct ltree_node* zroot, const uint8_t* dname, const uint8_t* rhs, unsigned ttl, const unsigned pref);
F_WUNUSED F_NONNULL
bool ltree_add_rec_srv_args(struct ltree_node* zroot, const uint8_t* dname, struct lt_srv_args args);
#define ltree_add_rec_srv(_z,_d,...) ltree_add_rec_srv_args(_z,_d,(struct lt_srv_args){__VA_ARGS__})
F_WUNUSED F_NONNULL
bool ltree_add_rec_naptr_args(struct ltree_node* zroot, const uint8_t* dname, struct lt_naptr_args args);
#define ltree_add_rec_naptr(_z,_d,...) ltree_add_rec_naptr_args(_z,_d,(struct lt_naptr_args){__VA_ARGS__})
F_WUNUSED F_NONNULL
bool ltree_add_rec_txt(struct ltree_node* zroot, const uint8_t* dname, const unsigned text_len, uint8_t* text, unsigned ttl);
F_WUNUSED F_NONNULLX(1, 2)
bool ltree_add_rec_rfc3597(struct ltree_node* zroot, const uint8_t* dname, const unsigned rrtype, unsigned ttl, const unsigned rdlen, uint8_t* rd);

// Load zonefiles (called from main, invokes parser)
void ltree_load_zones(void);

// One-shot init at startup, after config load
void ltree_init(void);

// this hash wrapper is for labels encoded as one length-byte followed
//  by N characters.  Thus the label "www" is "\003www" (4 bytes)
F_UNUSED F_PURE F_WUNUSED F_NONNULL F_HOT
static uintptr_t ltree_hash_label(const uint8_t* input)
{
    const size_t len = *input++;
    return gdnsd_shorthash_up(input, len);
}

// count2mask_u32 for a load factor of ~80%, by adding a rounded-down 25% (easy
// 2-bit shift) to the current count before converting it to the next po2 mask
F_CONST F_UNUSED
static uint32_t count2mask_u32_lf80(const uint32_t x)
{
    return count2mask_u32(x + (x >> 2U));
}

// Check whether an uncompressed wire-format name follows all the basic rules
// so that it doesn't trip up functions like those below.  storage bytes is
// whatever info the caller has to ensure we don't run off the end of an
// allocation.  If parsing the name would run past the lesser of storage_bytes
// or DNS's 255 limit, or if any single label is more than 63 bytes long, this
// function will return false.
F_UNUSED F_NONNULL
static bool name_is_valid(const uint8_t* name, unsigned storage_bytes)
{
    if (!storage_bytes)
        return false;
    if (storage_bytes > 255U)
        storage_bytes = 255U;
    unsigned llen;
    while ((llen = *name)) {
        llen++;
        if (llen >= storage_bytes || llen > 64U)
            return false;
        storage_bytes -= llen;
        name += llen;
    }
    return true;
}

// Given a wire-format, uncompressed FQDN "name", construct a tree path from
// it: a label-reversed version which keeps the terminal NUL at the end.
// Example:
// input:    "\1a\2mx\7example\3org\0"
// treepath: "\3org\7example\2mx\1a\0"
// Note this function *requires* that "name" is valid and well-formed, and that
// "treepath" has sufficient storage (255 bytes is enough to cover all cases),
// and that the two arguments' storage do not overlap or alias in any way.
// Retval can be ignored, it's mainly for the next interface below.
F_UNUSED F_NONNULL F_HOT
static const uint8_t* treepath_from_name(uint8_t* restrict treepath, const uint8_t* restrict name)
{
    gdnsd_assert(name_is_valid(name, 255U));

    const uint8_t* labels[127] = { 0 };
    unsigned lidx = 0;
    unsigned llen;
    while ((llen = *name)) {
        gdnsd_assume(llen <= 63U);
        gdnsd_assume(lidx < 127);
        labels[lidx++] = name++;
        name += llen;
    }
    while (lidx--) {
        const unsigned lstore = labels[lidx][0] + 1U;
        memcpy(treepath, labels[lidx], lstore);
        treepath += lstore;
    }
    *treepath = '\0';

    return name;
}

// As above, but does a tiny bit of extra work to return the total storage
// length (which is the same for both arguments, and would be 18 in the example
// above).
F_UNUSED F_NONNULL F_HOT
static unsigned treepath_len_from_name(uint8_t* restrict treepath, const uint8_t* restrict name)
{
    const uint8_t* name_nul = treepath_from_name(treepath, name);
    gdnsd_assume(name_nul >= name);
    gdnsd_assume((unsigned)(name_nul - name) < 255U);
    return (unsigned)(name_nul - name) + 1U;
}

// This just gets the len, without creating a treepath
F_UNUSED F_NONNULL
static unsigned len_from_name(const uint8_t* name)
{
    gdnsd_assert(name_is_valid(name, 255U));
    const uint8_t* orig_name = name;
    unsigned llen;
    while ((llen = *name++))
        name += llen;
    gdnsd_assume(name > orig_name);
    gdnsd_assume((unsigned)(name - orig_name) < 256U);
    return (unsigned)(name - orig_name);
}

// Used within ltree.c in many places, and also from dnspacket while traversing
// the tree for runtime lookups
F_NONNULL F_PURE F_UNUSED F_HOT
static struct ltree_node* ltree_node_find_child(const struct ltree_node* node, const uint8_t* child_label)
{
    if (node->child_table) {
        gdnsd_assume(node->ccount);
        const uint32_t mask = count2mask_u32_lf80(node->ccount);
        const uintptr_t kh = ltree_hash_label(child_label);
        uint32_t probe_dist = 0;
        do {
            const uint32_t slot = ((uint32_t)kh + probe_dist) & mask;
            const struct ltree_hslot* s = &node->child_table[slot];
            if (!s->node || ((slot - s->hash) & mask) < probe_dist)
                break;
            if (s->hash == kh && likely(!label_cmp(&s->node->dname[1], child_label)))
                return s->node;
            probe_dist++;
        } while (1);
    }
    return NULL;
}

// These defines are mainly used in ltree.c, but are also used in comp.c
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

// ltree_root is RCU-managed and accessed by reader threads, defined in ltree.c
GRCU_PUB_DECL(struct ltree_node*, root_tree);

#endif // GDNSD_LTREE_H
