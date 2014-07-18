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

  A whole ltree represents a whole zone as a linked tree of per-label nodes
starting at the root of the zone (the root zone of DNS in the example above).
The actual root node of the tree has no label, as the labels are only useful
in seaching the children of a node.  The root node itself is tracked and
searched through another data structure, the "zones tree" in ztree.h.

  Each node in the ltree (ltree_node_t) contains a resizable hash table of
child nodes, as well as the data for its own local rrsets and a flags field for
identifying important properties like delegation points.

  The zonefile parser (zscan.rl) constructs the label tree by making
ltree_add_rec_* calls into the ltree.c code.  After a zonefile has been
parsed and its raw data added to its ltree, the ltree code does multiple
phases of post-processing where it walks the entire tree, doing many data
validation checks and setting up inter-node references (such as NS->A glue,
MX->A additionals, etc).

  At runtime, the dnspacket.c code searches the ltree database directly, using
its own local search function that understands the ltree structure.

  The child node hash tables within each node are doubled in size every time
the load factor reaches 1.0 (and rehashed all over again into the new table).
Collisions are handled by linked lists of nodes.  The rrsets of a node are
represented by a linked list, and the rdata items within an rrset are
represented as a resizeable array of objects.

  There have been several design iterations, both in checked-in code and
private testing.  Past experiments that failed: A flat hash table of all
domainnames with lots of string-chopping to find the parents of failed lookups
(and some parent/deleg pointers in the nodes).  Various uses of Judy Arrays of
various types at various levels of the structure.  Ditto for crit-bit trees
(using the agl code which came from the djb code).  Ditto for "khash.h" from
AttractiveChaos.  Ditto for many other trie/tree/hash structures, and other
variations on the current setup (open addressing with various jump schemes,
etc).  I'm actually using a clever open-addressing variant over in ltarena.c
for the temporary hashtable that de-duplicates domainname storage within the
ltree, but it doesn't really apply here.

  I really want to find a better, faster, and more space-efficient advanced
data structure to use, but I just haven't found anything that beats the current
"naive (but highly optimized to the problem space) hashing + linked lists"
solution all-around on real-world data.  Recently I dropped a couple of space-
efficiency hacks from the current implementation to gain speed (the space waste
was quite minimal).  One of the biggest space efficiency gains in the current
setup though is the use of the "ltarena" pool allocator, which saves on some
of the wasted alignment of strings, and saves all the pointless resize/free-tracking
that malloc would normally use (all ltarena objects are static and persistent until
daemon exit time).

*/

#ifndef GDNSD_LTREE_H
#define GDNSD_LTREE_H

#include "config.h"
#include "dnswire.h"
#include "ltarena.h"
#include "gdnsd/plugapi.h"

// struct/typedef stuff
struct _ltree_node_struct;
typedef struct _ltree_node_struct ltree_node_t;

// depends on ltree_node_t above
#include "ztree.h"

struct _ltree_rdata_ns_struct;
struct _ltree_rdata_ptr_struct;
struct _ltree_rdata_mx_struct;
struct _ltree_rdata_srv_struct;
struct _ltree_rdata_naptr_struct;
struct _ltree_rdata_rfc3597_struct;

union  _ltree_rrset_union;
struct _ltree_rrset_addr_struct;
struct _ltree_rrset_soa_struct;
struct _ltree_rrset_cname_struct;
struct _ltree_rrset_ns_struct;
struct _ltree_rrset_ptr_struct;
struct _ltree_rrset_mx_struct;
struct _ltree_rrset_srv_struct;
struct _ltree_rrset_naptr_struct;
struct _ltree_rrset_txt_struct;
struct _ltree_rrset_rfc3597_struct;

typedef struct _ltree_rdata_ns_struct ltree_rdata_ns_t;
typedef struct _ltree_rdata_ptr_struct ltree_rdata_ptr_t;
typedef struct _ltree_rdata_mx_struct ltree_rdata_mx_t;
typedef struct _ltree_rdata_srv_struct ltree_rdata_srv_t;
typedef struct _ltree_rdata_naptr_struct ltree_rdata_naptr_t;
typedef uint8_t* * ltree_rdata_txt_t;
typedef struct _ltree_rdata_rfc3597_struct ltree_rdata_rfc3597_t;

typedef union  _ltree_rrset_union ltree_rrset_t;
typedef struct _ltree_rrset_gen_struct ltree_rrset_gen_t;
typedef struct _ltree_rrset_addr_struct ltree_rrset_addr_t;
typedef struct _ltree_rrset_soa_struct ltree_rrset_soa_t;
typedef struct _ltree_rrset_cname_struct ltree_rrset_cname_t;
typedef struct _ltree_rrset_ns_struct ltree_rrset_ns_t;
typedef struct _ltree_rrset_ptr_struct ltree_rrset_ptr_t;
typedef struct _ltree_rrset_mx_struct ltree_rrset_mx_t;
typedef struct _ltree_rrset_srv_struct ltree_rrset_srv_t;
typedef struct _ltree_rrset_naptr_struct ltree_rrset_naptr_t;
typedef struct _ltree_rrset_txt_struct ltree_rrset_txt_t;
typedef struct _ltree_rrset_rfc3597_struct ltree_rrset_rfc3597_t;

// Used to set/get the "glue" status of the "ad" pointer
//  in ltree_rdata_ns_t, which is stored in the LSB.
#define AD_IS_GLUE(x) (!!(((uintptr_t)(x)) & 1UL))
#define AD_SET_GLUE(x) ((x) = (void*)(((uintptr_t)(x)) | 1UL))
#define AD_GET_PTR(x) ((const ltree_rrset_addr_t*)((uintptr_t)(x) & (~1UL)))

struct _ltree_rdata_ns_struct {
    const uint8_t* dname;
    ltree_rrset_addr_t* ad;
};

struct _ltree_rdata_ptr_struct {
    const uint8_t* dname;
};

struct _ltree_rdata_mx_struct {
    const uint8_t* dname;
    ltree_rrset_addr_t* ad;
    uint16_t pref;
};

struct _ltree_rdata_srv_struct {
    const uint8_t* dname;
    ltree_rrset_addr_t* ad;
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
};

#define NAPTR_TEXTS_FLAGS 0
#define NAPTR_TEXTS_SERVICES 1
#define NAPTR_TEXTS_REGEXP 2
struct _ltree_rdata_naptr_struct {
    const uint8_t* dname;
    ltree_rrset_addr_t* ad;
    uint8_t* texts[3]; // flags, services, regexp
    uint16_t order;
    uint16_t pref;
};

struct _ltree_rdata_rfc3597_struct {
    uint8_t* rd;
    uint16_t rdlen;
};

// rrset structs

struct _ltree_rrset_gen_struct {
    ltree_rrset_t* next;
    uint32_t ttl;
    uint16_t type;
    // Most rr-types only use "count" below.  For rr-types which
    //  can resolve via dynamic plugin (addr, cname), a count of
    //  zero implies dynamic resolution (hence "is_static" for semantic
    //  clarity).  count_v4/count_v6 is a split count used by addr.
    union {
        uint16_t count;
        uint16_t is_static;
        struct {
            uint8_t count_v4;
            uint8_t count_v6;
        };
    };
};

struct _ltree_rrset_addr_struct {
    ltree_rrset_gen_t gen;
    union {
        struct {
            uint32_t* v4;
            uint8_t* v6;
        } addrs;
        struct {
            gdnsd_resolve_dynaddr_cb_t func;
            unsigned resource;
        } dyn;
    };
    uint16_t limit_v4;
    uint16_t limit_v6;
};

struct _ltree_rrset_soa_struct {
    ltree_rrset_gen_t gen;
    const uint8_t* email;
    const uint8_t* master;
    uint32_t times[5];
    uint32_t neg_ttl; // cache of htons(min(ntohs(gen.ttl), ntohs(times[4])))
};

struct _ltree_rrset_cname_struct {
    ltree_rrset_gen_t gen;
    union {
        const uint8_t* dname;
        struct {
            const uint8_t* origin;
            gdnsd_resolve_dyncname_cb_t func;
            unsigned resource;
        } dyn;
    };
};

struct _ltree_rrset_ns_struct {
    ltree_rrset_gen_t gen;
    ltree_rdata_ns_t* rdata;
};

struct _ltree_rrset_ptr_struct {
    ltree_rrset_gen_t gen;
    ltree_rdata_ptr_t* rdata;
};

struct _ltree_rrset_mx_struct {
    ltree_rrset_gen_t gen;
    ltree_rdata_mx_t* rdata;
};

struct _ltree_rrset_srv_struct {
    ltree_rrset_gen_t gen;
    ltree_rdata_srv_t* rdata;
};

struct _ltree_rrset_naptr_struct {
    ltree_rrset_gen_t gen;
    ltree_rdata_naptr_t* rdata;
};

struct _ltree_rrset_txt_struct {
    ltree_rrset_gen_t gen;
    ltree_rdata_txt_t* rdata;
};

struct _ltree_rrset_rfc3597_struct {
    ltree_rrset_gen_t gen;
    ltree_rdata_rfc3597_t* rdata;
};

// This is never allocated, it's just used
//  for pointer types to cast between generic
//  rrset_t and the specific rrset_t's
union _ltree_rrset_union {
    ltree_rrset_gen_t gen;
    ltree_rrset_addr_t addr;
    ltree_rrset_soa_t soa;
    ltree_rrset_cname_t cname;
    ltree_rrset_ns_t ns;
    ltree_rrset_ptr_t ptr;
    ltree_rrset_mx_t mx;
    ltree_rrset_srv_t srv;
    ltree_rrset_naptr_t naptr;
    ltree_rrset_txt_t txt;
    ltree_rrset_rfc3597_t rfc3597;
};

// For ltree_node_t.flags
#define LTNFLAG_DELEG 0x1 // This is the exact start of a delegated zone.
                          // These nodes *must* have an NS rrset (that's how they're
                          //  detected in the first place), and otherwise can only have
                          //  addr rrsets, and child nodes which contain only addr rrsets
                          //  (for NS glue)
#define LTNFLAG_GUSED 0x2 // For nodes at or below DELEG points which contain addresses, this
                          //  is set when the glue is used, and later checked for "glue unused"
                          //  warnings.  Also re-used in the same manner for out-of-zone glue,
                          //  which is stored under a special child node of the zone root.

struct _ltree_node_struct {
    uint32_t flags;
    // During the ltree_add_rec_* (parsing) phase of ltree.c, an accurate count
    //  is maintained in child_hash_mask, and the effective mask is computed from
    //  the count (next power of 2, -1).  After all records are added the raw count
    //  becomes useless, and this value is converted to a directly stored mask for
    //  use during post-processing and by the runtime code in dnspacket.c
    uint32_t child_hash_mask;
    const uint8_t* label;
    ltree_node_t* next;         // next node in this child_table hash slot
    ltree_node_t* * child_table; // The table of children.
    ltree_rrset_t* rrsets;     // The list of rrsets
};

// ztree/zone code uses these to create and destroy per-zone ltrees:
F_NONNULL
void ltree_init_zone(zone_t* zone);
F_WUNUSED F_NONNULL
bool ltree_postproc_zone(zone_t* zone);
F_NONNULL
void ltree_destroy(ltree_node_t* node);

// Adding data to the ltree (called from parser)
F_WUNUSED F_NONNULL
bool ltree_add_rec_soa(const zone_t* zone, const uint8_t* dname, const uint8_t* master, const uint8_t* email, unsigned ttl, unsigned serial, unsigned refresh, unsigned retry, unsigned expire, unsigned ncache);
F_WUNUSED F_NONNULL
bool ltree_add_rec_a(const zone_t* zone, const uint8_t* dname, uint32_t addr, unsigned ttl, unsigned limit_v4, const bool ooz);
F_WUNUSED F_NONNULL
bool ltree_add_rec_aaaa(const zone_t* zone, const uint8_t* dname, const uint8_t* addr, unsigned ttl, unsigned limit_v6, const bool ooz);
F_WUNUSED F_NONNULL
bool ltree_add_rec_dynaddr(const zone_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl, unsigned limit_v4, unsigned limit_v6, const bool ooz);
F_WUNUSED F_NONNULL
bool ltree_add_rec_cname(const zone_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl);
F_WUNUSED F_NONNULL
bool ltree_add_rec_dyncname(const zone_t* zone, const uint8_t* dname, const uint8_t* rhs, const uint8_t* origin, unsigned ttl);
F_WUNUSED F_NONNULL
bool ltree_add_rec_ptr(const zone_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl);
F_WUNUSED F_NONNULL
bool ltree_add_rec_ns(const zone_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl);
F_WUNUSED F_NONNULL
bool ltree_add_rec_mx(const zone_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl, unsigned pref);
F_WUNUSED F_NONNULL
bool ltree_add_rec_srv(const zone_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl, unsigned priority, unsigned weight, unsigned port);
F_WUNUSED F_NONNULL
bool ltree_add_rec_naptr(const zone_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl, unsigned order, unsigned pref, unsigned num_texts, uint8_t** texts);
F_WUNUSED F_NONNULL
bool ltree_add_rec_txt(const zone_t* zone, const uint8_t* dname, unsigned num_texts, uint8_t** texts, unsigned ttl);
F_WUNUSED F_NONNULL
bool ltree_add_rec_spf(const zone_t* zone, const uint8_t* dname, unsigned num_texts, uint8_t** texts, unsigned ttl);
F_WUNUSED F_NONNULL
bool ltree_add_rec_spftxt(const zone_t* zone, const uint8_t* dname, unsigned num_texts, uint8_t** texts, unsigned ttl);
F_WUNUSED F_NONNULLX(1)
bool ltree_add_rec_rfc3597(const zone_t* zone, const uint8_t* dname, unsigned rrtype, unsigned ttl, unsigned rdlen, uint8_t* rd);

// Load zonefiles (called from main, invokes parser)
void ltree_load_zones(void);

typedef enum {
    DNAME_NOAUTH = 0,
    DNAME_AUTH = 1,
    DNAME_DELEG = 2
} ltree_dname_status_t;

// This is the global singleton ltree_root
extern ltree_node_t* ltree_root;

/********************************************************************
 * This is the excellent fast string hash algorithm DJB came up
 * with.  He uses it in his cdb database.  http://cr.yp.to
 ********************************************************************/

// this variant is for labels encoded as one length-byte followed
//  by N characters.  Thus the label "www" becomes "\003www" (4 bytes)
F_UNUSED F_PURE F_WUNUSED F_NONNULL F_UNUSED
static uint32_t label_djb_hash(const uint8_t* input, const uint32_t hash_mask) {
   dmn_assert(input);

   uint32_t hash = 5381;
   uint32_t len = *input++;
   while(len--)
       hash = (hash * 33) ^ *input++;

   return hash & hash_mask;
}

// "lstack" must be allocated to 127 pointers
// "dname" must be valid
// retval is label count (not including zero-width root label)
F_UNUSED F_WUNUSED F_NONNULL
static unsigned dname_to_lstack(const uint8_t* dname, const uint8_t** lstack) {
    dmn_assert(dname); dmn_assert(dname_status(dname) == DNAME_VALID);
    dmn_assert(lstack);

    dname++; // skip overall len byte
    unsigned lcount = 0;
    unsigned llen; // current label len
    while((llen = *dname)) {
        dmn_assert(lcount < 127);
        lstack[lcount++] = dname++;
        dname += llen;
    }

    return lcount;
}

#endif // GDNSD_LTREE_H
