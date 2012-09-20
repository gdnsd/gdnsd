/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
 *
 * This file is part of gdnsd-plugin-geoip.
 *
 * gdnsd-plugin-geoip is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * gdnsd-plugin-geoip is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gdnsd.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// gdmaps = GeoIP -> Datacenter Mapping library code

#include "config.h"
#include "gdmaps.h"
#include "fips104.h"
#include "dcinfo.h"
#include "dclists.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pthread.h>

#include <gdnsd-dmn.h>
#include <gdnsd-log.h>
#include <gdnsd-vscf.h>
#include <gdnsd-ev.h>
#include <gdnsd-misc.h>

// When a GeoIP database file change is detected, we wait this long
//  for a followup change notification.  Every time we get another notification
//  within the window, we restart the timer again.  Once it has settled for
//  this long, we re-parse the db.  This ensures we're not fooled by bad software
//  re-writing the file in-place (instead of rename()ing into place like they should).
#define GEOIP_RELOAD_WAIT 30.0

// IP address macros...
#define CHKBIT_v6A(s6a,bit)          (s6a[((127UL - bit) >> 3)]  & (1UL << (~(127 - bit) & 7)))
#define SETBIT_v6(ipv6,bit) (ipv6.s6_addr[((127UL - bit) >> 3)] |= (1UL << (~(127 - bit) & 7)))
#define CHKBIT_v4A(ipv4,bit) (ipv4  & (1UL << bit))
#define CHKBIT_v4(ipv4,bit)  (ipv4  & (1UL << bit))
#define SETBIT_v4(ipv4,bit)  (ipv4 |= (1UL << bit))

// Some constant IPv6 address fragments...

static const uint8_t start_v4mapped[16] =
    { 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0xFF, 0xFF,
      0x00, 0x00, 0x00, 0x00 };

static const uint8_t start_v4compat[16] =
    { 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00 };

static const uint8_t start_siit[16] =
    { 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0xFF, 0xFF, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00 };

static const uint8_t start_6to4[16] =
    { 0x20, 0x02, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00 };

static const uint8_t start_teredo[16] =
    { 0x20, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00 };

// ::FFFE is the binary tree node that
//   the v4mapped space ::FFFF is the 1-direction
//   child of...
static const uint8_t parent_v4mapped[12] =
    { 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0xFF, 0xFE };

// zero-initializer for IPv6
static const struct in6_addr ip6_zero = { .s6_addr = { 0 } };

/***************************************
 * nets_t and related methods
 **************************************/

typedef struct {
    union {
        uint8_t ipv6[16]; // net-order
        uint32_t ipv4;    // host-order
    };
    unsigned mask;
    unsigned dclist;
    bool isv6;
} net_t;

typedef struct {
    net_t* nets;
    unsigned count;
} nets_t;

// Check whether the passed network is
//  a supernet or subnet of the special v4-like
//  address spaces, which is illegal for 'nets'
//  because supernets would cause inconsistent
//  lookup results and subnets would be ineffective
//  due to lookup-time conversions.

F_NONNULL F_PURE
static bool _v6_is_related(const uint8_t* check, const unsigned check_mask, const uint8_t* v4, const unsigned v4_mask) {
    dmn_assert(check); dmn_assert(v4);

    const unsigned mask = check_mask < v4_mask ? check_mask : v4_mask;
    if(!mask)
       return true;

    const unsigned byte = (mask >> 3); // compared whole bytes indexes < byte
    for(unsigned i = 0; i < byte; i++) {
       if(check[i] != v4[i])
           return false;
    }

    const unsigned byte_mask = ~((1U << (8 - (mask & 7))) - 1) & 0xFF;
    const unsigned check_final = check[byte] & byte_mask;
    const unsigned v4_final = v4[byte] & byte_mask;
    if(check_final != v4_final)
        return false;

    return true;
}

F_NONNULL
static void _check_v4_issues(const uint8_t* ipv6, const unsigned mask, const char* map_name, const char* net_str) {
    dmn_assert(ipv6); dmn_assert(map_name); dmn_assert(net_str);

    if(
          _v6_is_related(ipv6, mask, start_v4mapped, 96)
       || _v6_is_related(ipv6, mask, start_v4compat, 96)
       || _v6_is_related(ipv6, mask, start_siit, 96)
       || _v6_is_related(ipv6, mask, start_teredo, 32)
       || _v6_is_related(ipv6, mask, start_6to4, 16)
    )
        log_fatal("plugin_geoip: map '%s': 'nets' entry '%s/%u' covers illegal IPv4-like space, see the documentation for more info", map_name, net_str, mask);
}

// Sort 'nets' stanza.  Sort order is lowest
//   network-number first, and all ipv6 before
//   any ipv4.
// It is interesting to note that (a) we've told
//   people not to use v4-like v6 addresses, and (b)
//   because ipv4_root has already been set appropriately
//   and 'nets' application doesn't destroy pruned areas,
//   if someone were to 'nets' an IPv6 network which was
//   a supernet of all IPv4 space that's stored at the
//   v4-mapped area, v4 lookups would still go to the
//   right place within the orphaned sub-tree.
F_NONNULL F_PURE
static int _net_sorter(const void* a_void, const void* b_void) {
    const net_t* a = (const net_t*)a_void;
    const net_t* b = (const net_t*)b_void;

    int rv = 0;

    if(a->isv6) {
        if(b->isv6) {
            for(unsigned i = 0; i < 16; i++) {
                if(a->ipv6[i] < b->ipv6[i]) { rv = -1; break; }
                else if(a->ipv6[i] > b->ipv6[i]) { rv = 1; break; }
            }
        }
        else { rv = -1; }
    }
    else { // !a->isv6
        if(!b->isv6) {
            if(a->ipv4 < b->ipv4) { rv = -1; }
            else if(a->ipv4 > b->ipv4) { rv = 1; }
        }
        else { rv = 1; }
    }

    return rv;
}

F_NONNULL
static nets_t* nets_new(const vscf_data_t* nets_cfg, dclists_t* dclists, const char* map_name) {
    dmn_assert(nets_cfg); dmn_assert(dclists); dmn_assert(map_name);
    dmn_assert(vscf_is_hash(nets_cfg));

    nets_t* nets = calloc(1, sizeof(nets_t));
    unsigned nnets = vscf_hash_get_len(nets_cfg);
    nets->count = nnets;
    nets->nets = calloc(nnets, sizeof(net_t));
    for(unsigned i = 0; i < nnets; i++) {
        // convert 192.0.2.0/24 -> anysin_t w/ mask in port field
        char* net_str = strdup(vscf_hash_get_key_byindex(nets_cfg, i, NULL));
        char* mask = strchr(net_str, '/');
        if(!mask)
            log_fatal("plugin_geoip: map '%s': nets entry '%s' does not parse as addr/mask", map_name, net_str);
        *mask++ = '\0';
        anysin_t tempsin;
        int addr_err = gdnsd_anysin_getaddrinfo(net_str, mask, &tempsin);
        if(addr_err) // this errmsg could be a little confusing if it references the "port"...
            log_fatal("plugin_geoip: map '%s': nets entry '%s/%s' does not parse as addr/mask: %s", map_name, net_str, mask, gai_strerror(addr_err));

        // now store the anysin data into net_t
        if(tempsin.sa.sa_family == AF_INET6) {
            nets->nets[i].isv6 = true;
            nets->nets[i].mask = ntohs(tempsin.sin6.sin6_port);
            if(nets->nets[i].mask > 128)
                log_fatal("plugin_geoip: map '%s': nets entry '%s/%s': illegal mask (>128)", map_name, net_str, mask);
            memcpy(nets->nets[i].ipv6, tempsin.sin6.sin6_addr.s6_addr, 16);
            _check_v4_issues(nets->nets[i].ipv6, nets->nets[i].mask, map_name, net_str);
        }
        else {
            dmn_assert(tempsin.sa.sa_family == AF_INET);
            nets->nets[i].isv6 = false;
            nets->nets[i].mask = ntohs(tempsin.sin.sin_port);
            if(nets->nets[i].mask > 32)
                log_fatal("plugin_geoip: map '%s': nets entry '%s/%s': illegal mask (>128)", map_name, net_str, mask);
            nets->nets[i].ipv4 = ntohl(tempsin.sin.sin_addr.s_addr);
        }

        free(net_str);

        // get dclist integer from rhs
        const vscf_data_t* dc_cfg = vscf_hash_get_data_byindex(nets_cfg, i);
        nets->nets[i].dclist = dclists_find_or_add_vscf(dclists, dc_cfg, map_name, false);
    }

    qsort(nets->nets, nets->count, sizeof(net_t), _net_sorter);

    return nets;
}

F_NONNULL
static void nets_destroy(nets_t* nets) {
    dmn_assert(nets);
    free(nets->nets);
    free(nets);
}

/***************************************
 * dcmap_t and related methods
 **************************************/

typedef struct _dcmap_t dcmap_t;

struct _dcmap_t {
    // All 3 below are allocated to num_children entries.
    // For each index, exactly one of the following must be true:
    //  child_dclist[i] is non-zero, indicating a direct dclist
    //  child_dcmap[i] is non-null, indicating another level of depth
    char** child_names;
    int* child_dclists;
    dcmap_t** child_dcmaps;
    unsigned def_dclist; // copied from parent if not specced in cfg, required at root
    unsigned num_children;
    bool skip_level; // at this level of dcmap, skip ahead one chunk of locstr...
};

typedef struct {
    dcmap_t* dcmap;
    dclists_t* dclists;
    const char* map_name;
    unsigned child_num;
    unsigned true_depth;
    bool allow_auto;
} dcmap_iter_data;

F_NONNULL
static dcmap_t* dcmap_new(const vscf_data_t* map_cfg, dclists_t* dclists, const unsigned parent_def, const unsigned true_depth, const char* map_name, const bool allow_auto);

F_NONNULL static void validate_country_code(const char* cc, const char* map_name);
F_NONNULL static void validate_continent_code(const char* cc, const char* map_name);

F_NONNULL
static bool _dcmap_new_iter(const char* key, unsigned klen V_UNUSED, const vscf_data_t* val, void* data) {
    dmn_assert(key); dmn_assert(val); dmn_assert(data);

    dcmap_iter_data* did = data;

    unsigned true_depth = did->true_depth + (did->dcmap->skip_level ? 1 : 0);
    if(true_depth == 0)
        validate_continent_code(key, did->map_name);
    else if(true_depth == 1)
        validate_country_code(key, did->map_name);

    did->dcmap->child_names[did->child_num] = strdup(key);
    if(vscf_is_hash(val))
        did->dcmap->child_dcmaps[did->child_num] = dcmap_new(val, did->dclists, did->dcmap->def_dclist, true_depth + 1, did->map_name, did->allow_auto);
    else
        did->dcmap->child_dclists[did->child_num] = dclists_find_or_add_vscf(did->dclists, val, did->map_name, did->allow_auto);

    did->child_num++;

    return true;
}

F_NONNULL
static dcmap_t* dcmap_new(const vscf_data_t* map_cfg, dclists_t* dclists, const unsigned parent_def, const unsigned true_depth, const char* map_name, const bool allow_auto) {
    dmn_assert(map_cfg); dmn_assert(dclists); dmn_assert(map_name);
    dmn_assert(vscf_is_hash(map_cfg));

    dcmap_t* dcmap = calloc(1, sizeof(dcmap_t));
    unsigned nchild = vscf_hash_get_len(map_cfg);

    const vscf_data_t* def_cfg = vscf_hash_get_data_byconstkey(map_cfg, "default", true);
    if(def_cfg) {
        if(!true_depth) {
            uint8_t newlist[256];
            int status = dclists_xlate_vscf(dclists, def_cfg, map_name, newlist, allow_auto);
            if(status) {
                dmn_assert(status == -1 && allow_auto);
                dcmap->def_dclist = -1;
            }
            else {
                dcmap->def_dclist = 0;
                dclists_replace_list0(dclists, (uint8_t*)strdup((char*)newlist));
            }
        }
        else {
            dcmap->def_dclist = dclists_find_or_add_vscf(dclists, def_cfg, map_name, allow_auto);
        }
        nchild--; // don't iterate "default" later
    }
    else {
        if(!true_depth) {
            dcmap->def_dclist = allow_auto ? -1 : 0;
        }
        else {
            dcmap->def_dclist = parent_def;
        }
    }

    const vscf_data_t* skip_cfg = vscf_hash_get_data_byconstkey(map_cfg, "skip_level", true);
    if(skip_cfg) {
        if(!vscf_is_simple(skip_cfg) || !vscf_simple_get_as_bool(skip_cfg, &dcmap->skip_level))
            log_fatal("plugin_geoip: map '%s': 'skip_level' must be a boolean value ('true' or 'false')", map_name);
        nchild--; // don't iterate "skip_level" later
    }

    if(nchild) {
        dcmap->num_children = nchild;
        dcmap->child_names = calloc(nchild, sizeof(char*));
        dcmap->child_dclists = calloc(nchild, sizeof(unsigned));
        dcmap->child_dcmaps = calloc(nchild, sizeof(dcmap_t*));
        dcmap_iter_data did = {
            .child_num = 0,
            .dcmap = dcmap,
            .dclists = dclists,
            .map_name = map_name,
            .true_depth = true_depth,
            .allow_auto = allow_auto
        };
        vscf_hash_iterate(map_cfg, true, _dcmap_new_iter, &did);
    }

    return dcmap;
}

F_NONNULL
static int dcmap_lookup_loc(const dcmap_t* dcmap, const char* locstr) {
    dmn_assert(dcmap); dmn_assert(locstr);

    if(*locstr && dcmap->skip_level)
        locstr += strlen(locstr) + 1;

    if(*locstr) {
        for(unsigned i = 0; i < dcmap->num_children; i++) {
            if(!strcasecmp(locstr, dcmap->child_names[i])) {
                if(dcmap->child_dcmaps[i])
                    return dcmap_lookup_loc(dcmap->child_dcmaps[i], locstr + strlen(locstr) + 1);
                return dcmap->child_dclists[i];
            }
        }
    }

    return dcmap->def_dclist;
}

F_NONNULL
static void dcmap_destroy(dcmap_t* dcmap) {
    dmn_assert(dcmap);

    if(dcmap->child_names) {
        for(unsigned i = 0; i < dcmap->num_children; i++) {
            if(dcmap->child_names[i])
                free(dcmap->child_names[i]);
        }
        free(dcmap->child_names);
    }
    if(dcmap->child_dcmaps) {
        for(unsigned i = 0; i < dcmap->num_children; i++) {
            if(dcmap->child_dcmaps[i])
                dcmap_destroy(dcmap->child_dcmaps[i]);
        }
        free(dcmap->child_dcmaps);
    }
    if(dcmap->child_dclists)
        free(dcmap->child_dclists);
    free(dcmap);
}

/***************************************
 * ntree_t and related methods
 **************************************/

/*
 * This is our network/mask database.  It becomes fully populated, in that
 * a lookup of any address *will* find a node.  This is because the original
 * GeoIP database is also fully populated.  It maps network/mask -> dclist,
 * and is constructed by walking the entire input GeoIP database and remapping
 * it against this maps's vscf config.
 */

// Initial node allocation count, must be power of two due to alloc code below
static const unsigned NT_SIZE_INIT = 64;

typedef struct {
    // if terminal bit is set, only "dclist" matters,
    // if terminal bit is not set, only "zero" and "one" matter
    union {
        uint32_t zero;
        uint32_t dclist;
    };
    uint32_t one : 31;
    uint32_t terminal : 1;
} nnode_t;

typedef struct {
    nnode_t* store;
    dclists_t* dclists;
    unsigned count; // raw nodes, including interior ones
    unsigned alloc;
    unsigned ipv4_root;
    unsigned raw_count; // GeoIP nets
    unsigned terminals; // terminal, optimized nodes
    bool ipv6;
} ntree_t;

static ntree_t* ntree_new(const bool ipv6, const dclists_t* old_dclists) {
    ntree_t* newtree = malloc(sizeof(ntree_t));
    newtree->store = calloc(NT_SIZE_INIT, sizeof(nnode_t));
    newtree->dclists = dclists_clone(old_dclists);
    newtree->count = 1;
    newtree->alloc = NT_SIZE_INIT;
    newtree->ipv4_root = 0;
    newtree->raw_count = 0;
    newtree->terminals = 0;
    newtree->ipv6 = ipv6;
    return newtree;
}

F_NONNULL
static void ntree_destroy(ntree_t* tree, dclists_destroy_depth_t depth) {
    dmn_assert(tree);
    dclists_destroy(tree->dclists, depth);
    free(tree->store);
    free(tree);
}

F_NONNULL
static unsigned ntree_add_node(ntree_t* tree) {
    dmn_assert(tree);
    if(tree->count == tree->alloc) {
        tree->alloc <<= 1;
        tree->store = realloc(tree->store, tree->alloc * sizeof(nnode_t));
        memset(&tree->store[tree->count], 0, tree->count * sizeof(nnode_t));
    }
    const unsigned rv = tree->count;
    dmn_assert(rv < (1U << 24));
    tree->count++;
    return rv;
}

/* some debugging code saved for future dev use ...
F_NONNULL F_UNUSED
static void ntree_dump_v6(ntree_t* tree, unsigned bitdepth, unsigned offset, struct in6_addr ipv6) {
    dmn_assert(tree); dmn_assert(tree->ipv6);

    anysin_t tempsin;
    memset(&tempsin, 0, sizeof(tempsin));
    tempsin.len = sizeof(struct sockaddr_in6);
    tempsin.sa.sa_family = AF_INET6;
    memcpy(&tempsin.sin6.sin6_addr, &ipv6, sizeof(struct in6_addr));

    nnode_t* this_node = &tree->store[offset];
    if(this_node->terminal) {
        log_debug("Terminal net: %s/%u -> %u", logf_anysin_noport(&tempsin), 127U - bitdepth, this_node->dclist);
    }
    else {
        if(this_node->zero)
            ntree_dump_v6(tree, bitdepth - 1, this_node->zero, ipv6);
        else
            log_debug("Dangling zero-child beneath net: %s/%u", logf_anysin_noport(&tempsin), 127U - bitdepth);

        SETBIT_v6(ipv6, bitdepth);
        if(this_node->one)
            ntree_dump_v6(tree, bitdepth - 1, this_node->one, ipv6);
        else
            log_debug("Dangling one-child beneath net: %s/%u", logf_anysin_noport(&tempsin), 127U - bitdepth);
    }
}
*/

// Trim storage down to final static size
F_NONNULL
static void ntree_finalize(ntree_t* tree) {
    dmn_assert(tree);
    tree->alloc = tree->count;
    tree->store = realloc(tree->store, tree->alloc * sizeof(nnode_t));
}

#define DEFUN_NTAPPEND(ISV6, IPVN, IPTYPE, ONE_ADDED_CODE) \
F_NONNULL \
static void ntree_append_net_ ## IPVN(ntree_t* tree, const IPTYPE ip, const unsigned mask, const unsigned dclist) { \
    dmn_assert(tree);                               \
    const unsigned BITDEPTH = ISV6 ? 128 : 32;      \
    if(ISV6) {                                      \
        dmn_assert(ip);                             \
        dmn_assert(tree->ipv6);                     \
    }                                               \
    else {                                          \
        dmn_assert(tree->ipv4_root || !tree->ipv6); \
    }                                               \
    dmn_assert(mask <= BITDEPTH);                   \
    unsigned current_off = ISV6 ? 0 : tree->ipv4_root; \
    int depth = BITDEPTH - 1;                       \
    unsigned saved_dclist = 0;                      \
    bool under_old_terminal = false;                \
    while(mask != ((BITDEPTH - 1) - depth)) {       \
        if(tree->store[current_off].terminal) {     \
            dmn_assert(!under_old_terminal);        \
            under_old_terminal = true;              \
            saved_dclist = tree->store[current_off].dclist;        \
            memset(&tree->store[current_off], 0, sizeof(nnode_t)); \
            tree->terminals--;                      \
        }                                           \
        unsigned next_off = 0;                      \
        const bool our_direction = CHKBIT_ ## IPVN ## A(ip, depth);  \
        if(!our_direction || under_old_terminal) {                   \
            if(!tree->store[current_off].zero) {                     \
                unsigned temp_off = ntree_add_node(tree);            \
                tree->store[current_off].zero = temp_off;            \
            }                                                        \
            else { dmn_assert(!our_direction); }                     \
            if(!our_direction) { next_off = tree->store[current_off].zero; } \
            else {                                                           \
                nnode_t* zero = &tree->store[tree->store[current_off].zero]; \
                zero->terminal = 1;                       \
                zero->dclist = saved_dclist;              \
                tree->terminals++;                        \
            }                                             \
        }                                                 \
        if(our_direction || under_old_terminal) {         \
            if(!tree->store[current_off].one) {           \
                unsigned temp_off = ntree_add_node(tree); \
                tree->store[current_off].one = temp_off;  \
                ONE_ADDED_CODE                            \
            }                                             \
            else { dmn_assert(our_direction); }           \
            if(our_direction) { next_off = tree->store[current_off].one; } \
            else {                                                         \
                nnode_t* one = &tree->store[tree->store[current_off].one]; \
                one->terminal = 1;            \
                one->dclist = saved_dclist;   \
                tree->terminals++;            \
            }                                 \
        }                                     \
        dmn_assert(next_off < tree->count);   \
        depth--;                              \
        current_off = next_off;               \
    }                                         \
    tree->store[current_off].zero = 0;        \
    tree->store[current_off].one = 0;         \
    tree->store[current_off].terminal = 1U;   \
    tree->store[current_off].dclist = dclist; \
    tree->terminals++;                        \
}

#define IPV6_ONE_ADDED_CODE \
    if(depth == 32 && !memcmp(ip, start_v4mapped, 12)) \
        tree->ipv4_root = temp_off;

DEFUN_NTAPPEND(0, v4, uint32_t, ;)

DEFUN_NTAPPEND(1, v6, uint8_t*, IPV6_ONE_ADDED_CODE)

// If the v6 database didn't even contain the v4mapped root
//  node for us to have set tree->ipv4_root, we need to fix
//  that situation so that tree->ipv4_root is valid in some sense.
F_NONNULL
static void ntree_fixup_v4root(ntree_t* tree, const bool v4o) {
    dmn_assert(tree);
    dmn_assert(tree->ipv6);

    if(!tree->ipv4_root) {
        log_debug("plugin_geoip: doing ipv4_root fixup (v4_overlay or no v4mapped data)");

        // this makes sure ipv4_root exists, and creates it as
        //  a terminal node to the default dclist (0)
        ntree_append_net_v6(tree, start_v4mapped, 96U, 0);
        dmn_assert(tree->ipv4_root);

        // if we're doing v4_overlay, we need to reset the ipv4_root node
        //   so that that the v4 xlate code doesn't barf trying to add branches here...
        if(v4o) {
            memset(&tree->store[tree->ipv4_root], 0, sizeof(nnode_t));
            tree->terminals--; // keep terminals count correct..
        }
    }
}

static int ntree_apply_nets(ntree_t* tree, const nets_t* nets, const char* map_name) {
    dmn_assert(tree); dmn_assert(nets);

    int rv = 0;

    const unsigned nnets = nets->count;
    for(unsigned i = 0; !rv && i < nnets; i++) {
        const net_t* anet = &nets->nets[i];
        if(anet->isv6) {
            if(!tree->ipv6) {
                log_err("plugin_geoip: map '%s': IPv6 nets illegal: database is IPv4-based", map_name);
                rv = -1;
                break;
            }
            ntree_append_net_v6(tree, anet->ipv6, anet->mask, anet->dclist);
        }
        else {
            ntree_append_net_v4(tree, anet->ipv4, anet->mask, anet->dclist);
        }
    }

    return rv;
}

F_NONNULL
static unsigned ntree_lookup_v4(const ntree_t* tree, const uint32_t ip, unsigned* mask_out) {
    dmn_assert(tree); dmn_assert(mask_out);
    dmn_assert(tree->ipv4_root || !tree->ipv6);

    int depth = 31;
    unsigned current_off = tree->ipv4_root;

    nnode_t* current = &tree->store[current_off];
    while(!current->terminal) {
        dmn_assert(current->one && current->zero);
        current_off = (ip & (1 << depth)) ? current->one : current->zero;
        dmn_assert(current_off < tree->count);
        depth--;
        current = &tree->store[current_off];
    }

    // terminal node
    *mask_out = 31 - depth;
    return current->dclist;
}

F_NONNULL
static unsigned ntree_lookup_v6(const ntree_t* tree, const uint8_t* ip, unsigned* mask_out) {
    dmn_assert(tree); dmn_assert(ip); dmn_assert(mask_out);
    dmn_assert(tree->ipv6);

    int depth = 127;
    unsigned current_off = 0;

    nnode_t* current = &tree->store[current_off];
    while(!current->terminal) {
        dmn_assert(current->one && current->zero);
        current_off = CHKBIT_v6A(ip, depth) ? current->one : current->zero;
        dmn_assert(current_off < tree->count);
        depth--;
        current = &tree->store[current_off];
    }

    // terminal node
    *mask_out = 127 - depth;
    return current->dclist;
}

// if v6 addr is any of several v4-compatible forms, convert to
//   a uint32_t ipv4 address and return a mask adjustment value
// if no conversion is possible, returns a zero mask adjustment
F_NONNULL F_PURE
static int v6_v4compat(const uint8_t* restrict in, uint32_t* restrict ipv4) {
    dmn_assert(in); dmn_assert(ipv4);

    // easier access to various bits of the ipv6 space
    const uint16_t* in_16 = (const uint16_t*)in;
    const uint32_t* in_32 = (const uint32_t*)in;
    const uint64_t* in_64 = (const uint64_t*)in;

    int mask_adj = 0;

    if(!in_64[0] && (
        !in_32[2] // v4compat
        || in_32[2] == 0xFFFF0000 // v4mapped or SIIT (endianness...)
        || in_32[2] == 0x0000FFFF // v4mapped or SIIT (endianness...)
    )) {
        mask_adj = 96;
        *ipv4 = in_32[3];
    }
    else if(in[0] == 0x20) {
        // Teredo
        if(in[1] == 0x01 && in_16[1] == 0x0000) {
            mask_adj = 96;
            *ipv4 = in_32[3] ^ 0xFFFFFFFF;
        }
        // 6to4
        else if(in[1] == 0x02) {
            mask_adj = 16;
            *ipv4 = *((uint32_t*)&in[2]);
        }
    }

    return mask_adj;
}

F_NONNULL
static unsigned ntree_lookup(const ntree_t* tree, const client_info_t* client, unsigned* scope_mask) {
    dmn_assert(tree); dmn_assert(client);

    bool using_edns;
    unsigned nomask = 0;
    const anysin_t* client_addr;
    unsigned* mask_out;

    if(client->edns_client_mask) {
        using_edns = true;
        client_addr = &client->edns_client;
        mask_out = scope_mask;
    }
    else {
        using_edns = false;
        client_addr = &client->dns_source;
        mask_out = &nomask;
        *scope_mask = client->edns_client_mask;
    }

    do {
        if(client_addr->sa.sa_family == AF_INET) {
            return ntree_lookup_v4(tree, ntohl(client_addr->sin.sin_addr.s_addr), mask_out);
        }
        else {
            dmn_assert(client_addr->sa.sa_family == AF_INET6);
            uint32_t temp_v4;
            const int mask_adj = v6_v4compat(client_addr->sin6.sin6_addr.s6_addr, &temp_v4);
            if(mask_adj) {
                // client_addr was really v4, so do a mask-adjusted v4 lookup
                unsigned temp_mask;
                const unsigned rv = ntree_lookup_v4(tree, ntohl(temp_v4), &temp_mask);
                *mask_out = temp_mask + mask_adj;
                return rv;
            }
            else {
                // true v6 lookup on v6 db
                if(tree->ipv6) {
                    return ntree_lookup_v6(tree, client_addr->sin6.sin6_addr.s6_addr, mask_out);
                }
                else {
                    // tree is v4 and client_addr is really v6-only, so:

                    // if client_addr was from edns, fall back
                    //  to dns_source and retry the whole process
                    if(using_edns) {
                        using_edns = false;
                        client_addr = &client->dns_source;
                        mask_out = &nomask;
                        *scope_mask = client->edns_client_mask;
                    }

                    // if we're down to dns_source, return global default
                    else {
                        return 0;
                    }
                }
            }
        }
    } while(1);
}

/***************************************
 * gdmap_t/geoip_db_t and related methods
 **************************************/

typedef struct {
    pthread_rwlock_t tree_lock;
    char* name;
    char* geoip_path;
    char* geoip_v4o_path;
    const fips_t* fips;
    ntree_t* tree;
    dcinfo_t* dcinfo; // basic datacenter list/info
    // unique ordered result datacenter lists
    //   (this copy is temporary until first database load...)
    dclists_t* init_dclists;
    dcmap_t* dcmap; // map of locinfo -> dclist
    nets_t* nets; // net overrides
    ev_stat* geoip_stat_watcher;
    ev_stat* geoip_stat_watcher_v4o;
    ev_timer* geoip_reload_timer;
    bool city_no_region;
    bool city_no_city;
    bool city_auto_mode;
} gdmap_t;

typedef struct {
    unsigned offset;
    unsigned dclist;
} offset_cache_item_t;
#define OFFSET_CACHE_SIZE (1 << 18)

typedef struct {
    char* pathname;
    uint8_t* data;
    const fips_t* fips;
    unsigned size;
    int fd;
    int type;
    unsigned base;
    bool ipv6;

    offset_cache_item_t *offset_cache[OFFSET_CACHE_SIZE];
} geoip_db_t;

F_NONNULL
static int geoip_db_close(geoip_db_t* db);
F_NONNULLX(1)
static geoip_db_t* geoip_db_open(const char* pathname, const fips_t* fips, const char* map_name, const bool city_required);
F_NONNULLX(1, 2, 3)
static int geoip_tree_xlate(const gdmap_t* gdmap, ntree_t* tree, geoip_db_t* db, geoip_db_t* db_v4o);

F_NONNULL
static ntree_t* gdmap_make_tree(const gdmap_t* gdmap, const dclists_t* old_dclists) {
    dmn_assert(gdmap);
    dmn_assert(gdmap->geoip_path);

    geoip_db_t* geodb_v4o = NULL;
    geoip_db_t* geodb = geoip_db_open(gdmap->geoip_path, gdmap->fips, gdmap->name, gdmap->city_auto_mode);
    if(!geodb)
        return NULL;

    if(gdmap->geoip_v4o_path) {
        if(!geodb->ipv6) {
            log_err("plugin_geoip: map '%s': geoip_db_v4_overlay in effect, but primary geoip_db '%s' is not an IPv6 database!", gdmap->name, gdmap->geoip_path);
            geoip_db_close(geodb);
            return NULL;
        }
        if(!(geodb_v4o = geoip_db_open(gdmap->geoip_v4o_path, gdmap->fips, gdmap->name, gdmap->city_auto_mode))) {
            geoip_db_close(geodb);
            return NULL;
        }
        if(geodb_v4o->ipv6) {
            log_err("plugin_geoip: map '%s': geoip_db_v4_overlay '%s' is not an IPv4 database!", gdmap->name, gdmap->geoip_v4o_path);
            geoip_db_close(geodb_v4o);
            geoip_db_close(geodb);
            return NULL;
        }
    }

    ntree_t* tree = ntree_new(geodb->ipv6, old_dclists);

    if(geoip_tree_xlate(gdmap, tree, geodb, geodb_v4o)) {
        if(geodb_v4o) geoip_db_close(geodb_v4o);
        geoip_db_close(geodb);
        ntree_destroy(tree, KILL_NEW_LISTS);
        return NULL;
    }

    if(geodb_v4o && geoip_db_close(geodb_v4o)) {
        geoip_db_close(geodb);
        ntree_destroy(tree, KILL_NEW_LISTS);
        return NULL;
    }

    if(geoip_db_close(geodb)) {
        ntree_destroy(tree, KILL_NEW_LISTS);
        return NULL;
    }

    unsigned netsct = 0;
    if(gdmap->nets) {
        if(ntree_apply_nets(tree, gdmap->nets, gdmap->name)) {
            ntree_destroy(tree, KILL_NEW_LISTS);
            return NULL;
        }
        netsct = gdmap->nets->count;
    }

    log_info("plugin_geoip: map '%s' stats: geoip nets: %u optimized nets: %u (overrides: %u) dclists: %u", gdmap->name, tree->raw_count, tree->terminals, netsct, dclists_get_count(tree->dclists));

    ntree_finalize(tree);
    return tree;
}

F_NONNULL
static bool _gdmap_badkey(const char* key, unsigned klen V_UNUSED, const vscf_data_t* val V_UNUSED, void* data) {
    dmn_assert(key); dmn_assert(data);
    log_fatal("plugin_geoip: map '%s': invalid config key '%s'", (const char*)data, key);
    return false;
}

F_NONNULLX(1,2)
static gdmap_t* gdmap_new(const char* name, const vscf_data_t* map_cfg, const fips_t* fips) {
    dmn_assert(name); dmn_assert(map_cfg);

    // basics
    gdmap_t* gdmap = calloc(1, sizeof(gdmap_t));
    gdmap->name = strdup(name);
    gdmap->fips = fips;
    if(!vscf_is_hash(map_cfg))
        log_fatal("plugin_geoip: value for map '%s' must be a hash", name);

    // datacenters config
    const vscf_data_t* dc_cfg = vscf_hash_get_data_byconstkey(map_cfg, "datacenters", true);
    if(!dc_cfg)
        log_fatal("plugin_geoip: map '%s': missing required 'datacenters' array", name);
    const vscf_data_t* dc_auto_cfg = vscf_hash_get_data_byconstkey(map_cfg, "auto_dc_coords", true);
    const vscf_data_t* dc_auto_limit_cfg = vscf_hash_get_data_byconstkey(map_cfg, "auto_dc_limit", true);
    gdmap->city_auto_mode = dc_auto_cfg ? true : false;
    gdmap->dcinfo = dcinfo_new(dc_cfg, dc_auto_cfg, dc_auto_limit_cfg, name);
    gdmap->init_dclists = dclists_new(gdmap->dcinfo);

    // map config
    const vscf_data_t* map_map = vscf_hash_get_data_byconstkey(map_cfg, "map", true);
    if(map_map) {
        if(!vscf_is_hash(map_map))
            log_fatal("plugin_geoip: map '%s': 'map' stanza must be a hash", name);
        gdmap->dcmap = dcmap_new(map_map, gdmap->init_dclists, 0, 0, name, gdmap->city_auto_mode);
    }

    // nets config
    const vscf_data_t* nets_cfg = vscf_hash_get_data_byconstkey(map_cfg, "nets", true);
    if(nets_cfg) {
        if(!vscf_is_hash(nets_cfg))
            log_fatal("plugin_geoip: map '%s': 'nets' stanza must be a hash", name);
        gdmap->nets = nets_new(nets_cfg, gdmap->init_dclists, name);
    }

    // geoip_db config
    const vscf_data_t* gdb_cfg = vscf_hash_get_data_byconstkey(map_cfg, "geoip_db", true);
    if(!gdb_cfg)
        log_fatal("plugin_geoip: map '%s': missing required 'geoip_db' value", name);
    if(!vscf_is_simple(gdb_cfg) || !vscf_simple_get_len(gdb_cfg))
        log_fatal("plugin_geoip: map '%s': 'geoip_db' must have a non-empty string value", name);
    gdmap->geoip_path = str_combine(GEOIP_DIR, vscf_simple_get_data(gdb_cfg), NULL);

    // geoip_db_v4_overlay config
    const vscf_data_t* gdb_v4o_cfg = vscf_hash_get_data_byconstkey(map_cfg, "geoip_db_v4_overlay", true);
    if(gdb_v4o_cfg) {
        if(!vscf_is_simple(gdb_v4o_cfg) || !vscf_simple_get_len(gdb_v4o_cfg))
            log_fatal("plugin_geoip: map '%s': 'geoip_db_v4_overlay' must have a non-empty string value", name);
        gdmap->geoip_v4o_path = str_combine(GEOIP_DIR, vscf_simple_get_data(gdb_v4o_cfg), NULL);
    }

    // optional GeoIPCity behavior flags
    gdmap->city_no_region = false;
    gdmap->city_no_city = false;
    const vscf_data_t* cnr_cfg = vscf_hash_get_data_byconstkey(map_cfg, "city_no_region", true);
    if(cnr_cfg) {
        if(!vscf_is_simple(cnr_cfg) || !vscf_simple_get_as_bool(cnr_cfg, &gdmap->city_no_region))
            log_fatal("plugin_geoip: map '%s': 'city_no_region' must be a boolean value ('true' or 'false')", name);
    }
    const vscf_data_t* cnc_cfg = vscf_hash_get_data_byconstkey(map_cfg, "city_no_city", true);
    if(cnc_cfg) {
        if(!vscf_is_simple(cnc_cfg) || !vscf_simple_get_as_bool(cnc_cfg, &gdmap->city_no_city))
            log_fatal("plugin_geoip: map '%s': 'city_no_city' must be a boolean value ('true' or 'false')", name);
    }

    // check for invalid keys
    vscf_hash_iterate(map_cfg, true, _gdmap_badkey, (void*)name);

    // Set up tree lock for runtime reloads
    int pthread_err;
    pthread_rwlockattr_t lockatt;
    if((pthread_err = pthread_rwlockattr_init(&lockatt)))
        log_fatal("plugin_geoip: pthread_rwlockattr_init() failed: %s", logf_errnum(pthread_err));

    // Non-portable way to boost writer priority.  Our writelocks are held very briefly
    //  and very rarely, whereas the readlocks could be very spammy, and we don't want to
    //  block the write operation forever.  This works on Linux+glibc.
#   ifdef PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP
        if((pthread_err = pthread_rwlockattr_setkind_np(&lockatt, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)))
            log_fatal("plugin_geoip: pthread_rwlockattr_setkind_np(PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP) failed: %s", logf_errnum(pthread_err));
#   endif

    if((pthread_err = pthread_rwlock_init(&gdmap->tree_lock, &lockatt)))
        log_fatal("plugin_geoip: pthread_rwlock_init() failed: %s", logf_errnum(pthread_err));
    if((pthread_err = pthread_rwlockattr_destroy(&lockatt)))
        log_fatal("plugin_geoip: pthread_rwlockattr_destroy() failed: %s", logf_errnum(pthread_err));

    return gdmap;
}

F_NONNULL
static int gdmap_reload_geoip(gdmap_t* gdmap) {
    dmn_assert(gdmap);
    dmn_assert( (gdmap->init_dclists && !gdmap->tree)
        || (!gdmap->init_dclists && gdmap->tree) );

    ntree_t* old_tree = gdmap->tree;
    ntree_t* new_tree = gdmap_make_tree(gdmap, old_tree ? old_tree->dclists : gdmap->init_dclists);
    if(!new_tree)
        return -1;

    pthread_rwlock_wrlock(&gdmap->tree_lock);
    gdmap->tree = new_tree;
    pthread_rwlock_unlock(&gdmap->tree_lock);

    log_info("plugin_geoip: map '%s': (Re-)Load of GeoIP database(s) complete", gdmap->name);

    if(old_tree) {
        ntree_destroy(old_tree, KILL_NO_LISTS);
    }
    else {
        dclists_destroy(gdmap->init_dclists, KILL_NO_LISTS);
        gdmap->init_dclists = NULL;
    }

    return 0;
}

// Initial load
F_NONNULL
static void gdmap_load_geoip(gdmap_t* gdmap) {
    dmn_assert(gdmap);
    dmn_assert(!gdmap->tree);
    dmn_assert(gdmap->init_dclists);
    if(gdmap_reload_geoip(gdmap))
        log_fatal("plugin_geoip: map '%s': Initial tree construction failed", gdmap->name);
}

F_NONNULL
static void gdmap_geoip_reload_timer_cb(struct ev_loop* loop, ev_timer* w V_UNUSED, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_TIMER);

    gdmap_t* gdmap = (gdmap_t*)w->data;
    ev_timer_stop(loop, gdmap->geoip_reload_timer);
    gdmap_reload_geoip(gdmap);
}

F_NONNULL
static void gdmap_geoip_reload_stat_cb(struct ev_loop* loop, ev_stat* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_STAT);

    gdmap_t* gdmap = (gdmap_t*)w->data;

    if(w->attr.st_nlink) { // file exists
        if(w->attr.st_mtime != w->prev.st_mtime || !w->prev.st_nlink) {
            // Start (or restart) a timer to geoip_reload_timer_cb, so that we
            //  wait for multiple changes to "settle" before re-reading the file
            log_debug("plugin_geoip: map '%s': stat watcher triggered, settle-down timer kicked for a fresh %g secs", gdmap->name, GEOIP_RELOAD_WAIT);
            ev_timer_again(loop, gdmap->geoip_reload_timer);
        }
    }
    else {
        log_warn("plugin_geoip: map '%s': GeoIP database file dissappeared! Internal DB remains unchanged, waiting for it to re-appear...", gdmap->name);
    }
}

F_NONNULL
static void gdmap_setup_geoip_watcher(gdmap_t* gdmap, struct ev_loop* loop) {
    dmn_assert(gdmap); dmn_assert(loop);
    dmn_assert(gdmap->geoip_path);

    // the reload settling timer
    gdmap->geoip_reload_timer = malloc(sizeof(ev_timer));
    ev_init(gdmap->geoip_reload_timer, gdmap_geoip_reload_timer_cb);
    ev_set_priority(gdmap->geoip_reload_timer, -1);
    gdmap->geoip_reload_timer->repeat = GEOIP_RELOAD_WAIT;
    gdmap->geoip_reload_timer->data = gdmap;

    // watcher on gdmap->geoip_path to reload the db
    gdmap->geoip_stat_watcher = malloc(sizeof(ev_stat));
    ev_stat_init(gdmap->geoip_stat_watcher, gdmap_geoip_reload_stat_cb, gdmap->geoip_path, 0);
    ev_set_priority(gdmap->geoip_stat_watcher, 0);
    gdmap->geoip_stat_watcher->data = gdmap;
    ev_stat_start(loop, gdmap->geoip_stat_watcher);

    // ditto for v4o_path, using the same callback and reload timer
    if(gdmap->geoip_v4o_path) {
        gdmap->geoip_stat_watcher_v4o = malloc(sizeof(ev_stat));
        ev_stat_init(gdmap->geoip_stat_watcher_v4o, gdmap_geoip_reload_stat_cb, gdmap->geoip_v4o_path, 0);
        ev_set_priority(gdmap->geoip_stat_watcher_v4o, 0);
        gdmap->geoip_stat_watcher_v4o->data = gdmap;
        ev_stat_start(loop, gdmap->geoip_stat_watcher_v4o);
    }
}

F_NONNULL
static const char* gdmap_get_name(const gdmap_t* gdmap) {
    dmn_assert(gdmap);
    return gdmap->name;
}

F_NONNULLX(1,2)
static void gdmap_iter_dclists(const gdmap_t* gdmap, gdmaps_iter_dclists_cb_t f, void* data) {
    dmn_assert(gdmap); dmn_assert(f);
    dmn_assert(gdmap->init_dclists || gdmap->tree);
    dclists_iterate(gdmap->tree ? gdmap->tree->dclists : gdmap->init_dclists, f, data);
}

F_NONNULL
static const uint8_t*  gdmap_lookup(gdmap_t* gdmap, const client_info_t* client, unsigned* scope_mask) {
    dmn_assert(gdmap); dmn_assert(client);

    pthread_rwlock_rdlock(&gdmap->tree_lock);
    const unsigned dclist_u = ntree_lookup(gdmap->tree, client, scope_mask);
    const uint8_t* dclist_u8 = dclists_get_list(gdmap->tree->dclists, dclist_u);
    pthread_rwlock_unlock(&gdmap->tree_lock);

    dmn_assert(dclist_u8);
    return dclist_u8;
}

// In practice, the real plugin running in a daemon doesn't bother destroying
//  gdmap_t's, so there is no race here on pthread_cancel() of i/o
//  thread doing rdlock lookups and lock destruction here.
F_NONNULL
static void gdmap_destroy(gdmap_t* gdmap) {
    dmn_assert(gdmap);

    int pthread_err;
    if((pthread_err = pthread_rwlock_destroy(&gdmap->tree_lock)))
        log_fatal("plugin_geoip: pthread_rwlock_destroy() failed: %s", logf_errnum(pthread_err));
    if(gdmap->tree)
        ntree_destroy(gdmap->tree, KILL_ALL_LISTS);
    if(gdmap->nets)
        nets_destroy(gdmap->nets);
    free(gdmap->name);
    if(gdmap->geoip_v4o_path)
        free(gdmap->geoip_v4o_path);
    if(gdmap->geoip_path)
        free(gdmap->geoip_path);
    if(gdmap->geoip_stat_watcher_v4o)
        free(gdmap->geoip_stat_watcher_v4o);
    if(gdmap->geoip_stat_watcher)
        free(gdmap->geoip_stat_watcher);
    if(gdmap->geoip_reload_timer)
        free(gdmap->geoip_reload_timer);
    if(gdmap->init_dclists)
        dclists_destroy(gdmap->init_dclists, KILL_ALL_LISTS);
    dcinfo_destroy(gdmap->dcinfo);
    if(gdmap->dcmap)
        dcmap_destroy(gdmap->dcmap);
    free(gdmap);
}

/*****************************************************************************
 * This portion of the code in this file is specific to parsing
 * MaxMind's various GeoIP databases, and much of it was obviously created by
 * examining the code of (and copying the constants from) MaxMind's own
 * libGeoIP, which is licensed under the LGPL.
 * The code in this file is licensed under the GPLv3, which is compatible,
 * but in any case it's mostly just constants that were copied.
 ****************************************************************************/

#define COUNTRY_BEGIN 16776960
#define LARGE_COUNTRY_BEGIN 16515072
#define STATE_BEGIN_REV1 16000000
#define US_OFFSET 1
#define CANADA_OFFSET 677
#define WORLD_OFFSET 1353
#define FIPS_RANGE 360
#define STRUCTURE_INFO_MAX_SIZE 20
#define GEOIP_COUNTRY_EDITION          1
#define GEOIP_CITY_EDITION_REV1        2
#define GEOIP_REGION_EDITION_REV1      3
#define GEOIP_CITY_EDITION_REV0        6
#define GEOIP_COUNTRY_EDITION_V6       12
#define GEOIP_LARGE_COUNTRY_EDITION    17
#define GEOIP_LARGE_COUNTRY_EDITION_V6 18
#define GEOIP_CITY_EDITION_REV1_V6     30
#define GEOIP_CITY_EDITION_REV0_V6     31

const char GeoIP_country_continent[254][3] = { "--",
    "AS","EU","EU","AS","AS","NA","NA","EU","AS","NA",
    "AF","AN","SA","OC","EU","OC","NA","AS","EU","NA",
    "AS","EU","AF","EU","AS","AF","AF","NA","AS","SA",
    "SA","NA","AS","AN","AF","EU","NA","NA","AS","AF",
    "AF","AF","EU","AF","OC","SA","AF","AS","SA","NA",
    "NA","AF","AS","AS","EU","EU","AF","EU","NA","NA",
    "AF","SA","EU","AF","AF","AF","EU","AF","EU","OC",
    "SA","OC","EU","EU","NA","AF","EU","NA","AS","SA",
    "AF","EU","NA","AF","AF","NA","AF","EU","AN","NA",
    "OC","AF","SA","AS","AN","NA","EU","NA","EU","AS",
    "EU","AS","AS","AS","AS","AS","EU","EU","NA","AS",
    "AS","AF","AS","AS","OC","AF","NA","AS","AS","AS",
    "NA","AS","AS","AS","NA","EU","AS","AF","AF","EU",
    "EU","EU","AF","AF","EU","EU","AF","OC","EU","AF",
    "AS","AS","AS","OC","NA","AF","NA","EU","AF","AS",
    "AF","NA","AS","AF","AF","OC","AF","OC","AF","NA",
    "EU","EU","AS","OC","OC","OC","AS","NA","SA","OC",
    "OC","AS","AS","EU","NA","OC","NA","AS","EU","OC",
    "SA","AS","AF","EU","EU","AF","AS","OC","AF","AF",
    "EU","AS","AF","EU","EU","EU","AF","EU","AF","AF",
    "SA","AF","NA","AS","AF","NA","AF","AN","AF","AS",
    "AS","OC","AS","AF","OC","AS","EU","NA","OC","AS",
    "AF","EU","AF","OC","NA","SA","AS","EU","NA","SA",
    "NA","NA","AS","OC","OC","OC","AS","AF","EU","AF",
    "AF","EU","AF","--","--","--","EU","EU","EU","EU",
    "NA","NA","NA"
};

// this one's just for map validation
#define NUM_CONTINENTS 8
const char continent_list[NUM_CONTINENTS][3] = {
   "--", "AS", "AF", "OC", "EU", "NA", "SA", "AN"
};

#define NUM_COUNTRIES 254
const char GeoIP_country_code[NUM_COUNTRIES][3] = { "--",
    "AP","EU","AD","AE","AF","AG","AI","AL","AM","CW",
    "AO","AQ","AR","AS","AT","AU","AW","AZ","BA","BB",
    "BD","BE","BF","BG","BH","BI","BJ","BM","BN","BO",
    "BR","BS","BT","BV","BW","BY","BZ","CA","CC","CD",
    "CF","CG","CH","CI","CK","CL","CM","CN","CO","CR",
    "CU","CV","CX","CY","CZ","DE","DJ","DK","DM","DO",
    "DZ","EC","EE","EG","EH","ER","ES","ET","FI","FJ",
    "FK","FM","FO","FR","SX","GA","GB","GD","GE","GF",
    "GH","GI","GL","GM","GN","GP","GQ","GR","GS","GT",
    "GU","GW","GY","HK","HM","HN","HR","HT","HU","ID",
    "IE","IL","IN","IO","IQ","IR","IS","IT","JM","JO",
    "JP","KE","KG","KH","KI","KM","KN","KP","KR","KW",
    "KY","KZ","LA","LB","LC","LI","LK","LR","LS","LT",
    "LU","LV","LY","MA","MC","MD","MG","MH","MK","ML",
    "MM","MN","MO","MP","MQ","MR","MS","MT","MU","MV",
    "MW","MX","MY","MZ","NA","NC","NE","NF","NG","NI",
    "NL","NO","NP","NR","NU","NZ","OM","PA","PE","PF",
    "PG","PH","PK","PL","PM","PN","PR","PS","PT","PW",
    "PY","QA","RE","RO","RU","RW","SA","SB","SC","SD",
    "SE","SG","SH","SI","SJ","SK","SL","SM","SN","SO",
    "SR","ST","SV","SY","SZ","TC","TD","TF","TG","TH",
    "TJ","TK","TM","TN","TO","TL","TR","TT","TV","TW",
    "TZ","UA","UG","UM","US","UY","UZ","VA","VC","VE",
    "VG","VI","VN","VU","WF","WS","YE","YT","RS","ZA",
    "ZM","ME","ZW","A1","A2","O1","AX","GG","IM","JE",
    "BL","MF","BQ"
};

static void validate_country_code(const char* cc, const char* map_name) {
    for(unsigned i = 0; i < NUM_COUNTRIES; i++)
        if( !((cc[0] ^ GeoIP_country_code[i][0]) & 0xDF)
         && !((cc[1] ^ GeoIP_country_code[i][1]) & 0xDF)
         && !cc[2])
            return;
    log_fatal("plugin_geoip: map '%s': Country code '%s' is illegal", map_name, cc);
}

static void validate_continent_code(const char* cc, const char* map_name) {
    for(unsigned i = 0; i < NUM_CONTINENTS; i++)
        if( !((cc[0] ^ continent_list[i][0]) & 0xDF)
         && !((cc[1] ^ continent_list[i][1]) & 0xDF)
         && !cc[2])
            return;
    log_fatal("plugin_geoip: map '%s': Continent code '%s' is illegal", map_name, cc);
}

F_NONNULL
static unsigned region_lookup_dclist(const unsigned int ccid, const dcmap_t* dcmap) {
    dmn_assert(dcmap);

    char locstr[10];

    if (ccid < US_OFFSET) {
        locstr[0] = '-';
        locstr[1] = '-';
        locstr[2] = '\0';
        locstr[3] = '-';
        locstr[4] = '-';
        locstr[5] = '\0';
        locstr[6] = '\0';
    }
    else if (ccid < CANADA_OFFSET) {
        locstr[0] = 'N';
        locstr[1] = 'A';
        locstr[2] = '\0';
        locstr[3] = 'U';
        locstr[4] = 'S';
        locstr[5] = '\0';
        locstr[6] = (char) ((ccid - US_OFFSET) / 26 + 65);
        locstr[7] = (char) ((ccid - US_OFFSET) % 26 + 65);
        locstr[8] = '\0';
        locstr[9] = '\0';
    }
    else if (ccid < WORLD_OFFSET) {
        locstr[0] = 'N';
        locstr[1] = 'A';
        locstr[2] = '\0';
        locstr[3] = 'C';
        locstr[4] = 'A';
        locstr[5] = '\0';
        locstr[6] = (char) ((ccid - CANADA_OFFSET) / 26 + 65);
        locstr[7] = (char) ((ccid - CANADA_OFFSET) % 26 + 65);
        locstr[8] = '\0';
        locstr[9] = '\0';
    }
    else {
        const unsigned ccnum = (ccid - WORLD_OFFSET) / FIPS_RANGE;
        locstr[0] = GeoIP_country_continent[ccnum][0];
        locstr[1] = GeoIP_country_continent[ccnum][1];
        locstr[2] = '\0';
        locstr[3] = GeoIP_country_code[ccnum][0];
        locstr[4] = GeoIP_country_code[ccnum][1];
        locstr[5] = '\0';
        locstr[6] = '\0';
    }

    return dcmap_lookup_loc(dcmap, locstr);
}

F_NONNULL
static unsigned country_lookup_dclist(const unsigned int ccid, const dcmap_t* dcmap) {
    dmn_assert(dcmap);

    char locstr[7];

    locstr[0] = GeoIP_country_continent[ccid][0];
    locstr[1] = GeoIP_country_continent[ccid][1];
    locstr[2] = '\0';
    locstr[3] = GeoIP_country_code[ccid][0];
    locstr[4] = GeoIP_country_code[ccid][1];
    locstr[5] = '\0';
    locstr[6] = '\0';

    return dcmap_lookup_loc(dcmap, locstr);
}

F_NONNULL
static unsigned city_lookup_dclist(const geoip_db_t* db, unsigned int offs, const gdmap_t* gdmap, const ntree_t* tree) {
    dmn_assert(db); dmn_assert(gdmap);

    char locstr[256];
    unsigned raw_lat = 0;
    unsigned raw_lon = 0;

    if(!gdmap->city_auto_mode && !gdmap->dcmap)
        return 0;

    // Not found in DB
    if(offs == db->base) {
        if(gdmap->dcmap) {
            locstr[0] = '-';
            locstr[1] = '-';
            locstr[2] = '\0';
            locstr[3] = '-';
            locstr[4] = '-';
            locstr[5] = '\0';
            locstr[6] = '\0';
        }
        // 1800000 == 0.0 when raw is converted to floating-point degrees
        raw_lat = 1800000;
        raw_lon = 1800000;
    }
    else {
        offs += 5 * db->base;
        const uint8_t* rec = &db->data[offs];

        if(gdmap->dcmap) {
            locstr[0] = GeoIP_country_continent[rec[0]][0];
            locstr[1] = GeoIP_country_continent[rec[0]][1];
            locstr[2] = '\0';
            locstr[3] = GeoIP_country_code[rec[0]][0];
            locstr[4] = GeoIP_country_code[rec[0]][1];
            locstr[5] = '\0';
        }

        unsigned loc_pos = 6;
        rec++;

        // Get ptr to region_name from db, get length, skip past it in db
        const char* region_name = (const char*)rec;
        unsigned region_len = strlen(region_name);
        rec += region_len;
        rec++;

        // If we want to use region-level info...
        if(gdmap->dcmap && !gdmap->city_no_region) {
            // Check for FIPS 10-4 conversion, replacing
            //  region_name/region_len if so.
            if(region_len == 2 && db->fips) {
                const uint32_t key = ((unsigned)locstr[3])
                    + ((unsigned)locstr[4] << 8U)
                    + ((unsigned)region_name[0] << 16U)
                    + ((unsigned)region_name[1] << 24U);
                const char* rname = fips_lookup(db->fips, key);
                if(rname) {
                    region_name = rname;
                    region_len = strlen(region_name);
                }
            }

            if(!region_len || !*region_name || region_len > 120U) {
                // Handle oversize and empty cases as "--"
                if(region_len > 120U)
                    log_err("plugin_geoip: Bug: GeoIP City region name much longer than expected: %u '%s'", region_len, rec);
                locstr[loc_pos++] = '-';
                locstr[loc_pos++] = '-';
            }
            else {
                memcpy(&locstr[loc_pos], region_name, region_len);
                loc_pos += region_len;
            }
            locstr[loc_pos++] = '\0';
        }

        const char* city_name = (const char*)rec;
        const unsigned city_len = strlen(city_name);
        rec += city_len;
        rec++;

        if(gdmap->dcmap && !gdmap->city_no_city) {
            if(city_len > 120U) {
                log_err("plugin_geoip: Bug: GeoIP City city name much longer than expected: %u '%s'", city_len, rec);
            }
            else if(city_len) {
                memcpy(&locstr[loc_pos], city_name, city_len);
                loc_pos += city_len;
                locstr[loc_pos++] = '\0';
            }
        }

        // skip past postal code
        rec += strlen((const char*)rec);
        rec++;

        for(int j = 0; j < 3; ++j)
            raw_lat += (rec[j] << (j * 8));
        rec += 3;

        for(int j = 0; j < 3; ++j)
            raw_lon += (rec[j] << (j * 8));

        if(gdmap->dcmap)
            locstr[loc_pos] = '\0';
    }

    int dclist = gdmap->dcmap ? dcmap_lookup_loc(gdmap->dcmap, locstr) : -1;
    if(dclist < 0) {
        dmn_assert(gdmap->city_auto_mode);
        dmn_assert(dclist == -1);
        dclist = dclists_city_auto_map(tree->dclists, gdmap->name, raw_lat, raw_lon);
    }

    dmn_assert(dclist > -1);
    return dclist;
}

F_NONNULL
static unsigned get_dclist(const gdmap_t* gdmap, const ntree_t* tree, geoip_db_t* db, const unsigned int offset) {
    dmn_assert(gdmap); dmn_assert(db);

    unsigned dclist = 0;
    unsigned bucket_size = 0;
    unsigned ndx = offset % OFFSET_CACHE_SIZE;

    if (db->offset_cache[ndx]) {
        for (bucket_size = 0; db->offset_cache[ndx][bucket_size].offset; bucket_size++)
            if (db->offset_cache[ndx][bucket_size].offset == offset)
                return db->offset_cache[ndx][bucket_size].dclist;
    }

    switch(db->type) {
        case GEOIP_CITY_EDITION_REV1_V6:
        case GEOIP_CITY_EDITION_REV0_V6:
        case GEOIP_CITY_EDITION_REV1:
        case GEOIP_CITY_EDITION_REV0:
            dclist = city_lookup_dclist(db, offset, gdmap, tree);
            break;
        case GEOIP_COUNTRY_EDITION_V6:
        case GEOIP_LARGE_COUNTRY_EDITION_V6:
        case GEOIP_COUNTRY_EDITION:
        case GEOIP_LARGE_COUNTRY_EDITION:
            dclist = gdmap->dcmap ? country_lookup_dclist(offset - db->base, gdmap->dcmap) : 0;
            break;
        case GEOIP_REGION_EDITION_REV1:
            dclist = gdmap->dcmap ? region_lookup_dclist(offset - db->base, gdmap->dcmap) : 0;
            break;
        default:
            log_fatal("plugin_geoip: Bug: Unknown database type %i", db->type);
            break;
    }

    db->offset_cache[ndx] = realloc(db->offset_cache[ndx], sizeof(offset_cache_item_t) * (bucket_size+2));
    dmn_assert(db->offset_cache[ndx]);
    db->offset_cache[ndx][bucket_size].offset = offset;
    db->offset_cache[ndx][bucket_size].dclist = dclist;
    db->offset_cache[ndx][bucket_size+1].offset = 0;

    return dclist;
}

// Used to create two variant functions (IPv4 vs IPv6) which translate
//   GeoIP databases to optimized ntree_t trees.
// C really needs a better macro/template idea :(
#define DEFUN_TREE_XLATE(IPVN, IPTYPE, IPZERO, BITDEPTH, V4ROOT_CODE, SKIP_CODE) \
F_NONNULL              \
static int geoip_tree_xlate_ ## IPVN(const gdmap_t* gdmap, ntree_t* tree, geoip_db_t* db) { \
    dmn_assert(gdmap); dmn_assert(tree); dmn_assert(db); \
    struct {                                             \
        int depth;                                       \
        unsigned offset;                                 \
        unsigned tree_off;                               \
        IPTYPE ip;                                       \
    } ones_stack[BITDEPTH];                              \
    int ones_todo = 0;                                   \
    int rv = 0;                                          \
    int depth = BITDEPTH;                                \
    unsigned offset = 0;                                 \
    unsigned tree_off = tree->ipv4_root;                 \
    IPTYPE ip = IPZERO;                                  \
    while(1) {                                           \
        if(offset >= db->base) {                         \
            dmn_assert(!tree->store[tree_off].terminal); \
            dmn_assert(!tree->store[tree_off].zero);     \
            dmn_assert(!tree->store[tree_off].one);      \
            dmn_assert(!tree->store[tree_off].dclist);   \
            tree->raw_count++;                           \
            tree->store[tree_off].terminal = 1U;         \
            tree->store[tree_off].dclist = get_dclist(gdmap, tree, db, offset);                    \
            tree->terminals++;                                                                     \
            while(likely(tree_off > 1)                                                             \
                && tree_off == tree->store[tree_off - 2].one                                       \
                && tree_off != tree->ipv4_root                                                     \
                && (tree_off - 1) == tree->store[tree_off - 2].zero                                \
                && !memcmp(&tree->store[tree_off - 1], &tree->store[tree_off], sizeof(nnode_t))) { \
                tree_off -= 2;                                                                     \
                dmn_assert(!tree->store[tree_off].terminal);                                       \
                dmn_assert(tree->store[tree_off + 1].terminal);                                    \
                dmn_assert(tree->store[tree_off + 2].terminal);                                    \
                memcpy(&tree->store[tree_off], &tree->store[tree_off + 1], sizeof(nnode_t));       \
                tree->count -= 2;                                                                  \
                tree->terminals--;                                                                 \
                memset(&tree->store[tree->count], 0, 2 * sizeof(nnode_t));                         \
            }                                                              \
            if(ones_todo--) {                                              \
                depth = ones_stack[ones_todo].depth;                       \
                offset = ones_stack[ones_todo].offset;                     \
                tree_off = ones_stack[ones_todo].tree_off;                 \
                ip = ones_stack[ones_todo].ip;                             \
                dmn_assert(!tree->store[tree_off].one);                    \
                const unsigned tree_off_tmp = ntree_add_node(tree);        \
                tree_off = tree->store[tree_off].one = tree_off_tmp;       \
                V4ROOT_CODE \
            }               \
            else {          \
                break;      \
            }               \
        }                   \
        else {              \
            if(unlikely( depth < 1 || ((3 * 2 * offset) + 6) > db->size )) { \
                log_err("plugin_geoip: map '%s': "                \
                    "Error traversing GeoIP database, corrupt?",  \
                    gdmap->name);                                 \
                rv = -1;                                          \
                break;                                            \
            }                                                     \
            dmn_assert(!tree->store[tree_off].terminal);          \
            const unsigned char *buf = db->data + 3 * 2 * offset; \
            depth--;                                              \
            bool skip_one = false;                                \
            bool skip_zero = false;                               \
            SKIP_CODE                                             \
            dmn_assert(!skip_one || !skip_zero);                  \
            if(!skip_one && !skip_zero) {                         \
                ones_stack[ones_todo].depth = depth;              \
                ones_stack[ones_todo].offset                      \
                    = buf[3] + (buf[4] << 8) + (buf[5] << 16);    \
                ones_stack[ones_todo].tree_off = tree_off;        \
                ones_stack[ones_todo].ip = ip;                    \
                SETBIT_ ## IPVN(ones_stack[ones_todo].ip,depth);  \
                ones_todo++;                                      \
            }                                                     \
            const unsigned tree_off_tmp = ntree_add_node(tree);   \
            if(!skip_zero) {                                      \
                dmn_assert(!tree->store[tree_off].zero);              \
                tree_off = tree->store[tree_off].zero = tree_off_tmp; \
                offset = buf[0] + (buf[1] << 8) + (buf[2] << 16);     \
            }      \
            else { \
                dmn_assert(!tree->store[tree_off].zero);              \
                dmn_assert(!tree->store[tree_off].one);               \
                tree->store[tree_off_tmp].terminal = 1;               \
                tree->store[tree_off].zero = tree_off_tmp;            \
                tree->terminals++;                                    \
                const unsigned tree_off_tmp2 = ntree_add_node(tree);  \
                tree_off = tree->store[tree_off].one = tree_off_tmp2; \
                offset = buf[3] + (buf[4] << 8) + (buf[5] << 16);     \
                SETBIT_ ## IPVN(ip,depth);  \
            }      \
        }          \
    }              \
    return rv;     \
}

DEFUN_TREE_XLATE(v4, uint32_t, 0, 32, ;, ;)

#define V6_V4ROOT_CODE \
    if(depth == 32 && !memcmp(ip.s6_addr, start_v4mapped, 12)) \
        tree->ipv4_root = tree_off;

#define V6_SKIP_CODE \
    if(depth == 32) { \
        if(!memcmp(ip.s6_addr, start_v4compat, 12)) \
            skip_zero = true; \
        else if(gdmap->geoip_v4o_path && !memcmp(ip.s6_addr, parent_v4mapped, 12)) \
            skip_one = true; \
    } \
    else if(depth == 112 && ip.s6_addr[0] == 0x20 && ip.s6_addr[1] == 0x02) \
        skip_zero = true; \

DEFUN_TREE_XLATE(v6, struct in6_addr, ip6_zero, 128, V6_V4ROOT_CODE, V6_SKIP_CODE)

static int geoip_tree_xlate(const gdmap_t* gdmap, ntree_t* tree, geoip_db_t* db, geoip_db_t* db_v4o) {
    dmn_assert(gdmap); dmn_assert(tree); dmn_assert(db);

    log_info("plugin_geoip: map '%s': Processing GeoIP database '%s'...", gdmap->name, logf_pathname(gdmap->geoip_path));

    int rv;
    if(db->ipv6) {
        rv = geoip_tree_xlate_v6(gdmap, tree, db);
        ntree_fixup_v4root(tree, !!db_v4o);
        if(!rv && db_v4o) {
            log_info("plugin_geoip: map '%s': Processing GeoIP v4_overlay database '%s'...", gdmap->name, logf_pathname(gdmap->geoip_v4o_path));
            rv = geoip_tree_xlate_v4(gdmap, tree, db_v4o);
        }
    }
    else {
        rv = geoip_tree_xlate_v4(gdmap, tree, db);
    }

    return rv;
}

static int geoip_db_close(geoip_db_t* db) {
    dmn_assert(db);
    int rv = 0;

    if(db->fd != -1) {
        if(db->data) {
            if(-1 == munmap(db->data, db->size)) {
                log_err("plugin_geoip: munmap() of '%s' failed: %s", logf_pathname(db->pathname), logf_errno());
                rv = -1;
            }
        }
        if(close(db->fd) == -1) {
            log_err("plugin_geoip: close() of '%s' failed: %s", logf_pathname(db->pathname), logf_errno());
            rv = -1;
        }
    }

    for (unsigned i = 0; i < OFFSET_CACHE_SIZE; i++)
        free(db->offset_cache[i]);
    if(db->pathname)
        free(db->pathname);
    free(db);

    return rv;
}

static geoip_db_t* geoip_db_open(const char* pathname, const fips_t* fips, const char* map_name, const bool city_required) {
    dmn_assert(pathname);

    geoip_db_t* db = calloc(1, sizeof(geoip_db_t));
    db->fd = -1;
    db->pathname = strdup(pathname);

    if((db->fd = open(pathname, O_RDONLY)) == -1) {
        log_err("plugin_geoip: map '%s': Cannot open '%s' for reading: %s", map_name, logf_pathname(pathname), logf_errno());
        geoip_db_close(db);
        return NULL;
    }

    struct stat db_stat;
    if(fstat(db->fd, &db_stat) == -1) {
        log_err("plugin_geoip: map '%s': Cannot fstat '%s': %s", map_name, logf_pathname(pathname), logf_errno());
        geoip_db_close(db);
        return NULL;
    }

    db->size = db_stat.st_size;

    // 9 bytes would be a single record splitting the IPv4
    //   space into 0.0.0.0/1 and 128.0.0.0/1, each mapped
    //   to a single countryid, plus the requisite 0xFFFFFF
    //   end marker.
    if(db->size < 9) {
        log_err("plugin_geoip: map '%s': GeoIP database '%s' too small", map_name, logf_pathname(pathname));
        geoip_db_close(db);
        return NULL;
    }

    if((db->data = mmap(NULL, db->size, PROT_READ, MAP_SHARED, db->fd, 0)) == MAP_FAILED) {
        db->data = 0;
        log_err("plugin_geoip: map '%s': Failed to mmap GeoIP DB '%s': %s", map_name, logf_pathname(pathname), logf_errno());
        geoip_db_close(db);
        return NULL;
    }

    /* This GeoIP structure info stuff is confusing...
     * Apparently the first structure info record is the final
     *   3 bytes of the file.  If that's 0xFFFFFF, we're done,
     *   and it's a plain country database.
     * If those 3 bytes aren't 0xFFFFFF, then we step back by
     *   *four* bytes and try again.  From here on when we get
     *   our match on the first 3 bytes being 0xFFFFFF, the
     *   4th byte is the database type.
     */
    db->type = GEOIP_COUNTRY_EDITION;
    int offset = db->size - 3;
    for(unsigned i = 0; i < STRUCTURE_INFO_MAX_SIZE; i++) {
        if(db->data[offset] == 255 && db->data[offset + 1] == 255 && db->data[offset + 2] == 255) {
            if(i) db->type = db->data[offset + 3];
            break;
        }
        offset -= 4;
        if(offset < 0)
            break;
    }

    if(city_required) {
        switch(db->type) {
            case GEOIP_CITY_EDITION_REV0_V6:
            case GEOIP_CITY_EDITION_REV1_V6:
            case GEOIP_CITY_EDITION_REV0:
            case GEOIP_CITY_EDITION_REV1:
                break;
            default:
                log_err("plugin_geoip: map '%s': GeoIP DB '%s' is not a City-level database and this map uses auto_dc_coords", map_name, logf_pathname(db->pathname));
                geoip_db_close(db);
                return NULL;
        }
    }

    switch(db->type) {
        case GEOIP_COUNTRY_EDITION_V6:
            db->ipv6 = true;
        case GEOIP_COUNTRY_EDITION:
            db->base = COUNTRY_BEGIN;
            break;

        case GEOIP_LARGE_COUNTRY_EDITION_V6:
            db->ipv6 = true;
        case GEOIP_LARGE_COUNTRY_EDITION:
            db->base = LARGE_COUNTRY_BEGIN;
            break;

        case GEOIP_REGION_EDITION_REV1:
            db->base = STATE_BEGIN_REV1;
            break;

        case GEOIP_CITY_EDITION_REV0_V6:
        case GEOIP_CITY_EDITION_REV1_V6:
            db->ipv6 = true;
        case GEOIP_CITY_EDITION_REV0:
        case GEOIP_CITY_EDITION_REV1:
            offset += 4;
            for(unsigned i = 0; i < 3; i++)
                db->base += (db->data[offset + i] << (i * 8));
            if(fips)
                db->fips = fips;
            break;

        default:
            log_err("plugin_geoip: map '%s': GeoIP DB '%s': Unrecognized DB type %i", map_name, logf_pathname(db->pathname), db->type);
            geoip_db_close(db);
            return NULL;
    }

    return db;
}

/***************************************
 * gdmaps_t and related methods
 **************************************/

struct _gdmaps_t {
    pthread_t reload_tid;
    bool reload_thread_spawned;
    unsigned count;
    struct ev_loop* reload_loop;
    fips_t* fips;
    gdmap_t** maps;
};

F_NONNULL
static bool _gdmaps_new_iter(const char* key, unsigned klen V_UNUSED, const vscf_data_t* val, void* data) {
    dmn_assert(key); dmn_assert(val); dmn_assert(data);
    gdmaps_t* gdmaps = data;
    gdmaps->maps = realloc(gdmaps->maps, sizeof(gdmap_t*) * (gdmaps->count + 1));
    gdmaps->maps[gdmaps->count++] = gdmap_new(key, val, gdmaps->fips);
    return true;
}

gdmaps_t* gdmaps_new(const vscf_data_t* maps_cfg) {
    dmn_assert(maps_cfg);
    dmn_assert(vscf_is_hash(maps_cfg));

    gdmaps_t* gdmaps = calloc(1, sizeof(gdmaps_t));

    const vscf_data_t* crn_cfg = vscf_hash_get_data_byconstkey(maps_cfg, "city_region_names", true);
    if(crn_cfg) {
        if(!vscf_is_simple(crn_cfg))
            log_fatal("plugin_geoip: 'city_region_names' must be a filename as a simple string value");
        gdmaps->fips = fips_init(vscf_simple_get_data(crn_cfg));
    }

    vscf_hash_iterate(maps_cfg, true, _gdmaps_new_iter, gdmaps);
    return gdmaps;
}

int gdmaps_name2idx(const gdmaps_t* gdmaps, const char* map_name) {
    dmn_assert(gdmaps); dmn_assert(map_name);
    for(unsigned i = 0; i < gdmaps->count; i++)
        if(!strcmp(map_name, gdmap_get_name(gdmaps->maps[i])))
            return (int)i;
    return -1;
}

const char* gdmaps_idx2name(const gdmaps_t* gdmaps, const unsigned gdmap_idx) {
    dmn_assert(gdmaps);
    if(gdmap_idx >= gdmaps->count)
        return NULL;
    return gdmap_get_name(gdmaps->maps[gdmap_idx]);
}

unsigned gdmaps_get_dc_count(const gdmaps_t* gdmaps, const unsigned gdmap_idx) {
    dmn_assert(gdmaps);
    dmn_assert(gdmap_idx < gdmaps->count);
    return dcinfo_get_count(gdmaps->maps[gdmap_idx]->dcinfo);
}

unsigned gdmaps_dcname2num(const gdmaps_t* gdmaps, const unsigned gdmap_idx, const char* dcname) {
    dmn_assert(gdmaps); dmn_assert(dcname);
    dmn_assert(gdmap_idx < gdmaps->count);
    return dcinfo_name2num(gdmaps->maps[gdmap_idx]->dcinfo, dcname);
}

const char* gdmaps_dcnum2name(const gdmaps_t* gdmaps, const unsigned gdmap_idx, const unsigned dcnum) {
    dmn_assert(gdmaps);
    dmn_assert(gdmap_idx < gdmaps->count);
    return dcinfo_num2name(gdmaps->maps[gdmap_idx]->dcinfo, dcnum);
}

// mostly for debugging / error output
#define DCLIST_LOGF_MAX 512
static const char dclist_len_err[] = "<dclist too large to format for printing>";
static const char dclist_nodc[] = "<INVALID>";
const char* gdmaps_logf_dclist(const gdmaps_t* gdmaps, const unsigned gdmap_idx, const uint8_t* dclist) {
    dmn_assert(gdmaps); dmn_assert(dclist);
    dmn_assert(gdmap_idx < gdmaps->count);

    char tbuf[DCLIST_LOGF_MAX];
    tbuf[0] = '\0';
    unsigned tbuf_remain = DCLIST_LOGF_MAX - 1;

    unsigned dcnum;
    bool first = true;
    while((dcnum = *dclist++)) {
        const char* dcname = gdmaps_dcnum2name(gdmaps, gdmap_idx, dcnum);
        if(!dcname)
            dcname = dclist_nodc;
        unsigned addlen = strlen(dcname);
        if(!first) addlen += 2;
        if(addlen > tbuf_remain)
            return dclist_len_err;
        if(!first)
            strcat(tbuf, ", ");
        strcat(tbuf, dcname);
        tbuf_remain -= addlen;
        first = false;
    }

    char* buf = dmn_fmtbuf_alloc(strlen(tbuf) + 1);
    strcpy(buf, tbuf);
    return buf;
}

const uint8_t* gdmaps_lookup(const gdmaps_t* gdmaps, const unsigned gdmap_idx, const client_info_t* client, unsigned* scope_mask) {
    dmn_assert(gdmaps); dmn_assert(client);
    dmn_assert(gdmap_idx < gdmaps->count);
    return gdmap_lookup(gdmaps->maps[gdmap_idx], client, scope_mask);
}

void gdmaps_load_geoip_databases(gdmaps_t* gdmaps) {
    dmn_assert(gdmaps);
    for(unsigned i = 0; i < gdmaps->count; i++)
        gdmap_load_geoip(gdmaps->maps[i]);
}

static void* gdmaps_reload_thread(void* arg) {
    gdmaps_t* gdmaps = (gdmaps_t*)arg;

    gdmaps->reload_loop = ev_loop_new(EVFLAG_AUTO);
    ev_set_timeout_collect_interval(gdmaps->reload_loop, 0.5);
    ev_set_io_collect_interval(gdmaps->reload_loop, 0.5);

    for(unsigned i = 0; i < gdmaps->count; i++)
        gdmap_setup_geoip_watcher(gdmaps->maps[i], gdmaps->reload_loop);

    ev_run(gdmaps->reload_loop, 0);

    return NULL;
}

void gdmaps_setup_geoip_watchers(gdmaps_t* gdmaps) {
    dmn_assert(gdmaps);

    pthread_attr_t attribs;
    pthread_attr_init(&attribs);
    pthread_attr_setdetachstate(&attribs, PTHREAD_CREATE_JOINABLE);

    sigset_t sigmask_all, sigmask_prev;
    sigfillset(&sigmask_all);
    pthread_sigmask(SIG_SETMASK, &sigmask_all, &sigmask_prev);

    int pthread_err;
    if((pthread_err = pthread_create(&gdmaps->reload_tid, &attribs, gdmaps_reload_thread, gdmaps)))
        log_fatal("plugin_geoip: failed to create GeoIP reload thread: %s", logf_errnum(pthread_err));

    gdmaps->reload_thread_spawned = true;

    pthread_sigmask(SIG_SETMASK, &sigmask_prev, NULL);
    pthread_attr_destroy(&attribs);
}

void gdmaps_iter_dclists(const gdmaps_t* gdmaps, const unsigned gdmap_idx, gdmaps_iter_dclists_cb_t f, void* data) {
    dmn_assert(gdmaps); dmn_assert(gdmap_idx < gdmaps->count); dmn_assert(f);
    gdmap_iter_dclists(gdmaps->maps[gdmap_idx], f, data);
}

void gdmaps_destroy(gdmaps_t* gdmaps) {
    dmn_assert(gdmaps);
    if(gdmaps->reload_thread_spawned) {
        pthread_cancel(gdmaps->reload_tid);
        pthread_join(gdmaps->reload_tid, NULL);
    }
    if(gdmaps->reload_loop)
        ev_loop_destroy(gdmaps->reload_loop);
    for(unsigned i = 0; i < gdmaps->count; i++)
        gdmap_destroy(gdmaps->maps[i]);
    free(gdmaps->maps);
    if(gdmaps->fips)
        fips_destroy(gdmaps->fips);
    free(gdmaps);
}
