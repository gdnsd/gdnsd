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

#include "config.h"
#include "ntree.h"
#include <gdnsd/log.h>

// Initial node allocation count,
//   must be power of two due to alloc code,
static const unsigned NT_SIZE_INIT = 128;

ntree_t* ntree_new(void) {
    ntree_t* newtree = malloc(sizeof(ntree_t));
    newtree->store = malloc(NT_SIZE_INIT * sizeof(nnode_t));
    newtree->count = 0;
    newtree->alloc = NT_SIZE_INIT; // set to zero on fixation
    return newtree;
}

void ntree_destroy(ntree_t* tree) {
    dmn_assert(tree);
    free(tree->store);
    free(tree);
}

unsigned ntree_add_node(ntree_t* tree) {
    dmn_assert(tree);
    dmn_assert(tree->alloc);
    if(tree->count == tree->alloc) {
        tree->alloc <<= 1;
        tree->store = realloc(tree->store, tree->alloc * sizeof(nnode_t));
    }
    const unsigned rv = tree->count;
    dmn_assert(rv < (1U << 24));
    tree->count++;
    return rv;
}

// returns either a node offset for the true ipv4 root
//   node at exactly ::/96, or a terminal dclist
//   for a wholly enclosing supernet.  This is cached
//   for the tree to make various ipv4-related lookups
//   faster and simpler.
F_NONNULL
static unsigned ntree_find_v4root(const ntree_t* tree) {
    dmn_assert(tree);

    unsigned offset = 0;
    unsigned mask_depth = 96;
    do {
        dmn_assert(offset < tree->count);
        offset = tree->store[offset].zero;
    } while(--mask_depth && !NN_IS_DCLIST(offset));

    return offset;
}

void ntree_finish(ntree_t* tree) {
    dmn_assert(tree);
    tree->alloc = 0; // flag fixed, will fail asserts on add_node, etc now
    tree->store = realloc(tree->store, tree->count * sizeof(nnode_t));
    tree->ipv4 = ntree_find_v4root(tree);
}

#ifndef NDEBUG // debug dump code

F_NONNULL
static void ntree_dump_recurse(const ntree_t* tree, const unsigned bitdepth, const unsigned offset, struct in6_addr ipv6);

F_NONNULL
static void ntree_dump_rec_sub(const ntree_t* tree, const unsigned bitdepth, const unsigned val, struct in6_addr ipv6) {
    dmn_assert(tree);
    if(NN_IS_DCLIST(val)) {
        anysin_t tempsin;
        memset(&tempsin, 0, sizeof(tempsin));
        tempsin.len = sizeof(struct sockaddr_in6);
        tempsin.sa.sa_family = AF_INET6;
        memcpy(&tempsin.sin6.sin6_addr, &ipv6, sizeof(struct in6_addr));
        log_debug("%s/%u -> %u", logf_anysin_noport(&tempsin), 128U - bitdepth, NN_GET_DCLIST(val));
    }
    else {
        dmn_assert(bitdepth);
        ntree_dump_recurse(tree, bitdepth - 1, val, ipv6);
    }
}

static void ntree_dump_recurse(const ntree_t* tree, const unsigned bitdepth, const unsigned offset, struct in6_addr ipv6) {
    dmn_assert(tree);
    const nnode_t* this_node = &tree->store[offset];
    ntree_dump_rec_sub(tree, bitdepth, this_node->zero, ipv6);
    SETBIT_v6(ipv6.s6_addr, 127 - bitdepth);
    ntree_dump_rec_sub(tree, bitdepth, this_node->one, ipv6);
}

void ntree_debug_dump(const ntree_t* tree) {
    dmn_assert(tree);
    ntree_dump_recurse(tree, 127, 0, ip6_zero);
}

// an ntree is optimal if it never has a terminal dclist value
//   that's identical in the zero+one slots of a single node (which
//   should have been merged up a layer to be optimal).  Note that
//   we don't ever alias ntree subtrees...
void ntree_assert_optimal(const ntree_t* tree) {
    dmn_assert(tree);

    // note that for tree->count == 1 and the whole space
    //   mapped to a single dclist, we can't optimize that to
    //   a full /0 mask, it has to be a pair of /1 results,
    //   so we don't check that case.
    if(tree->count > 1) {
        for(unsigned offs = 0; offs < tree->count; offs++) {
            const nnode_t* current = &tree->store[offs];
            dmn_assert(current->zero != current->one);
        }
    }
}
#else
#define ntree_debug_dump(x)
#define ntree_assert_optimal(x)
#endif

F_NONNULL
static inline bool CHKBIT_v6(const uint8_t* ipv6, const unsigned bit) {
    dmn_assert(ipv6);
    dmn_assert(bit < 128);
    return ipv6[bit >> 3] & (1UL << (~bit & 7));
}

F_NONNULL
static unsigned ntree_lookup_v6(const ntree_t* tree, const uint8_t* ip, unsigned* mask_out) {
    dmn_assert(tree); dmn_assert(ip); dmn_assert(mask_out);

    unsigned chkbit = 0;
    unsigned offset = 0;
    do {
        dmn_assert(offset < tree->count);
        const nnode_t* current = &tree->store[offset];
        dmn_assert(current->one && current->zero);
        offset = CHKBIT_v6(ip, chkbit++) ? current->one : current->zero;
        dmn_assert(chkbit < 129);
    } while(!NN_IS_DCLIST(offset));

    *mask_out = chkbit;
    dmn_assert(offset != NN_UNDEF); // the special v4-like undefined areas
    return NN_GET_DCLIST(offset);
}

static inline bool CHKBIT_v4(const uint32_t ip, const unsigned maskbit) {
    dmn_assert(maskbit < 32U);
    return ip & (1U << (31U - maskbit));
}

// lookup_v4's "mask_out" is within the range /0 -> /32 and needs adjusting
//   for the various v4-like v6 spaces.  As a result we never return a supernet
//   mask for these (e.g. /41 for a lookup on v4compat space, or /2 for a lookup
//   on teredo, etc...), even if that would technically be more optimal.  It's far
//   more confusing and not worth optimizing for.
F_NONNULL
static unsigned ntree_lookup_v4(const ntree_t* tree, const uint32_t ip, unsigned* mask_out) {
    dmn_assert(tree); dmn_assert(mask_out);
    dmn_assert(tree->ipv4);

    unsigned chkbit = 0;
    unsigned offset = tree->ipv4;
    while(!NN_IS_DCLIST(offset)) {
        dmn_assert(offset < tree->count);
        const nnode_t* current = &tree->store[offset];
        dmn_assert(current->one && current->zero);
        offset = CHKBIT_v4(ip, chkbit++) ? current->one : current->zero;
        dmn_assert(chkbit < 33);
    }

    *mask_out = chkbit;
    dmn_assert(offset != NN_UNDEF); // the special v4-like undefined areas
    return NN_GET_DCLIST(offset);
}

// if "addr" is in any v4-compatible spaces other than
//   v4compat (our canonical one), convert to v4compat,
//   and return a mask_adj to v4_compat.
// else, leave addr as-is and return 0.
F_NONNULL
static uint32_t v6_v4fixup(const uint8_t* in, unsigned* mask_adj) {
    dmn_assert(in); dmn_assert(mask_adj);

    uint32_t ip_out = 0;

    if(!memcmp(in, start_v4mapped, 12)
        || !memcmp(in, start_siit, 12)) {
        ip_out = ntohl(gdnsd_get_una32(&in[12]));
        *mask_adj = 96;
    }
    else if(!memcmp(in, start_teredo, 4)) {
        ip_out = ntohl(gdnsd_get_una32(&in[12]) ^ 0xFFFFFFFF);
        *mask_adj = 96;
    }
    else if(!memcmp(in, start_6to4, 2)) {
        ip_out = ntohl(gdnsd_get_una32(&in[2]));
        *mask_adj = 16;
    }

    return ip_out;
}

F_NONNULL
static unsigned ntree_lookup_inner(const ntree_t* tree, const anysin_t* client_addr, unsigned* scope_mask) {
    dmn_assert(tree); dmn_assert(client_addr); dmn_assert(scope_mask);

    unsigned rv;

    if(client_addr->sa.sa_family == AF_INET) {
        rv = ntree_lookup_v4(tree, ntohl(client_addr->sin.sin_addr.s_addr), scope_mask);
    }
    else {
        dmn_assert(client_addr->sa.sa_family == AF_INET6);
        unsigned mask_adj = 0; // for v4-like conversions...
        const uint32_t ipv4 = v6_v4fixup(client_addr->sin6.sin6_addr.s6_addr, &mask_adj);
        if(mask_adj) {
            unsigned temp_mask;
            rv = ntree_lookup_v4(tree, ipv4, &temp_mask);
            *scope_mask = temp_mask + mask_adj;
        }
        else {
            rv = ntree_lookup_v6(tree, client_addr->sin6.sin6_addr.s6_addr, scope_mask);
        }
    }

    return rv;
}

unsigned ntree_lookup(const ntree_t* tree, const client_info_t* client, unsigned* scope_mask) {
    dmn_assert(tree); dmn_assert(client); dmn_assert(scope_mask);
    dmn_assert(!tree->alloc); // ntree_finish() was called
    dmn_assert(tree->ipv4); // must be a non-zero node offset or a dclist w/ high-bit set

    unsigned rv;

    if(client->edns_client_mask)
        rv = ntree_lookup_inner(tree, &client->edns_client, scope_mask);
    else
        rv = ntree_lookup_inner(tree, &client->dns_source, scope_mask);

    return rv;
}
