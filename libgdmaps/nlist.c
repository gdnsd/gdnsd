/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
 *
 * This file is part of gdnsd.
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

#include <config.h>
#include "nlist.h"

#include "dclists.h"

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/misc.h>

#include <string.h>
#include <stdlib.h>

#define NLIST_INITSIZE 64

struct nlist* nlist_new(const char* map_name, const bool pre_norm)
{
    struct nlist* nl = xmalloc(sizeof(*nl));
    nl->nets = xmalloc_n(NLIST_INITSIZE, sizeof(*nl->nets));
    nl->map_name = xstrdup(map_name);
    nl->alloc = NLIST_INITSIZE;
    nl->count = 0;
    nl->normalized = pre_norm;
    return nl;
}

// only used for normalization assertions in debug builds...
F_UNUSED F_NONNULL
static struct nlist* nlist_clone(const struct nlist* nl)
{
    struct nlist* nlc = xmalloc(sizeof(*nlc));
    nlc->map_name = xstrdup(nl->map_name);
    nlc->alloc = nl->alloc;
    nlc->count = nl->count;
    nlc->normalized = nl->normalized;
    nlc->nets = xmalloc_n(nlc->alloc, sizeof(*nlc->nets));
    memcpy(nlc->nets, nl->nets, sizeof(*nlc->nets) * nlc->count);
    return nlc;
}

void nlist_debug_dump(const struct nlist* nl)
{
    log_debug(" --- nlist debug on %s --- ", nl->map_name);
    for (unsigned i = 0; i < nl->count; i++)
        log_debug("   %s/%u -> %u", logf_ipv6(nl->nets[i].ipv6), nl->nets[i].mask, nl->nets[i].dclist);
}

void nlist_destroy(struct nlist* nl)
{
    free(nl->map_name);
    free(nl->nets);
    free(nl);
}

#ifndef NDEBUG
F_NONNULL
static void assert_clear_mask_bits(const uint8_t* ipv6, const unsigned mask)
{
    gdnsd_assume(mask < 129);

    if (likely(mask)) {
        const unsigned revmask = 128 - mask;
        const unsigned byte_mask = ~(0xFFU << (revmask & 7)) & 0xFF;
        unsigned bbyte = 15 - (revmask >> 3);

        gdnsd_assume(!(ipv6[bbyte] & byte_mask));
        while (++bbyte < 16)
            gdnsd_assume(!ipv6[bbyte]);
    } else {
        gdnsd_assume(!memcmp(ipv6, &ip6_zero.s6_addr, 16));
    }
}
#else
#define assert_clear_mask_bits(x, y)
#endif

F_NONNULL
static void clear_mask_bits(const char* map_name, uint8_t* ipv6, const unsigned mask)
{
    gdnsd_assume(mask < 129);

    bool maskbad = false;

    if (likely(mask)) {
        const unsigned revmask = 128 - mask;
        const unsigned byte_mask = ~(0xFFU << (revmask & 7)) & 0xFF;
        unsigned bbyte = 15 - (revmask >> 3);

        if (ipv6[bbyte] & byte_mask) {
            maskbad = true;
            ipv6[bbyte] &= ~byte_mask;
        }

        while (++bbyte < 16) {
            if (ipv6[bbyte]) {
                maskbad = true;
                ipv6[bbyte] = 0;
            }
        }
    } else if (memcmp(ipv6, &ip6_zero.s6_addr, 16)) {
        maskbad = true;
        memset(ipv6, 0, 16);
    }

    if (maskbad)
        log_warn("plugin_geoip: map '%s': input network %s/%u had illegal bits beyond mask, which were cleared", map_name, logf_ipv6(ipv6), mask);
}

// Sort an array of struct net.  Sort prefers
//   lowest network number, smallest mask.
F_NONNULL F_PURE
static int net_sorter(const void* a_void, const void* b_void)
{
    const struct net* a = a_void;
    const struct net* b = b_void;
    // nets.c:nets_parse() constrains input masks to 128, but the process of
    // deleting networks via merging can also set the magic value 0xFF.
    gdnsd_assume(a->mask <= 0xFF);
    gdnsd_assume(b->mask <= 0xFF);
    const int mcrv = memcmp(a->ipv6, b->ipv6, 16);
    if (mcrv)
	return mcrv;
    const int am = (int)a->mask;
    const int bm = (int)b->mask;
    return (am > bm) - (am < bm);
}

F_NONNULL F_PURE
static bool masked_net_eq(const uint8_t* v6a, const uint8_t* v6b, const unsigned mask)
{
    gdnsd_assume(mask < 128U); // 2x128 would call here w/ 127...

    const unsigned bytes = mask >> 3;
    gdnsd_assume(bytes < 16U);

    const unsigned bytemask = (0xFF00U >> (mask & 7)) & 0xFF;
    return !memcmp(v6a, v6b, bytes)
           && (v6a[bytes] & bytemask) == (v6b[bytes] & bytemask);
}

F_NONNULL F_PURE
static bool mergeable_nets(const struct net* na, const struct net* nb)
{
    bool rv = false;
    if (na->dclist == nb->dclist) {
        if (na->mask == nb->mask)
            rv = masked_net_eq(na->ipv6, nb->ipv6, na->mask - 1);
        else if (na->mask < nb->mask)
            rv = masked_net_eq(na->ipv6, nb->ipv6, na->mask);
    }
    return rv;
}

void nlist_append(struct nlist* nl, const uint8_t* ipv6, const unsigned mask, const unsigned dclist)
{
    if (unlikely(nl->count == nl->alloc)) {
        nl->alloc <<= 1U;
        nl->nets = xrealloc_n(nl->nets, nl->alloc, sizeof(*nl->nets));
    }
    struct net* this_net = &nl->nets[nl->count++];
    memcpy(this_net->ipv6, ipv6, 16U);
    this_net->mask = mask;
    this_net->dclist = dclist;

    // In the pre-norm case, we can keep the list in fully-normalized
    //   form as we go by doing this merge op after each append and
    //   keeping the list minimized.  What we're catching here is adjacent
    //   networks which share a dclist and mask and are thus mergeable,
    //   and we do so by deleting the most-recently added one and decrementing
    //   the subnet mask of the older one.
    // Because this is happening back-to-front after each append, there's
    //   no need to create (or later deal with) holes in the array.
    if (nl->normalized) {
        assert_clear_mask_bits(this_net->ipv6, mask);
        unsigned idx = nl->count;
        while (--idx > 0) {
            const struct net* nb = &nl->nets[idx];
            struct net* na = &nl->nets[idx - 1];
            if (mergeable_nets(na, nb)) {
                if (na->mask == nb->mask)
                    na->mask--;
                nl->count--;
            } else {
                break;
            }
        }
    } else {
        // for raw input, just correct any netmask errors as we insert,
        //   as these will screw up later sorting for normalization
        clear_mask_bits(nl->map_name, this_net->ipv6, mask);
    }
}

F_NONNULL F_PURE
static bool net_eq(const struct net* na, const struct net* nb)
{
    return na->mask == nb->mask && !memcmp(na->ipv6, nb->ipv6, 16);
}

// do a single pass of forward-normalization
//   on a sorted nlist, then sort the result.
F_NONNULL
static bool nlist_normalize_1pass(struct nlist* nl)
{
    gdnsd_assume(nl->count);

    bool rv = false;

    const unsigned oldcount = nl->count;
    unsigned newcount = nl->count;
    unsigned i = 0;
    while (i < oldcount) {
        struct net* na = &nl->nets[i];
        unsigned j = i + 1;
        while (j < oldcount) {
            struct net* nb = &nl->nets[j];
            if (net_eq(na, nb)) { // net+mask match, dclist may or may not match
                if (na->dclist != nb->dclist)
                    log_warn("plugin_geoip: map '%s' nets: Exact duplicate networks with conflicting dclists at %s/%u", nl->map_name, logf_ipv6(na->ipv6), na->mask);
            } else if (mergeable_nets(na, nb)) { // dclists match, nets adjacent (masks equal) or subnet-of
                if (na->mask == nb->mask)
                    na->mask--;
            } else {
                break;
            }
            nb->mask = 0xFF; // illegally-huge, to sort deletes later
            memset(nb->ipv6, 0xFF, 16); // all-1's, also for sort...
            newcount--;
            j++;
        }
        i = j;
    }

    if (newcount != oldcount) { // merges happened above
        // the "deleted" entries have all-1's IPs and >legal masks, so they
        //   sort to the end...
        qsort(nl->nets, oldcount, sizeof(*nl->nets), net_sorter);

        // reset the count to ignore the deleted entries at the end
        nl->count = newcount;

        // signal need for another pass
        rv = true;
    }

    return rv;
}

F_NONNULL
static void nlist_normalize(struct nlist* nl, const bool post_merge)
{
    if (nl->count) {
        // initial sort, unless already sorted by the merge process
        if (!post_merge)
            qsort(nl->nets, nl->count, sizeof(*nl->nets), net_sorter);

        // iterate merge+sort passes until no further merges are found
        while (nlist_normalize_1pass(nl))
            ; // empty

        // optimize storage space
        if (nl->count != nl->alloc) {
            gdnsd_assume(nl->count < nl->alloc);
            nl->alloc = nl->count;
            nl->nets = xrealloc_n(nl->nets, nl->alloc, sizeof(*nl->nets));
        }
    }

    nl->normalized = true;
}

F_NONNULL
void nlist_finish(struct nlist* nl)
{
    if (nl->normalized) {
#ifndef NDEBUG
        // assert normalization in debug builds via clone->normalize->compare
        struct nlist* nlc = nlist_clone(nl);
        nlist_normalize(nlc, false);
        gdnsd_assume(nlc->count == nl->count);
        gdnsd_assume(!memcmp(nlc->nets, nl->nets, sizeof(*nlc->nets) * nlc->count));
        nlist_destroy(nlc);
#endif
    } else {
        nlist_normalize(nl, false);
    }
}

F_NONNULL F_PURE
static bool net_subnet_of(const struct net* sub, const struct net* super)
{
    gdnsd_assume(sub->mask < 129);
    gdnsd_assume(super->mask < 129);

    bool rv = false;
    if (sub->mask >= super->mask) {
        const unsigned wbyte = (super->mask >> 3);
        const unsigned byte_mask = (0xFFU << (8U - (super->mask & 7))) & 0xFF;
        if (!memcmp(sub->ipv6, super->ipv6, wbyte)
                && (wbyte == 16 || (super->ipv6[wbyte] & byte_mask) == (sub->ipv6[wbyte] & byte_mask)))
            rv = true;
    }

    return rv;
}

F_NONNULL F_RETNN
static struct nlist* nlist_merge(const struct nlist* nl_a, const struct nlist* nl_b)
{
    gdnsd_assume(nl_a->normalized);
    gdnsd_assume(nl_b->normalized);

    struct nlist* merged = nlist_new(nl_a->map_name, false);

    const struct net* n_a = &nl_a->nets[0];
    const struct net* n_b = &nl_b->nets[0];
    const struct net* end_a = &nl_a->nets[nl_a->count];
    const struct net* end_b = &nl_b->nets[nl_b->count];

    while (n_a < end_a && n_b < end_b) {
        if (net_sorter(n_a, n_b) < 0) {
            // n_a < n_b
            //   therefore n_a is a supernet of the next n_b,
            //   or an unrelated predecessor, copy it...
            nlist_append(merged, n_a->ipv6, n_a->mask, n_a->dclist);
            n_a++;
        } else { // n_a >= n_b
            nlist_append(merged, n_b->ipv6, n_b->mask, n_b->dclist);
            // this is where we skip networks from the first list
            //   that are effectively masked out by entries in the second
            while (n_a < end_a && net_subnet_of(n_a, n_b))
                n_a++;
            n_b++;
        }
    }

    // Usually only one of the lists will have remaining entries,
    //   which should be copyable.  Rarely, both will already be finished.
    while (n_b < end_b) {
        nlist_append(merged, n_b->ipv6, n_b->mask, n_b->dclist);
        n_b++;
    }
    while (n_a < end_a) {
        nlist_append(merged, n_a->ipv6, n_a->mask, n_a->dclist);
        n_a++;
    }

    nlist_normalize(merged, true);
    return merged;
}

F_NONNULL
static unsigned nxt_rec(const struct net** nl, const struct net* const nl_end, struct ntree* nt, struct net tree_net);

F_NONNULL
static void nxt_rec_dir(const struct net** nlp, const struct net* const nl_end, struct ntree* nt, struct net tree_net, const unsigned nt_idx, const bool direction)
{
    gdnsd_assume(tree_net.mask < 129 && tree_net.mask > 0);

    const struct net* nl = *nlp;
    unsigned cnode;

    // If items remain in the list, and the next list item
    //   is a subnet of (including exact match for) the current
    //   ntree node...
    if (nl < nl_end && net_subnet_of(nl, &tree_net)) {
        // exact match, consume...
        if (tree_net.mask == nl->mask) {
            (*nlp)++; // consume *nlp and move to next
            // need to pre-check for a deeper subnet next in the list.
            // We use the consumed entry as the new default and keep recursing
            //   if deeper subnets exist.  If they don't, we assign and end recursion...
            const struct net* nl_next = *nlp;
            if (nl_next < nl_end && net_subnet_of(nl_next, nl)) {
                tree_net.dclist = nl->dclist;
                cnode = nxt_rec(nlp, nl_end, nt, tree_net);
            } else {
                cnode = NN_SET_DCLIST(nl->dclist);
            }
        } else {
            // Not an exact match, so just keep recursing towards such a match...
            cnode = nxt_rec(nlp, nl_end, nt, tree_net);
        }
    } else {
        // list item isn't a subnet of the current tree node, and due to our
        //   normalization that means there are no such list items remaining,
        //   so terminate the recursion with the current default dclist.
        cnode = NN_SET_DCLIST(tree_net.dclist);
    }

    // store direct or recursed result.  Note we have to wait until
    //   here to deref nt->store[nt_idx] because recursion could
    //   re-allocate nt->store[] during nxt_rec()'s ntree_add_node() call.
    if (direction)
        nt->store[nt_idx].one = cnode;
    else
        nt->store[nt_idx].zero = cnode;
}

F_NONNULL
static unsigned nxt_rec(const struct net** nl, const struct net* const nl_end, struct ntree* nt, struct net tree_net)
{
    gdnsd_assume(tree_net.mask < 128);
    tree_net.mask++; // now mask for zero/one stubs

    const unsigned nt_idx = ntree_add_node(nt);
    nxt_rec_dir(nl, nl_end, nt, tree_net, nt_idx, false);
    SETBIT_v6(tree_net.ipv6, tree_net.mask - 1);
    nxt_rec_dir(nl, nl_end, nt, tree_net, nt_idx, true);

    unsigned rv = nt_idx;

    // catch missed optimizations during final translation
    if (unlikely(nt->store[nt_idx].zero == nt->store[nt_idx].one) && likely(nt_idx > 0)) {
        nt->count--; // delete the just-added node
        rv = nt->store[nt_idx].zero;
    }

    return rv;
}

struct ntree* nlist_xlate_tree(const struct nlist* nl)
{
    gdnsd_assume(nl->normalized);

    struct ntree* nt = ntree_new();
    const struct net* nlnet = &nl->nets[0];
    const struct net* const nlnet_end = &nl->nets[nl->count];
    struct net tree_net = {
        .ipv6 = { 0 },
        .mask = 0,
        .dclist = 0
    };

    // Special-case: if a list entry for ::/0 exists, it will
    //   be first in the list, and it needs to be skipped
    //   over (with its dclist as the new default) before
    //   recursing (because ::/0 is the first node of the
    //   tree itself).
    if (nl->count && !nl->nets[0].mask) {
        tree_net.dclist = nl->nets[0].dclist;
        nlnet++;
    }

    // recursively build the tree from the list
    nxt_rec(&nlnet, nlnet_end, nt, tree_net);

    // assert that the whole list was consumed
    gdnsd_assume(nlnet == nlnet_end);

    // finalize the tree
    ntree_finish(nt);

    // make sure all our logic worked out sanely
    ntree_assert_optimal(nt);

    return nt;
}

struct ntree* nlist_merge2_tree(const struct nlist* nl_a, const struct nlist* nl_b)
{
    struct nlist* merged = nlist_merge(nl_a, nl_b);
    struct ntree* rv = nlist_xlate_tree(merged);
    nlist_destroy(merged);
    return rv;
}
