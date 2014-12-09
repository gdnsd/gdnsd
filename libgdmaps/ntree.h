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

#ifndef NTREE_H
#define NTREE_H

#include <gdnsd/compiler.h>
#include <gdnsd/plugapi.h>

#include <inttypes.h>

/***************************************
 * ntree_t and related methods
 **************************************/

// ipv6 is a uint8_t[16]
// bit is 0->127 (MSB -> LSB)
F_NONNULL F_UNUSED
static void SETBIT_v6(uint8_t* ipv6, const unsigned bit) {
    dmn_assert(ipv6);
    dmn_assert(bit < 128);
    ipv6[bit >> 3] |= (1UL << (~bit & 7));
}

// Some constant IPv6 address fragments...

// 96-bit prefix
static const uint8_t start_v4compat[16] =
    { 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00 };

// 96-bit prefix
static const uint8_t start_v4mapped[16] =
    { 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0xFF, 0xFF,
      0x00, 0x00, 0x00, 0x00 };

// 96-bit prefix
static const uint8_t start_siit[16] =
    { 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0xFF, 0xFF, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00 };

// 96-bit prefix
static const uint8_t start_wkp[16] =
    { 0x00, 0x64, 0xFF, 0x9B,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00 };

// 16-bit prefix
static const uint8_t start_6to4[16] =
    { 0x20, 0x02, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00 };

// 32-bit prefix
static const uint8_t start_teredo[16] =
    { 0x20, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00 };

// zero-initializer for IPv6
static const struct in6_addr ip6_zero = { .s6_addr = { 0 } };

/*
 * This is our network/mask database.  It becomes fully populated, in that
 * a lookup of any address *will* find a node.  This is because the original
 * GeoIP database is also fully populated.  It maps network/mask -> dclist,
 * and is constructed by walking the entire input GeoIP database and remapping
 * it against this maps's vscf config.
 */

/*
 * the legal range of a dclist or a node index is 0 -> INT32_MAX,
 *   and we store it as a uint32_t using the high bit to signal which
 * For each of the branch fields zero and one:
 *   if the MSB is set, the rest of the uint32_t is a dclist
 *     index (terminal).  If the remainder is INT32_MAX (meaning
 *     the whole is UINT32_MAX), it is the special value NN_UNDEF.
 *   if the MSB is not set, the rest of the uint32_t is
 *     a node index for recursion.
 */

#define NN_UNDEF UINT32_MAX // special undefined dclist, never
                            //   the result of a lookup, used to
                            //   to get netmasks correct adjacent
                            //   to undefined v4-like spaces...
#define NN_IS_DCLIST(x) ((x) & (1U << 31U))
#define NN_GET_DCLIST(x) ((x) & ~(1U << 31U)) // strips high bit
#define NN_SET_DCLIST(x) ((x) | (1U << 31U)) // sets high bit

typedef struct {
    uint32_t zero;
    uint32_t one;
} nnode_t;

typedef struct {
    nnode_t* store;
    unsigned ipv4;  // cached ipv4 lookup hint
    unsigned count; // raw nodes, including interior ones
    unsigned alloc; // current allocation of store during construction,
                    //   set to zero after _finish()
} ntree_t;

ntree_t* ntree_new(void);

F_NONNULL
void ntree_destroy(ntree_t* tree);

// keeps ->count up-to-date and resizes storage
//   as necc by doubling.
F_NONNULL
unsigned ntree_add_node(ntree_t* tree);

// call this after done adding data
F_NONNULL
void ntree_finish(ntree_t* tree);

#ifndef NDEBUG
F_NONNULL
void ntree_debug_dump(const ntree_t* tree);
F_NONNULL
void ntree_assert_optimal(const ntree_t* tree);
#else
#define ntree_debug_dump(x)
#define ntree_assert_optimal(x)
#endif

F_NONNULL
unsigned ntree_lookup(const ntree_t* tree, const client_info_t* client, unsigned* scope_mask);

#endif // NTREE_H
