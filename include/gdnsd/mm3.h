/*
 * MurmurHash3 was written by Austin Appleby, and is placed in the public
 * domain. The author hereby disclaims copyright to this source code.
 * --
 * This is a lightly-modified set of MurmurHash3 implementations.  The
 * algorithms are the same, but things about code style, interfaces,
 * bit-widths, portability, etc have been modified to suit our needs.
 *
 * The interfaces are always:
 * size_t hash_mm3_sz(const uint8_t* data, const size_t len);
 * uint32_t hash_mm3_u32(const uint8_t* data, const size_t len);
 *
 * The autoconf-provided SIZEOF_SIZE_T determines whether we're doing 64-bit
 * mode or 32-bit mode.
 *
 * In 32-bit mode (with a 32-bit size_t), it's MurmurHash3_x86_32, which uses
 * 32-bit math and returns a 32-bit hash value, and both interface functions
 * are identical.
 *
 * In 64-bit mode (with a 64-bit size_t), it's MurmurHash3_x64_128, which uses
 * 64-bit math, and returns a 64 bit hash value (just the h2 part of the
 * original 128-bit output).  The u32 variant just truncates the 64-bit output.
 */

#ifndef GDNSD_MM3_H
#define GDNSD_MM3_H

#include <gdnsd/compiler.h>

#include <stddef.h>
#include <inttypes.h>

#if SIZEOF_SIZE_T == 8 // 64-bit vs 32-bit

static uint64_t rotl64(uint64_t x, int8_t r)
{
    return (x << r) | (x >> (64 - r));
}

static uint64_t fmix64(uint64_t k)
{
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdLLU;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53LLU;
    k ^= k >> 33;
    return k;
}

F_UNUSED F_NONNULL
static size_t hash_mm3_sz(const uint8_t* data, const size_t len)
{
    const uint64_t c1 = 0x87c37b91114253d5LLU;
    const uint64_t c2 = 0x4cf5ad432745937fLLU;
    const size_t nblocks_bytes = (len / 16U) * 16U;
    uint64_t h1 = 0;
    uint64_t h2 = 0;

    // body
    for (size_t i = 0; i < nblocks_bytes; i += 16) {
        uint64_t k1 = gdnsd_get_una64(&data[i]);
        uint64_t k2 = gdnsd_get_una64(&data[i + 8]);
        k1 *= c1;
        k1  = rotl64(k1, 31);
        k1 *= c2;
        h1 ^= k1;
        h1 = rotl64(h1, 27);
        h1 += h2;
        h1 = h1 * 5 + 0x52dce729;
        k2 *= c2;
        k2  = rotl64(k2, 33);
        k2 *= c1;
        h2 ^= k2;
        h2 = rotl64(h2, 31);
        h2 += h1;
        h2 = h2 * 5 + 0x38495ab5;
    }

    // tail
    const uint8_t* tail = &data[nblocks_bytes];
    uint64_t k1 = 0;
    uint64_t k2 = 0;
    switch (len & 15) {
    case 15:
        k2 ^= ((uint64_t)tail[14]) << 48;
        S_FALLTHROUGH; // FALLTHROUGH
    case 14:
        k2 ^= ((uint64_t)tail[13]) << 40;
        S_FALLTHROUGH; // FALLTHROUGH
    case 13:
        k2 ^= ((uint64_t)tail[12]) << 32;
        S_FALLTHROUGH; // FALLTHROUGH
    case 12:
        k2 ^= ((uint64_t)tail[11]) << 24;
        S_FALLTHROUGH; // FALLTHROUGH
    case 11:
        k2 ^= ((uint64_t)tail[10]) << 16;
        S_FALLTHROUGH; // FALLTHROUGH
    case 10:
        k2 ^= ((uint64_t)tail[9]) << 8;
        S_FALLTHROUGH; // FALLTHROUGH
    case  9:
        k2 ^= ((uint64_t)tail[8]) << 0;
        k2 *= c2;
        k2  = rotl64(k2, 33);
        k2 *= c1;
        h2 ^= k2;
        S_FALLTHROUGH; // FALLTHROUGH
    case  8:
        k1 ^= ((uint64_t)tail[7]) << 56;
        S_FALLTHROUGH; // FALLTHROUGH
    case  7:
        k1 ^= ((uint64_t)tail[6]) << 48;
        S_FALLTHROUGH; // FALLTHROUGH
    case  6:
        k1 ^= ((uint64_t)tail[5]) << 40;
        S_FALLTHROUGH; // FALLTHROUGH
    case  5:
        k1 ^= ((uint64_t)tail[4]) << 32;
        S_FALLTHROUGH; // FALLTHROUGH
    case  4:
        k1 ^= ((uint64_t)tail[3]) << 24;
        S_FALLTHROUGH; // FALLTHROUGH
    case  3:
        k1 ^= ((uint64_t)tail[2]) << 16;
        S_FALLTHROUGH; // FALLTHROUGH
    case  2:
        k1 ^= ((uint64_t)tail[1]) << 8;
        S_FALLTHROUGH; // FALLTHROUGH
    case  1:
        k1 ^= ((uint64_t)tail[0]) << 0;
        k1 *= c1;
        k1  = rotl64(k1, 31);
        k1 *= c2;
        h1 ^= k1;
        S_FALLTHROUGH; // FALLTHROUGH
    default:
        break;
    }

    // finalization
    h1 ^= len;
    h2 ^= len;
    h1 += h2;
    h2 += h1;
    h1 = fmix64(h1);
    h2 = fmix64(h2);
    h1 += h2;
    h2 += h1;
    return h2;
}

// For some other use cases, this is still better than our old lookup2 32-bit
// hash (about the same speed, but better hash quality).  The simple wrapper
// here is just to avoid casting in the consumers and be explicit about it.
F_UNUSED F_NONNULL
static uint32_t hash_mm3_u32(const uint8_t* data, const size_t len)
{
    return (uint32_t)(hash_mm3_sz(data, len));
}

#else // 64-bit vs 32-bit

static uint32_t rotl32(uint32_t x, int8_t r)
{
    return (x << r) | (x >> (32 - r));
}

static uint32_t fmix32(uint32_t h)
{
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

F_UNUSED F_NONNULL
static size_t hash_mm3_sz(const uint8_t* data, const size_t len)
{
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;
    const size_t nblocks_bytes = (len / 4U) * 4U;
    uint32_t h1 = 0;

    // body
    for (size_t i = 0; i < nblocks_bytes; i += 4U) {
        uint32_t k1 = gdnsd_get_una32(&data[i]);
        k1 *= c1;
        k1 = rotl32(k1, 15);
        k1 *= c2;
        h1 ^= k1;
        h1 = rotl32(h1, 13);
        h1 = h1 * 5 + 0xe6546b64;
    }

    // tail
    const uint8_t* tail = &data[nblocks_bytes];
    uint32_t k1 = 0;
    switch (len & 3) {
    case 3:
        k1 ^= tail[2] << 16;
        S_FALLTHROUGH; // FALLTHROUGH
    case 2:
        k1 ^= tail[1] << 8;
        S_FALLTHROUGH; // FALLTHROUGH
    case 1:
        k1 ^= tail[0];
        k1 *= c1;
        k1 = rotl32(k1, 15);
        k1 *= c2;
        h1 ^= k1;
        S_FALLTHROUGH; // FALLTHROUGH
    default:
        break;
    }

    // finalization
    h1 ^= len;
    h1 = fmix32(h1);
    return h1;
}

// In the 32-bit case, the functions are identical
#define hash_mm3_u32 hash_mm3_sz

#endif // 64-bit vs 32-bit
#endif // GDNSD_MM3_H
