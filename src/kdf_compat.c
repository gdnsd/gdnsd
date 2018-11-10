/*
 * ISC License
 *
 * Copyright (c) 2013-2018
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/****************************************************************************
 ** Code here is derived/copied directly from libsodium, hence the         **
 ** alternate copyright/license block above!                               **
 **   All of the crypto_kdf interfaces, including the blake2b-specific one **
 ** we use in cookie.c, did not exist until libsodium 1.0.12, and multiple **
 ** current OS distributions we'd like to easily compile/deploy on haven't **
 ** shipped such a version yet.                                            **
 **   Therefore, we've copied the blake2b kdf interface function here, as  **
 ** it's just a wrapper over crypto_generichash_blake2b_salt_personal(),   **
 ** which does exist all the way back to libsodium 1.0.0.                  **
 **   It must exactly mirror the real upstream in all functional details,  **
 ** so that future versions of gdnsd compiled without this hack match and  **
 ** validate the final server cookie outputs of those concurrently running **
 ** on this code as part of the same anycast/loadbalance cluster.          **
 **   At some future date when we can reasonably require libsodium 1.0.12+ **
 ** this compatibility hack/wrapper will be deleted from gdnsd's source.   **
 ****************************************************************************/

#include <config.h>

#include "kdf_compat.h"

#include <inttypes.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>

#include <sodium.h>

int gdnsd_crypto_kdf_blake2b_derive_from_key(unsigned char* subkey, size_t subkey_len,
        uint64_t subkey_id,
        const char ctx[gdnsd_crypto_kdf_blake2b_CONTEXTBYTES],
        const unsigned char key[gdnsd_crypto_kdf_blake2b_KEYBYTES])
{
    unsigned char ctx_padded[crypto_generichash_blake2b_PERSONALBYTES];
    unsigned char salt[crypto_generichash_blake2b_SALTBYTES];

    memcpy(ctx_padded, ctx, gdnsd_crypto_kdf_blake2b_CONTEXTBYTES);
    memset(ctx_padded + gdnsd_crypto_kdf_blake2b_CONTEXTBYTES, 0, sizeof ctx_padded - gdnsd_crypto_kdf_blake2b_CONTEXTBYTES);

    // was STORE64_LE in libsodium, expanded to generic form here without little-endian perf hacks
    salt[0] = (uint8_t) subkey_id;
    subkey_id >>= 8;
    salt[1] = (uint8_t) subkey_id;
    subkey_id >>= 8;
    salt[2] = (uint8_t) subkey_id;
    subkey_id >>= 8;
    salt[3] = (uint8_t) subkey_id;
    subkey_id >>= 8;
    salt[4] = (uint8_t) subkey_id;
    subkey_id >>= 8;
    salt[5] = (uint8_t) subkey_id;
    subkey_id >>= 8;
    salt[6] = (uint8_t) subkey_id;
    subkey_id >>= 8;
    salt[7] = (uint8_t) subkey_id;

    memset(salt + 8, 0, (sizeof salt) - 8);
    if (subkey_len < gdnsd_crypto_kdf_blake2b_BYTES_MIN ||
            subkey_len > gdnsd_crypto_kdf_blake2b_BYTES_MAX) {
        errno = EINVAL;
        return -1;
    }

    return crypto_generichash_blake2b_salt_personal(subkey, subkey_len,
            NULL, 0,
            key, gdnsd_crypto_kdf_blake2b_KEYBYTES,
            salt, ctx_padded);
}
