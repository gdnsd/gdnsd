#ifndef GDNSD_KDF_COMPAT_H
#define GDNSD_KDF_COMPAT_H

#include <inttypes.h>
#include <stddef.h>

#define gdnsd_crypto_kdf_blake2b_CONTEXTBYTES 8
#define gdnsd_crypto_kdf_blake2b_KEYBYTES 32
#define gdnsd_crypto_kdf_blake2b_BYTES_MIN 16
#define gdnsd_crypto_kdf_blake2b_BYTES_MAX 64

int gdnsd_crypto_kdf_blake2b_derive_from_key(unsigned char* subkey, size_t subkey_len,
        uint64_t subkey_id,
        const char ctx[gdnsd_crypto_kdf_blake2b_CONTEXTBYTES],
        const unsigned char key[gdnsd_crypto_kdf_blake2b_KEYBYTES]);

#endif // GDNSD_KDF_COMPAT_H
