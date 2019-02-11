/* Copyright © 2018 Brandon L Black <blblack@gmail.com>
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

/*************************************************
 * EDNS Cookies implementation/design notes:
 * * Master Key:
 *   By default, we use a random master key generated at first startup, which
 *   affords no cross-server sync.  The daemon attempts to persist this to the
 *   rundir and read it back on replace/restart to minimize cookie disruption,
 *   but key i/o to the rundir fails non-fatally with a logged error, in which
 *   case a new key is being generated on every daemon start.  Commonly on
 *   Linux/systemd, the rundir is empty after a reboot, which will cause a new
 *   key to be generated once per server reboot.  Master key changes cause a
 *   less-desirable (but probably commonly ok) abrupt rift in client cookie
 *   validities.  For cross-server sync (and avoiding said rifts even for
 *   singular servers on reboots), the admin can define a keyfile containing a
 *   pre-defined master key, which must contain at least 32 bytes of data,
 *   which should be securely-generated random data.  The keyfile can be
 *   updated with a new key from time to time, but this can happen on slow
 *   timescales (e.g. once a year or whatever makes sense for generic secret
 *   key management).
 *
 * * The Time Counter
 *   Standard unix UTC time is divided into 1 hour chunks as a counter that
 *   increments approximately once per unix hour (when the raw time value
 *   modulo 3600 is zero), giving us a simple counter that's synchronized by
 *   the servers' NTP, and steps forward at roughly the same time on all
 *   servers once an hour (+/- a bit of skew is fine).
 *
 * * Runtime Server Secrets used for Server Cookie output:
 *   The runtime secret key is defined by the output of a high-quality
 *   cryptographic KDF function, using the master key as its secret key, and
 *   the unix hour counter as the subkey id.  While the unix hour is
 *   deterministic and predictable, the master key isn't, and so the anycast
 *   pool's sequence of runtime secrets isn't predictable by attackers who lack
 *   the secret master key.
 *
 * * Runtime Secret Rotation/Overlap:
 *   Roughly once per hour (keeping in mind all the blah blah about unix time
 *   and leap seconds, properly), servers update their secrets using the new
 *   unix hour counter as input.  When generating secrets, they all generate 3
 *   secrets named "previous", "current", and "next", corresponding with the
 *   secrets for the previous, current, and next unix hour counter values.
 *   Only "current" is used to generate new server cookies sent to clients, but
 *   all three of the secrets can be used to successfully validate
 *   previously-generated server cookies sent by the client.  With this scheme,
 *   so long as a cookie-enabled client checks in with the server more often
 *   than once every hour, they're guaranteed to smoothly roll over from one
 *   server cookie to the next without ever sending the server an outdated
 *   cookie it doesn't recognize.  Also, so long as NTP sync problems between
 *   servers keep them well under an hour apart in time, there will be at least
 *   some reasonable overlap in server cookie validity between the servers (the
 *   closer the time sync is, the better!), and "next" ensures there's no
 *   issues with "cookies from the future" issued by the first of a
 *   clock-skewed set of servers arriving at another that has not quite rolled
 *   over its time yet.  Assuming sync'd server clocks, the maximum possible
 *   validity window of a client's server cookie is ~2 hours, and the minimum is
 *   ~1 hour.
 *
 * * Actual Server Cookie Generation:
 *   This part happens in the runtime flow of request->response cycles, so it
 *   must be performant.  For this, we use a faster non-cryptographic keyed
 *   hash function with reasonable security properties.  The current runtime
 *   server secret is given as the key, and a concatenation of the client's IP
 *   and client cookie are used as the message to hash, resulting in an 8-byte
 *   hash output as the server cookie value, with reasonable security
 *   properties for edns cookies with ~2h maximum lifetimes.
 *
 * * BADCOOKIE and related:
 *   This server doesn't ever send a BADCOOKIE rcode.  It always includes a
 *   fresh cookie in response to any query that contained a validly-formed
 *   cookie option, whether cookie validation failed or not.  If the optional,
 *   non-default "max_nocookie_response" option is set to limit amplification,
 *   the result is that UDP answers which would've exceeded that size limit and
 *   lack a correct server cookie are answered with the TC-bit set to send the
 *   client over to TCP.  There is no RRL mechanism.
 *
 * * Crypto implementation:
 *   We chose libsodium as the crypto library.  It has nice properties for this
 *   usage, and also seems to fit the bill for other future crypto use in
 *   gdnsd.  Aside from the crypto itself, libsodium helper functions are also
 *   used for random key generation, managing secure memory allocations for key
 *   data, and for constant-time comparisons during cookie validation.
 *   I've avoided the generic algorithm-neutral APIs because we need algorithm
 *   stability across future (possibly async for an anycast server set) major
 *   version upgrades of libsodium, which could change the underlying
 *   algorithms used by those APIs.
 *   Our current algorithm choices are:
 *   blake2b KDF for master key + salted hour counter -> hourly keys
 *   siphash-2-4 for hourly key + client cookie/ip -> server cookie
 */

#include <config.h>

#include "cookie.h"
#include "main.h"

#include <gdnsd/log.h>
#include <gdnsd/paths.h>

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <sodium.h>
#include <urcu-qsbr.h>
#include <ev.h>

// Workaround to ensure we can compile/run on any libsodium-1.x, to be removed
// when we can require libsodium-1.0.12+
#include "kdf_compat.h"

// Defined by RFC
#define CCOOKIE_LEN 8

// Defined by us, RFC range is 8-32
#define SCOOKIE_LEN 8

// Room for 16 byte client IP (zero-filled for ipv4) + client cookie
#define SCOOKIE_INPUT_LEN (16 + CCOOKIE_LEN)

// shorthand for alg-specific calls/values
#define KDF_FUNC gdnsd_crypto_kdf_blake2b_derive_from_key
#define KDF_KEYBYTES gdnsd_crypto_kdf_blake2b_KEYBYTES
#define KDF_CTXBYTES gdnsd_crypto_kdf_blake2b_CONTEXTBYTES
#define SHORTHASH_FUNC crypto_shorthash_siphash24
#define SHORTHASH_BYTES crypto_shorthash_siphash24_BYTES
#define SHORTHASH_KEYBYTES crypto_shorthash_siphash24_KEYBYTES

#if __STDC_VERSION__ >= 201112L // C11
_Static_assert(SHORTHASH_BYTES == SCOOKIE_LEN, "libsodium shorthash output size == server cookie len");
#endif

typedef struct {
    uint8_t previous[SHORTHASH_KEYBYTES];
    uint8_t current[SHORTHASH_KEYBYTES];
    uint8_t next[SHORTHASH_KEYBYTES];
} timekeys_t;

// The secret master key used to derive the time-evolving keys_in_use below
static void* master_key = NULL;

// RCU-swapped for runtime use in actual cookie validation/generation
static timekeys_t* keys_inuse = NULL;

// libev periodic timer for secret rotation
static ev_periodic hourly;

// Constant non-secret context for the Cookie KDF (like an app-specific fixed salt)
static const char kdf_ctx[KDF_CTXBYTES] = {
    'g', 'd', 'n', 's', 'C', 'K', 'D', 'F'
};

// Filename in rundir for persisting an auto-generated key
static const char base_autokey[] = "cookie.autokey";

static void rotate_timekeys(void)
{
    // cookie_config() must have already happened
    gdnsd_assert(master_key);

    const uint64_t current_ctr = ((uint64_t)time(NULL)) / 3600U;
    const uint64_t previous_ctr = current_ctr - 1U;
    const uint64_t next_ctr = current_ctr + 1U;

    timekeys_t* keys_new = sodium_malloc(sizeof(*keys_new));
    if (!keys_new)
        log_fatal("sodium_malloc() failed: %s", logf_errno());

    if (sodium_mprotect_readonly(master_key))
        log_fatal("sodium_mprotect_readonly() failed: %s", logf_errno());
    KDF_FUNC(keys_new->previous, sizeof(keys_new->previous), previous_ctr, kdf_ctx, master_key);
    KDF_FUNC(keys_new->current, sizeof(keys_new->current), current_ctr, kdf_ctx, master_key);
    KDF_FUNC(keys_new->next, sizeof(keys_new->next), next_ctr, kdf_ctx, master_key);
    if (sodium_mprotect_noaccess(master_key))
        log_fatal("sodium_mprotect_noaccess() failed: %s", logf_errno());

    if (sodium_mprotect_readonly(keys_new))
        log_fatal("sodium_mprotect_readonly() failed: %s", logf_errno());

    timekeys_t* keys_old = keys_inuse;
    rcu_assign_pointer(keys_inuse, keys_new);
    synchronize_rcu();
    if (keys_old)
        sodium_free(keys_old);
}

F_NONNULL
static void hourly_callback(struct ev_loop* loop V_UNUSED, ev_periodic* w V_UNUSED, int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_PERIODIC);
    rotate_timekeys();
}

F_NONNULL
static int safe_read_keyfile(const char* key_fn, uint8_t* keybuf)
{
    const int key_fd = open(key_fn, O_CLOEXEC | O_RDONLY);
    if (key_fd < 0)
        return -1;
    const ssize_t readrv = read(key_fd, keybuf, KDF_KEYBYTES);
    const int closerv = close(key_fd);
    return (readrv == KDF_KEYBYTES) ? closerv : -1;
}

F_NONNULL
static int safe_write_keyfile(const char* key_fn, uint8_t* keybuf)
{
    const int key_fd = open(key_fn, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (key_fd < 0)
        return -1;
    const ssize_t writerv = write(key_fd, keybuf, KDF_KEYBYTES);
    const int closerv = close(key_fd);
    return (writerv == KDF_KEYBYTES) ? closerv : -1;
}

// Must happen after iothreads are done using keys and the eventloop has exited
static void cookie_destroy(void)
{
    if (keys_inuse)
        sodium_free(keys_inuse);
    if (master_key)
        sodium_free(master_key);
    keys_inuse = NULL;
    master_key = NULL;
}

/************* Public functions *************/

void cookie_config(const char* key_file)
{
    gdnsd_assert(master_key == NULL); // config only happens once!

    if (sodium_init() < 0)
        log_fatal("Could not initialize libsodium: %s", logf_errno());

    master_key = sodium_malloc(KDF_KEYBYTES);
    if (!master_key)
        log_fatal("sodium_malloc() failed: %s", logf_errno());

    if (key_file) {
        if (safe_read_keyfile(key_file, master_key))
            log_fatal("Cannot read %zu bytes from '%s': %s", (size_t)KDF_KEYBYTES, key_file, logf_errno());
    } else {
        char* autokey_path = gdnsd_resolve_path_run(base_autokey, NULL);
        if (safe_read_keyfile(autokey_path, master_key)) {
            randombytes_buf(master_key, KDF_KEYBYTES);
            if (safe_write_keyfile(autokey_path, master_key))
                log_err("Can neither correctly read nor overwrite persistent auto-generated edns cookie key file '%s'.  Delete any existing file and ensure the daemon can write to the directory!", autokey_path);
        }
        free(autokey_path);
    }

    if (sodium_mprotect_noaccess(master_key))
        log_fatal("sodium_mprotect_noaccess() failed: %s", logf_errno());

    gdnsd_atexit(cookie_destroy);
}

void cookie_runtime_init(struct ev_loop* loop)
{
    // First rotation gets done immediately so runtime has something to work
    // with until the first timer fires.
    rotate_timekeys();

    // ~2.02s after every hour mark, as reassurance against minor time issues
    // where e.g. poor system management of leap seconds might manage to trip up
    // ev_periodic somehow (which is intended to handle them properly it sounds
    // like, but I suspect there's still room for system-level administrative
    // mistakes).
    ev_periodic* hourly_p = &hourly;
    ev_periodic_init(hourly_p, hourly_callback, 2.02, 3600., NULL);
    ev_periodic_start(loop, hourly_p);
}

bool cookie_process(uint8_t* cookie_data_out, const uint8_t* cookie_data_in, const gdnsd_anysin_t* client, const size_t cookie_data_in_len)
{
    // Assert that cookie_config() and cookie_runtime_init() were called to define the keys
    gdnsd_assert(master_key);
    gdnsd_assert(keys_inuse);

    // This is required of the caller:
    gdnsd_assert(cookie_data_in_len == CCOOKIE_LEN
                 || (cookie_data_in_len >= (CCOOKIE_LEN + SCOOKIE_LEN)
                     && cookie_data_in_len <= 40U));

    // Setup server cookie input data buffer w/ client IP + client cookie
    uint8_t scookie_input[SCOOKIE_INPUT_LEN] = { 0 };
    if (client->sa.sa_family == AF_INET) {
        memcpy(scookie_input, &client->sin4.sin_addr.s_addr, 4LU);
    } else {
        gdnsd_assert(client->sa.sa_family == AF_INET6);
        memcpy(scookie_input, client->sin6.sin6_addr.s6_addr, 16LU);
    }
    memcpy(&scookie_input[16], cookie_data_in, CCOOKIE_LEN);

    bool valid = false;
    const timekeys_t* keys = rcu_dereference(keys_inuse);

    uint8_t scookie_current[SHORTHASH_BYTES];
    SHORTHASH_FUNC(scookie_current, scookie_input, SCOOKIE_INPUT_LEN, keys->current);

    if (cookie_data_in_len > CCOOKIE_LEN) {
        uint8_t scookie_previous[SHORTHASH_BYTES];
        uint8_t scookie_next[SHORTHASH_BYTES];
        SHORTHASH_FUNC(scookie_previous, scookie_input, SCOOKIE_INPUT_LEN, keys->previous);
        SHORTHASH_FUNC(scookie_next, scookie_input, SCOOKIE_INPUT_LEN, keys->next);

        const int c1 = sodium_memcmp(scookie_previous, &cookie_data_in[CCOOKIE_LEN], SCOOKIE_LEN);
        const int c2 = sodium_memcmp(scookie_current, &cookie_data_in[CCOOKIE_LEN], SCOOKIE_LEN);
        const int c3 = sodium_memcmp(scookie_next, &cookie_data_in[CCOOKIE_LEN], SCOOKIE_LEN);
        gdnsd_assert(c1 == 0 || c1 == -1); // sodium API claims this
        gdnsd_assert(c2 == 0 || c2 == -1); // sodium API claims this
        gdnsd_assert(c3 == 0 || c3 == -1); // sodium API claims this

        const int inlen_check = ((int)cookie_data_in_len) ^ (CCOOKIE_LEN + SCOOKIE_LEN);
        valid = !((c1 & c2 & c3) | inlen_check);
    }

    memcpy(cookie_data_out, cookie_data_in, CCOOKIE_LEN);
    memcpy(&cookie_data_out[CCOOKIE_LEN], scookie_current, SCOOKIE_LEN);

    return valid;
}
