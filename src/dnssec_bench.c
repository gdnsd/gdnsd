/* Copyright © 2021 Brandon L Black <blblack@gmail.com>
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

#include <config.h>

#include "dnssec_alg.h"
#include "dnswire.h"

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <sodium.h>

static double get_rate(const struct timespec start, const struct timespec end, const unsigned long iters)
{
    struct timespec elapsed;
    if ((end.tv_nsec - start.tv_nsec) < 0) {
        elapsed.tv_sec = end.tv_sec - start.tv_sec - 1;
        elapsed.tv_nsec = 1000000000L + end.tv_nsec - start.tv_nsec;
    } else {
        elapsed.tv_sec = end.tv_sec - start.tv_sec;
        elapsed.tv_nsec = end.tv_nsec - start.tv_nsec;
    }
    const double elapsed_ms = ((double)elapsed.tv_sec * 1000.0) + ((double)elapsed.tv_nsec) * 1E-6;
    const double rate = (double)iters / elapsed_ms;
    return rate;
}

static void bench_run(uint8_t* out, const struct dnssec_zsk* zsk, const uint8_t* in, const unsigned inlen, const unsigned long iters)
{
    fprintf(stdout, "Alg: %-35s ", zsk->alg->bench_desc);

    struct timespec start = { 0 };
    struct timespec end = { 0 };

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
    for (unsigned long i = 0; i < iters; i++)
        zsk->alg->sign(zsk, out, in, inlen);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);

    fprintf(stdout, "Rate: %.3f/ms\n", get_rate(start, end, iters));
}

static void usage(const char* argv0)
{
    fprintf(stderr, "Usage: %s [-i 100000] [-s 256]\n"
            "  Estimates max signing speed with clock_gettime(CLOCK_PROCESS_CPUTIME_ID)\n"
            "  -i iterations (1 - 100000000)\n"
            "  -s input msg size (1 - 16384)\n",
            argv0);
    exit(99);
}

int main(int argc, char* argv[])
{
    unsigned long dsize = 256LU;
    unsigned long iters = 100000LU;
    int optchar;
    while ((optchar = getopt(argc, argv, "i:s:")) != -1) {
        switch (optchar) {
        case 'i':
            errno = 0;
            iters = strtoul(optarg, NULL, 10);
            if (errno || !iters || iters > 100000000LU)
                usage(argv[0]);
            break;
        case 's':
            errno = 0;
            dsize = strtoul(optarg, NULL, 10);
            if (errno || !dsize || dsize > 16384LU)
                usage(argv[0]);
            break;
        default:
            usage(argv[0]);
        }
    }

    // To ensure we consistently see progress output from the benches *before* they run
    if (setvbuf(stdout, NULL, _IONBF, 0))
        log_warn("setvbuf(stdout, NULL, _IONBF, 0) -> %s", logf_errno());

    if (sodium_init() < 0)
        log_fatal("Could not initialize libsodium: %s", logf_errno());

    struct dnssec_zsk* zsks = sodium_malloc(16U * sizeof(*zsks));
    unsigned num_zsks = 0;
    uint8_t* dnskey_rdata = dnssec_alg_init_zsk(&zsks[num_zsks++], DNSSEC_ALG_ED25519, 0);
    free(dnskey_rdata);
#ifdef HAVE_GNUTLS
    dnskey_rdata = dnssec_alg_init_zsk(&zsks[num_zsks++], DNSSEC_ALG_ECDSAP256SHA256, 0);
    free(dnskey_rdata);
    dnskey_rdata = dnssec_alg_init_zsk(&zsks[num_zsks++], DNSSEC_ALG_ECDSAP256SHA256, ALG_DETERMINISTIC);
    free(dnskey_rdata);
#endif
    dnskey_rdata = NULL;

    fprintf(stdout, "Benchmark: %lu iterations signing %lu byte messages:\n", iters, dsize);

    uint8_t* in = xmalloc(dsize);
    randombytes_buf(in, dsize);

    uint8_t out[4096];
    for (unsigned a = 0; a < num_zsks; a++)
        bench_run(out, &zsks[a], in, (unsigned)dsize, iters);

    free(in);
    for (unsigned a = 0; a < num_zsks; a++)
        zsks[a].alg->wipe_sk(&zsks[a]);
    sodium_free(zsks);

    return 0;
}
