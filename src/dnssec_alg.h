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

#ifndef GDNSD_DNSSEC_ALG_H
#define GDNSD_DNSSEC_ALG_H

#include <gdnsd/compiler.h>

#include <stdbool.h>

#include <sodium.h>

// req_flags for init_zsk:
#define ALG_DETERMINISTIC 1U

struct dnssec_zsk;

struct dnssec_alg {
    unsigned id;
    unsigned flags;
    unsigned sig_len;
    void(*init_global)(void);
    uint8_t* (*init_sk)(struct dnssec_zsk* zsk);
    unsigned(*sign)(const struct dnssec_zsk* zsk, uint8_t* out, const uint8_t* in, const unsigned in_len);
    void(*wipe_sk)(struct dnssec_zsk* zsk);
    const char* bench_desc;
};

struct dnssec_zsk {
    unsigned tag;
    const struct dnssec_alg* alg;
    void* sk;
};

F_NONNULL
uint8_t* dnssec_alg_init_zsk(struct dnssec_zsk* zsk, unsigned algid, unsigned req_flags);

#endif // GDNSD_DNSSEC_ALG_H
