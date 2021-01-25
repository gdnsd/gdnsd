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

#ifndef GDNSD_DNSSEC_NXDC_H
#define GDNSD_DNSSEC_NXDC_H

#include <gdnsd/compiler.h>

#include "dnssec.h"
#include "statio.h"

#include <inttypes.h>

struct nxdc;

struct nxdc* nxdc_new(struct dns_stats* stats, const unsigned scale, const unsigned rate, const unsigned max_zsks);

F_NONNULL
void nxdc_destroy(struct nxdc* n);

F_NONNULL
unsigned nxdc_synth(struct nxdc* n, const struct dnssec* sec, const uint8_t* nxd_name, uint8_t* buf, uint64_t gen, const unsigned nxd_name_len);

#endif // GDNSD_DNSSEC_NXDC_H
