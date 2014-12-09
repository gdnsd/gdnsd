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

#ifndef FIPS104_H
#define FIPS104_H

#include <gdnsd/compiler.h>

#include <inttypes.h>

typedef struct _fips_t fips_t;

F_NONNULL
fips_t* fips_init(const char* pathname);

F_PURE F_NONNULL
const char* fips_lookup(const fips_t* fips, const uint32_t key);

#endif // FIPS104_H
