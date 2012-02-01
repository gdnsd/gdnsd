/* Copyright © 2011 Brandon L Black <blblack@gmail.com>
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

#ifndef _GDNSD_LTARENA_H
#define _GDNSD_LTARENA_H

#include "config.h"
#include "gdnsd.h"

void lta_init(void);
void lta_close(void);

F_MALLOC F_WUNUSED
void* lta_malloc(unsigned size, unsigned align_bytes);

#define lta_malloc_p(_size) lta_malloc(_size, SIZEOF_UINTPTR_T)
#define lta_malloc_1(_size) lta_malloc(_size, 1)

// Works for both dnames and labels technically
F_NONNULL F_WUNUSED
uint8_t* lta_labeldup(const uint8_t* dn);

// This is for dname storage, it uses a temporary
//  hash to de-duplicate them.
F_NONNULL F_WUNUSED
uint8_t* lta_dnamedup_hashed(const uint8_t* dn);

#endif // _GDNSD_LTARENA_H
