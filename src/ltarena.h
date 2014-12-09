/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
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

#ifndef GDNSD_LTARENA_H
#define GDNSD_LTARENA_H

#include <gdnsd/compiler.h>

#include <inttypes.h>

/******************************************************************\
* ltarena is arena storage for ltree string data, it allocates
*   unaligned string data in giant pools with no overhead.
\******************************************************************/

typedef struct _ltarena ltarena_t;

// Allocate a new arena
F_MALLOC F_WUNUSED
ltarena_t* lta_new(void);

// This is like a strdup() that allocates from an lta arena
//  and happens to know the internally-encoded length of
//  label strings as used in ltrees.
// Use only for label data.
F_MALLOC F_WUNUSED F_NONNULL
uint8_t* lta_labeldup(ltarena_t* lta, const uint8_t* label);

// As above, except:
//   1) Assumes gdnsd's "dname"-format data
//   2) Can de-duplicate storage by returning data that aliases
//     previous allocations via this same interface and arena.
F_WUNUSED F_NONNULL
const uint8_t* lta_dnamedup(ltarena_t* lta, const uint8_t* dname);

// Close an arena to further allocations, idempotent.
// After this call, the only valid operations are _close()/_destroy()
F_NONNULL
void lta_close(ltarena_t* lta);

// Destroy an arena, freeing all storage associated with it
F_NONNULL
void lta_destroy(ltarena_t* lta);

#endif // GDNSD_LTARENA_H
