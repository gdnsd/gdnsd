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
#include <string.h>

/******************************************************************\
* ltarena is arena storage for ltree label/dname data, it allocates
*   unaligned string data in giant pools with no overhead.
\******************************************************************/

typedef struct ltarena ltarena_t;

// Allocate a new arena
F_WUNUSED
ltarena_t* lta_new(void);

// Actual allocator, asserts size <= 256, cannot fail or return nonnull
// (underlying allocator will abort the whole program if truly unable to make
// space for new pools)
F_MALLOC F_ALLOCSZ(2) F_RETNN F_NONNULL
uint8_t* lta_malloc(ltarena_t* lta, const size_t size);

// Duplicate a label in arena storage
F_MALLOC F_UNUSED F_RETNN F_NONNULL
static uint8_t* lta_labeldup(ltarena_t* lta, const uint8_t* label)
{
    const size_t sz = *label + 1U;
    uint8_t* rv = lta_malloc(lta, sz);
    memcpy(rv, label, sz);
    return rv;
}

// As above for dnames, function is identical, but naming matters
#define lta_dnamedup lta_labeldup

// Close an arena to further allocations, idempotent.
// After this call, the only valid operations are _close()/_destroy()
F_NONNULL
void lta_close(ltarena_t* lta);

// Destroy an arena, freeing all storage associated with it
F_NONNULL
void lta_destroy(ltarena_t* lta);

#endif // GDNSD_LTARENA_H
