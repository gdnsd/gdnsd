/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
 *
 * This file is part of gdnsd-plugin-geoip.
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

#ifndef GDMAPS_TEST_H
#define GDMAPS_TEST_H

#include "config.h"
#include <inttypes.h>
#include <gdnsd/vscf.h>
#include <gdnsd/plugapi.h>

#include "gdmaps.h"

// init gdmaps_t based on user-supplied rootdir (or default if NULL)
gdmaps_t* gdmaps_test_init(const char* input_rootdir);

// A complete results-checker.  It will terminate with stderr output if
//  the data comparison (or any earlier part of the operation) fails.
F_NONNULL
void gdmaps_test_lookup_check(const unsigned tnum, const gdmaps_t* gdmaps, const char* map_name, const char* addr_txt, const char* dclist_cmp, const unsigned scope_cmp);

// This variant only validates that we can complete the lookup operation
//   without crashing, it doesn't care about the data in the results
F_NONNULL
void gdmaps_lookup_noop(const unsigned tnum, const gdmaps_t* gdmaps, const char* map_name, const char* addr_txt);

#endif // GDMAPS_TEST_H
