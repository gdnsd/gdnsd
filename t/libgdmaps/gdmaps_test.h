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

#ifndef GDMAPS_TEST_H
#define GDMAPS_TEST_H

#include <gdmaps.h>

#include <stdbool.h>

// initialize test environment.  cfg_data is a string containing
//   the ",,," from "plugins => { geoip => { maps => { ... } }}
//   cfg_dir is where to look for referenced nets/geoip files.
// these two must be called in sequence.
F_NONNULL
void gdmaps_test_init(const char* cfg_dir);
F_NONNULL
gdmaps_t* gdmaps_test_load(const char* cfg_data);

// A complete results-checker.
F_NONNULL
void gdmaps_test_lookup_check(const gdmaps_t* gdmaps, const char* map_name, const char* addr_txt, const char* dclist_cmp, const unsigned scope_cmp);

// This variant only validates that we can complete the lookup operation
//   without crashing, it doesn't care about the data in the results
F_NONNULL
void gdmaps_test_lookup_noop(const gdmaps_t* gdmaps, const char* map_name, const char* addr_txt);

// boolean for whether a given file exists in the geoip config dir
F_NONNULL
bool gdmaps_test_db_exists(const char* dbfile);

// number of actual libtap tests for each invocation above
#define LOOKUP_CHECK_NTESTS 2
#define LOOKUP_NOOP_NTESTS 1

// handy for config blocks
#define QUOTE(...) #__VA_ARGS__

#endif // GDMAPS_TEST_H
