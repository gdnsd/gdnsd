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

// Unit test for gdmaps

#include "config.h"
#include <gdnsd/log.h>
#include "gdmaps_test.h"

int main(int argc, char* argv[]) {
    if(argc != 2)
        log_fatal("root directory must be set on commandline");

    // dcs are 1 == dc02 and 2 == dc01
    gdmaps_t* gdmaps = gdmaps_test_init(argv[1]);
    unsigned tnum = 0;
    gdmaps_test_lookup_check(tnum++, gdmaps, "my_prod_map", "192.0.2.1", "\2\1", 19);
    gdmaps_test_lookup_check(tnum++, gdmaps, "my_prod_map", "79.125.18.68", "\2", 17);
    gdmaps_test_lookup_check(tnum++, gdmaps, "my_prod_map", "69.58.186.119", "\1\2", 16);
    gdmaps_test_lookup_check(tnum++, gdmaps, "my_prod_map", "::69.58.186.119", "\1\2", 112); // v4-compat
    gdmaps_test_lookup_check(tnum++, gdmaps, "my_prod_map", "::FFFF:69.58.186.119", "\1\2", 112); // v4-mapped
    gdmaps_test_lookup_check(tnum++, gdmaps, "my_prod_map", "::FFFF:0:69.58.186.119", "\1\2", 112); // SIIT
    gdmaps_test_lookup_check(tnum++, gdmaps, "my_prod_map", "2002:453A:BA77::", "\1\2", 32); // 6to4
    gdmaps_test_lookup_check(tnum++, gdmaps, "my_prod_map", "2001::BAC5:4588", "\1\2", 112); // Teredo
    gdmaps_test_lookup_check(tnum++, gdmaps, "my_prod_map", "2600:3c00::f03c:91ff:fe96:6a4f", "\1\2", 30);
}

