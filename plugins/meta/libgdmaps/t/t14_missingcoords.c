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

// Unit test for gdmaps

#include "config.h"
#include <gdnsd-log.h>
#include "gdmaps_test.h"

int main(int argc, char* argv[]) {
    if(argc != 2)
        log_fatal("root directory must be set on commandline");

    gdmaps_t* gdmaps = gdmaps_test_init(argv[1]);
    unsigned tnum = 0;
    //datacenters => [ us, ie, sg, tr, br ]
    gdmaps_test_lookup_check(tnum++, gdmaps, "my_prod_map", "137.138.144.168", "\2\1\5\3", 16); // Geneva
    gdmaps_test_lookup_check(tnum++, gdmaps, "my_prod_map", "69.58.186.119", "\1\2\5\3", 16); // US East Coast
    gdmaps_test_lookup_check(tnum++, gdmaps, "my_prod_map", "117.53.170.202", "\3\5\1\2", 20); // Australia
    gdmaps_test_lookup_check(tnum++, gdmaps, "my_prod_map", "133.11.114.194", "\2\4", 8); // JP, horrible custom 'map' entry
    gdmaps_test_lookup_check(tnum++, gdmaps, "my_prod_map", "10.0.0.44", "\4\2", 24); // Custom 'nets' entry
    gdmaps_test_lookup_check(tnum++, gdmaps, "my_prod_map", "10.0.1.44", "", 24); // Custom 'nets' entry, empty
    gdmaps_test_lookup_check(tnum++, gdmaps, "my_prod_map", "192.168.1.1", "\1\2\3\4\5", 16); // meta-default, no loc
    gdmaps_destroy(gdmaps);
}

