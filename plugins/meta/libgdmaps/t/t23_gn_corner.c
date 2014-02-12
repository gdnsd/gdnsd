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
#include <gdnsd/log.h>
#include "gdmaps_test.h"

int main(int argc, char* argv[]) {
    if(argc != 2)
        log_fatal("root directory must be set on commandline");

    gdmaps_t* gdmaps = gdmaps_test_init(argv[1]);
    unsigned tnum = 0;
    gdmaps_test_lookup_check(tnum++, gdmaps, "my_prod_map", "79.125.0.0", "\2", 17);
    gdmaps_test_lookup_check(tnum++, gdmaps, "my_prod_map", "10.111.1.1", "\2", 14);
    gdmaps_destroy(gdmaps);
}
