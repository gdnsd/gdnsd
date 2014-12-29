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

#include <config.h>
#include "gdmaps_test.h"
#include <tap.h>

static const char cfg[] = QUOTE(
   my_prod_map => {
    geoip_db => GeoIP-20111210.dat,
    datacenters => [ dc01, dc02 ],
    nets => gn_corner.nets
    map => {
     na => [ dc02, dc01 ],
     EU => { ie => [ dc01 ] },
    }
   }
);

gdmaps_t* gdmaps = NULL;

int main(int argc V_UNUSED, char* argv[] V_UNUSED) {
    gdmaps_test_init(getenv("TEST_CFDIR"));
    if(!gdmaps_test_db_exists("GeoIP-20111210.dat")) {
        plan_skip_all("Missing database");
        exit(exit_status());
    }
    plan_tests(LOOKUP_CHECK_NTESTS * 2);
    gdmaps = gdmaps_test_load(cfg);
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "79.125.0.0", "\2", 17);
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "10.111.1.1", "\2", 14);
    exit(exit_status());
}
