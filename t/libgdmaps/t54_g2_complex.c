/* Copyright © 2014 Brandon L Black <blblack@gmail.com>
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

// *INDENT-OFF*
static const char cfg[] = QUOTE(
   // bringing it all together: city-auto w/ 5 dcs, custom maps, custom nets
   my_prod_map => {
    geoip2_db => GeoLite2-City-20141008.mmdb,
    datacenters => [ us, ie, sg, tr, br ]
    auto_dc_coords => {
     us = [ 38.9, -77 ]
     ie = [ 53.3, -6.3 ]
     sg = [ 1.3, 103.9 ]
     tr = [ 38.7, 35.5 ]
     br = [ -22.9, -43.2 ]
    }
    map => {
     AS => { JP => [ ie, tr ] }
    }
    nets => {
     10.0.1.0/24 => [ ]
     10.0.0.0/24 => [ tr, ie ]
    }
   }
);
// *INDENT-ON*

gdmaps_t* gdmaps = NULL;

int main(int argc V_UNUSED, char* argv[] V_UNUSED)
{
    gdmaps_test_init(getenv("TEST_CFDIR"));
#ifndef HAVE_GEOIP2
    plan_skip_all("No GeoIP2 support");
    exit(exit_status());
#endif
    if (!gdmaps_test_db_exists("GeoLite2-City-20141008.mmdb")) {
        plan_skip_all("Missing database");
        exit(exit_status());
    }
    plan_tests(LOOKUP_CHECK_NTESTS * 7);
    gdmaps = gdmaps_test_load(cfg);
    //datacenters => [ us, ie, sg, tr, br ]
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "137.138.144.168", "\2\4\1", 16); // Geneva
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "69.58.186.119", "\1\2\5", 17); // US East Coast
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "117.53.170.202", "\3\4\5", 23); // Australia
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "133.11.114.194", "\2\4", 8); // JP, horrible custom 'map' entry
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "10.0.0.44", "\4\2", 24); // Custom 'nets' entry
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "10.0.1.44", "", 24); // Custom 'nets' entry, empty
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "192.168.1.1", "\1\2\3\4\5", 16); // meta-default, no loc
    exit(exit_status());
}
