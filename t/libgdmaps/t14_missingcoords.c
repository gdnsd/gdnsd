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
   // bringing it all together: city-auto w/ 5 dcs,
   //  dual GeoIP inputs, custom maps, custom nets
   //  testing with one datacenter not used in auto coords
   my_prod_map => {
    geoip_db => GeoLiteCityv6-20111210.dat,
    geoip_db_v4_overlay => GeoLiteCity-20111210.dat,
    datacenters => [ us, ie, sg, tr, br ]
    auto_dc_limit => 5,
    auto_dc_coords => {
     us = [ 38.9, -77 ]
     ie = [ 53.3, -6.3 ]
     sg = [ 1.3, 103.9 ]
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

gdmaps_t* gdmaps = NULL;

int main(int argc V_UNUSED, char* argv[] V_UNUSED) {
    gdmaps_test_init(getenv("TEST_CFDIR"));
    if(!gdmaps_test_db_exists("GeoLiteCityv6-20111210.dat")
      || !gdmaps_test_db_exists("GeoLiteCity-20111210.dat")) {
        plan_skip_all("Missing database");
        exit(exit_status());
    }
    plan_tests(LOOKUP_CHECK_NTESTS * 7);
    gdmaps = gdmaps_test_load(cfg);
    //datacenters => [ us, ie, sg, tr, br ]
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "137.138.144.168", "\2\1\5\3", 16); // Geneva
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "69.58.186.119", "\1\2\5\3", 16); // US East Coast
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "117.53.170.202", "\3\5\1\2", 20); // Australia
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "133.11.114.194", "\2\4", 8); // JP, horrible custom 'map' entry
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "10.0.0.44", "\4\2", 24); // Custom 'nets' entry
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "10.0.1.44", "", 24); // Custom 'nets' entry, empty
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "192.168.1.1", "\1\2\3\4\5", 16); // meta-default, no loc
    exit(exit_status());
}
