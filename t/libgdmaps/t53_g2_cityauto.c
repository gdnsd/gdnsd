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

static const char cfg[] = QUOTE(
   my_prod_map => {
    geoip2_db => GeoLite2-City-20141008.mmdb,
    datacenters => [ us, ie, sg ]
    auto_dc_coords => {
     ie = [ 53.3, -6.3 ]
     sg = [ 1.3, 103.9 ]
     us = [ 38.9, -77 ]
    }
    auto_dc_limit => 0 // unlimited
   }
);

gdmaps_t* gdmaps = NULL;

int main(int argc V_UNUSED, char* argv[] V_UNUSED) {
    gdmaps_test_init(getenv("TEST_CFDIR"));
#ifndef HAVE_GEOIP2
    plan_skip_all("No GeoIP2 support");
    exit(exit_status());
#endif
    if(!gdmaps_test_db_exists("GeoLite2-City-20141008.mmdb")) {
        plan_skip_all("Missing database");
        exit(exit_status());
    }
    plan_tests(LOOKUP_CHECK_NTESTS * 3);
    gdmaps = gdmaps_test_load(cfg);
    //datacenters => [ us, ie, sg ]
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "137.138.144.168", "\2\1\3", 16); // Geneva
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "69.58.186.119", "\1\2\3", 17); // US East Coast
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "117.53.170.202", "\3\2\1", 23); // Australia
    exit(exit_status());
}
