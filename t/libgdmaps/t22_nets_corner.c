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
    datacenters => [ dc01, dc02, dc03 ],
    nets => nets_corner.nets
   }
);

gdmaps_t* gdmaps = NULL;

int main(int argc V_UNUSED, char* argv[] V_UNUSED) {
    gdmaps_test_init(getenv("TEST_CFDIR"));
    plan_tests(LOOKUP_CHECK_NTESTS * 4);
    gdmaps = gdmaps_test_load(cfg);
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "::1", "\3", 101);
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "10.0.0.0", "\1", 9);
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "10.128.0.1", "\2", 10);
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "FFFF:FFFF::1", "\2", 127);
    exit(exit_status());
}
