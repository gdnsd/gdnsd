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

// *INDENT-OFF*
static const char cfg[] = QUOTE(
   my_prod_map => {
    datacenters => [ dc01, dc02 ],
    nets => extn_all.nets
   }
);
// *INDENT-ON*

gdmaps_t* gdmaps = NULL;

int main(int argc V_UNUSED, char* argv[] V_UNUSED)
{
    gdmaps_test_init(getenv("TEST_CFDIR"));
    plan_tests(LOOKUP_CHECK_NTESTS * 2);
    gdmaps = gdmaps_test_load(cfg);
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "192.0.2.1", "\2", 0);
    gdmaps_test_lookup_check(gdmaps, "my_prod_map", "2600:3c02:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", "\2", 6);
    exit(exit_status());
}
