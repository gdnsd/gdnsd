/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
 *
 * This file is part of gdnsd.
 *
 * gdnsd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * gdnsd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gdnsd.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef GDNSD_PATHS_H
#define GDNSD_PATHS_H

#include <gdnsd/compiler.h>

// given a configfile name and an optional path prefix, return
//  a pathname usable for e.g. open()/stat() within the gdnsd
//  config directory.
// When given an absolute path, the prefix is ignored and
//  absolute reference is given.
// Examples:
//    gdnsd_resolve_path_cfg(NULL, NULL);
//        -> /etc/gdnsd
//    gdnsd_resolve_path_cfg("config", NULL);
//        -> /etc/gdnsd/config
//    gdnsd_resolve_path_cfg("GeoIPRegion.dat", "geoip");
//        -> /etc/gdnsd/geoip/GeoIPRegion.dat
//    gdnsd_resolve_path_cfg("/usr/share/maxmind/GeoIPRegion.dat", "geoip");
//        -> /usr/share/maxmind/GeoIPRegion.dat
char* gdnsd_resolve_path_cfg(const char* inpath, const char* pfx);

// As above for "run" paths (e.g. /var/run/gdnsd or /run/gdnsd)
char* gdnsd_resolve_path_run(const char* inpath, const char* pfx);

// As above for "state" paths (e.g. /var/lib/gdnsd)
char* gdnsd_resolve_path_state(const char* inpath, const char* pfx);

// As above for "libexec" paths (e.g. /usr/libexec/gdnsd/)
char* gdnsd_resolve_path_libexec(const char* inpath, const char* pfx);

#endif // GDNSD_PATHS_H
