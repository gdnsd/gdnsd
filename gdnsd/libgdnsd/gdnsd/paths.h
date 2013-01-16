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

// cleanup path_in via realpath() (symlink / relative eliminated),
//  returning a newly allocated string.  path_in must actually
//  exist to succeed.
// "desc" will be used to log errors or to log_info() the path translation.
F_NONNULL
char* gdnsd_realpath(const char* path_in, const char* desc);

// given a configfile name and an optional path prefix, return
//  a pathname usable for e.g. open()/stat() within the gdnsd
//  config directory.
// When given an absolute path, the prefix is ignored and
//  absolute reference is given (within root context in rooted case).
// (Keep in mind the daemon is always chdir() to the specified
//  rootdir even before chroot(), or to '/' if using system paths).
// Examples:
//    gdnsd_resolve_path_cfg("config", NULL);
//        unrooted -> /etc/gdnsd/config
//        rooted -> etc/config
//    gdnsd_resolve_path_cfg("GeoIPRegion.dat", "geoip");
//        unrooted -> /etc/gdnsd/geoip/GeoIPRegion.dat
//        rooted -> etc/geoip/GeoIPRegion.dat
//    gdnsd_resolve_path_cfg("/var/lib/maxmind/GeoIPRegion.dat", "geoip");
//        unrooted -> /var/lib/maxmind/GeoIPRegion.dat
//        rooted -> var/lib/maxmind/GeoIPRegion.dat
F_NONNULLX(1)
char* gdnsd_resolve_path_cfg(const char* inpath, const char* pfx);

#endif // GDNSD_PATHS_H
