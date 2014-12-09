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

#include <gdnsd/vscf.h>

#include <stdbool.h>

#pragma GCC visibility push(default)

// This is just to display the compiled-in static default for e.g.
//   commandline help output purposes
const char* gdnsd_get_default_config_dir(void);

// Every independent program which makes use of libgdnsd must call this
// fairly early in its lifecycle, usually right after dmn_init1().
// One should assume that everything else in the gdnsd_ namespace from
// libgdnsd depends on this being called first to initialize the library.
//
// This does the following:
//   0) Calls other internal initialization routines for e.g. the
//      network and RNG portions of the library.
//   1) If config_dir is not NULL, uses it to override the compiled-in
//      default configuration directory.
//   2) Parses the primary config file into a vscf data structure,
//      if it's present at all.
//   3) Sets all libgdsnsd-internal directory pathnames for use by
//      gdnsd_resolve_path_foo(), some of which are going to be based on
//      either the config_dir or options => foo_dir within the configuration.
//   4) If check_create_dirs is true, it will also validate the directories'
//      existence and in some cases create them (state, run).  This option
//      should be true if the intent is to start a runtime gdnsd daemon, but
//      false otherwise (e.g. simple commandline programs).
//   5) Returns the parsed vscf config object for further consumption by the
//      caller.  The directory-related options mentioned above will already be
//      marked as consumed for the purposes of later iterating for bad config
//      keys.  The caller is responsible for destroying it via vscf_destroy().
//
vscf_data_t* gdnsd_initialize(const char* config_dir, const bool check_create_dirs);

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

#pragma GCC visibility pop

#endif // GDNSD_PATHS_H
