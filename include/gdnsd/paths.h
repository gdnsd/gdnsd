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

// Call this at most once!
// This does the following:
//   1) If config_dir is not NULL, uses it to override the compiled-in
//      default configuration directory.
//   2) Parses the primary config file into a vscf data structure,
//      if it's present at all.
//   3) Sets all libgdsnsd-internal directory pathnames for use by
//      gdnsd_resolve_path_foo(), some of which are going to be based on
//      either the config_dir or options => foo_dir within the configuration.
//   4) If create_dirs is true, it will also create, if missing, the runtime
//      "state" (e.g. /var/lib/gdnsd) and "run" (e.g. /var/run/gdnsd) dirs
//   5) Returns the parsed vscf config object for further consumption by the
//      caller.  The directory-related options mentioned above will already be
//      marked as consumed for the purposes of later iterating for bad config
//      keys.  The caller is responsible for destroying it via vscf_destroy().
//
vscf_data_t* gdnsd_init_paths(const char* config_dir, const bool create_dirs);

// This is just to display the compiled-in static default for e.g.
//   commandline help output purposes
F_CONST F_RETNN
const char* gdnsd_get_default_config_dir(void);

// Gets a readonly copy of the base config dir actually in use
F_PURE F_RETNN
const char* gdnsd_get_config_dir(void);

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
F_RETNN F_MALLOC
char* gdnsd_resolve_path_cfg(const char* inpath, const char* pfx);

// As above for "run" paths (e.g. /var/run/gdnsd or /run/gdnsd)
F_RETNN F_MALLOC
char* gdnsd_resolve_path_run(const char* inpath, const char* pfx);

// As above for "state" paths (e.g. /var/lib/gdnsd)
F_RETNN F_MALLOC
char* gdnsd_resolve_path_state(const char* inpath, const char* pfx);

// As above for "libexec" paths (e.g. /usr/libexec/gdnsd/)
F_RETNN F_MALLOC
char* gdnsd_resolve_path_libexec(const char* inpath, const char* pfx);

#endif // GDNSD_PATHS_H
