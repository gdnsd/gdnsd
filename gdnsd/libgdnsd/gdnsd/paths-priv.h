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

#ifndef GDNSD_PATHS_PRIV_H
#define GDNSD_PATHS_PRIV_H

#include "gdnsd/compiler.h"
#include "gdnsd/paths.h"

// Called by core daemon only, once at startup.
//   It cleans up "rootdir_in" via realpath(), verifies
//   existence, and does a chdir() into it.
// From here forward, the data root dir paths
//   are used as relative paths, e.g. "etc/config",
//   "etc/geoip/GeoIPRegion.dat", etc...
// (Unless the default or argument is "system", in
//   which case we set up for unrooted execution
//   with system default paths from autoconf)
void gdnsd_set_rootdir(const char* rootdir_in);

// Returns the realpath()-cleaned actual rootdir
//   determined and used above.  Almost none of the
//   code should actually need this, except the
//   security code for chroot().
F_PURE
const char* gdnsd_get_rootdir(void);

// this returns the compiled default (a path
//   for chroot default, or "system", never NULL),
//   to help with the usage() output...
F_PURE
const char* gdnsd_get_def_rootdir(void);

// get a pathname for pidfile operations
char* gdnsd_get_pidpath(void);

#endif // GDNSD_PATHS_PRIV_H
