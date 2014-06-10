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
#include <stdbool.h>

// Return the compiled-in default config file pathname
const char* gdnsd_get_default_config_file(void);

// Set any explicitly-configured directories to non-default
//   values.  Only supply explicit overrides!
// The state/run dirs will get compiled-in defaults if NULL.
// The internal config dir behavior has 3 basic cases:
//   1) if config_dir, use that.
//   2) else if config_file, use dirname(config_file)
//   3) else use dirname(gdnsd_get_default_config_file())
// if runtime_dirs is false, the state/run dirs will not
//   be checked for existence or created.  Useful for
//   uses outside of gdnsd itself (e.g. testsuite binaries)
void gdnsd_set_dirs(const char* run_dir, const char* state_dir, const char* config_dir, const char* config_file, const bool runtime_dirs);

#endif // GDNSD_PATHS_PRIV_H
