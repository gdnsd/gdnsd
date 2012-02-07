/* Copyright © 2011 Brandon L Black <blblack@gmail.com>
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

// wraps embedded libev source

// override assert with ours which syslogs failures in daemonized debug builds
// (also requires a one-line change in ev.c to disable including assert.h)
#include "gdnsd-dmn.h"
#define assert dmn_assert
// suppress warnings, because libev is noisy with the gcc warnings
#pragma GCC system_header
#include "ev.c"
