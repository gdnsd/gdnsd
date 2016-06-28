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

#ifndef GDSND_STATIO_H
#define GDSND_STATIO_H

#include "socks.h"

#include <gdnsd/compiler.h>

#include <stdbool.h>

#include <ev.h>

F_NONNULL
void statio_start(struct ev_loop* statio_loop, const socks_cfg_t* socks_cfg);

// main thread calls this to issue final stats output
F_NONNULL
void statio_final_stats(struct ev_loop* statio_loop);

#endif // GDSND_STATIO_H
