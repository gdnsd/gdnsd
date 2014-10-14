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

#include "config.h"
#include <gdnsd/compiler.h>
#include <stdbool.h>
#include <ev.h>

void statio_init(void);
void statio_bind_socks(void);
bool statio_check_socks(bool soft);

F_NONNULL
void statio_start(struct ev_loop* statio_loop);

// main thread calls this to issue final stats output
void statio_final_stats(void);

// main thread calls this to wait on completion of the above
void statio_final_stats_wait(void);

#endif // GDSND_STATIO_H

