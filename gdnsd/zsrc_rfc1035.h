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

#ifndef GDNSD_ZSRC_RFC1035_H
#define GDNSD_ZSRC_RFC1035_H

#include "config.h"
#include "gdnsd/compiler.h"
#include <ev.h>

void zsrc_rfc1035_load_zones(void);

F_NONNULL
void zsrc_rfc1035_runtime_init(struct ev_loop* loop);

void zsrc_rfc1035_sighup(void);

#endif // GDNSD_ZSRC_RFC1035_H
