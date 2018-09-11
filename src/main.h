/* Copyright © 2014 Brandon L Black <blblack@gmail.com>
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

#ifndef GDNSD_MAIN
#define GDNSD_MAIN

#include <gdnsd/compiler.h>

F_NONNULL
void gdnsd_atexit(void (*f)(void));

// css calls this to start an async zone data reload operation
void spawn_async_zones_reloader_thread(void);

// ztree calls this on reload completion
void notify_reload_zones_done(void);

#endif // GDNSD_MAIN
