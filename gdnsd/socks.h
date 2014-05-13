
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

#ifndef GDNSD_SOCKS
#define GDNSD_SOCKS

#include "config.h"
#include "conf.h"
#include <stdbool.h>

F_NONNULL
bool socks_helper_bind(const char* desc, const int sock, const dmn_anysin_t* asin, bool no_freebind);

// helper uses this (when told) to bind all sockets (calls above, indirectly in the statio case)
void socks_helper_bind_all(void);

F_NONNULL
bool socks_sock_is_bound_to(int sock, dmn_anysin_t* addr);

// daemon uses this to validate work done above
// if soft: false retval means all succeeded, true retval means one or more failed
// if !soft: will log_fatal() if any fail
bool socks_daemon_check_all(bool soft);

#endif // GDNSD_SOCKS
