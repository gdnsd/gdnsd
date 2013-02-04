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

#ifndef GDNSD_DNSIO_UDP_H
#define GDNSD_DNSIO_UDP_H

#include "config.h"
#include "conf.h"

// retval indicates need for net bind caps, if possible
F_NONNULL
bool udp_sock_setup(dns_addr_t *addrconf);

F_NONNULL F_NORETURN
void* dnsio_udp_start(void* addrconf_asvoid);

#endif // GDNSD_DNSIO_UDP_H
