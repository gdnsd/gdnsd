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

#ifndef GDNSD_DNSIO_TCP_H
#define GDNSD_DNSIO_TCP_H

#include "socks.h"

#include <gdnsd/compiler.h>
#include <gdnsd/net.h>

// Called before threads are started, to initialize a thread registry used for stopping
void dnsio_tcp_init(size_t num_threads);

// Uses the above registry to ask threads to stop.  They will exit when
// outstanding TCP connections drain due to close/timeout.
void dnsio_tcp_request_threads_stop(void);

F_NONNULL
void* dnsio_tcp_start(void* thread_asvoid);

F_NONNULL
void tcp_dns_listen_setup(dns_thread_t* t);

#endif // GDNSD_DNSIO_TCP_H
