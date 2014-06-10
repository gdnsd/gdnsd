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

#ifndef GDNSD_LOG_H
#define GDNSD_LOG_H

#include <gdnsd/compiler.h>
#include <gdnsd/net.h>

#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <syslog.h>
#include <gdnsd/dmn.h>

// shortcut defines for basic log levels
#define log_info dmn_log_info
#define log_warn dmn_log_warn
#define log_err dmn_log_err
#define log_fatal dmn_log_fatal
#define log_debug dmn_log_debug
#define log_devdebug dmn_log_devdebug

/* Custom thread-safe %s-formatters for dmn_anysin_t*, errno, etc..
 * Use these *only* in the argument lists of log_foo() calls!
 *
 * e.g.:
 *
 * dmn_anysin_t* asin = ...;
 * int pthread_error = ...;
 * log_err("pthread error: %s, regular errno: %s, sockaddr: %s",
 *     dmn_logf_strerror(pthread_error), dmn_logf_errno(), dmn_logf_anysin(asin));
 */
const char* gdnsd_logf_dname(const uint8_t* dname);

// "ipv6" must be allocated for 16 bytes, containing
//   a network-order address
const char* gdnsd_logf_ipv6(const uint8_t* ipv6);
// standard "struct in6_addr" (basically the same thing...)
const char* gdnsd_logf_in6a(const struct in6_addr* in6a);

// shortcuts for the above
#define logf_dname gdnsd_logf_dname
#define logf_ipv6 gdnsd_logf_ipv6
#define logf_in6a gdnsd_logf_in6a

#endif // GDNSD_LOG_H
