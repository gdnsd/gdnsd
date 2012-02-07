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

#ifndef _GDNSD_LOG_H
#define _GDNSD_LOG_H

#include <gdnsd-compiler.h>
#include <gdnsd-net.h>

#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <syslog.h>

#include <gdnsd-dmn.h>

#define gdnsd_logger dmn_logger
#define gdnsd_loggerv dmn_loggerv
#define log_info dmn_log_info
#define log_warn dmn_log_warn
#define log_err dmn_log_err
#define log_fatal dmn_log_fatal
#define log_debug dmn_log_debug

/* Custom thread-safe %s-formatters for anysin_t*, errno, etc..
 * Use these *only* in the argument lists of log_foo() calls!
 *
 * e.g.:
 *
 * anysin_t* asin = ...;
 * int pthread_error = ...;
 * log_err("pthread error: %s, regular errno: %s, sockaddr: %s",
 *     logf_errnum(pthread_error), logf_errno(), logf_anysin(asin));
 */

F_PURE
const char* gdnsd_logf_rrtype(const unsigned rrtype); // host order

const char* gdnsd_logf_dname(const uint8_t* dname);
const char* gdnsd_logf_lstack(const uint8_t** lstack, const int depth);
const char* gdnsd_logf_anysin(const anysin_t* asin);
const char* gdnsd_logf_anysin_noport(const anysin_t* asin);
#define gdnsd_logf_errnum dmn_strerror
#define gdnsd_logf_errno() dmn_strerror(errno)
#define logf_rrtype gdnsd_logf_rrtype
#define logf_dname gdnsd_logf_dname
#define logf_lstack gdnsd_logf_lstack
#define logf_anysin gdnsd_logf_anysin
#define logf_anysin_noport gdnsd_logf_anysin_noport
#define logf_errnum dmn_strerror
#define logf_errno() dmn_strerror(errno)

#endif // _GDNSD_LOG_H
