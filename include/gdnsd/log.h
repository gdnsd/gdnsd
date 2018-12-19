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

#include <sys/types.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <syslog.h>

/***
**** Logging interfaces
***/

// Setter+Getter for logging debug output:
void gdnsd_log_set_debug(bool debug);
F_PURE
bool gdnsd_log_get_debug(void);

// Setter+Getter for syslog (vs stderr) log output:
void gdnsd_log_set_syslog(bool set_syslog, const char* ident);
F_PURE
bool gdnsd_log_get_syslog(void);

// This is a syslog()-like interface that will log
//  to stderr and is thread-safe
F_COLD F_NONNULLX(2) F_PRINTF(2, 3)
void gdnsd_logger(int level, const char* fmt, ...);

// The intended simple API for logging with 5 separate function-call-like
// interfaces with different levels.  The _fatal variant exits after emitting
// the logged statement, and the _debug variant's output is toggled with the
// runtime gdnsd_log_set_debug() call (defaults off)
#define gdnsd_log_info(...) gdnsd_logger(LOG_INFO, __VA_ARGS__)
#define gdnsd_log_warn(...) gdnsd_logger(LOG_WARNING, __VA_ARGS__)
#define gdnsd_log_err(...) gdnsd_logger(LOG_ERR, __VA_ARGS__)

// log_debug() messages will only be emitted if the runtime debug flag is set
#define gdnsd_log_debug(...) do {\
     if (gdnsd_log_get_debug())\
         gdnsd_logger(LOG_DEBUG, __VA_ARGS__);\
     } while (0)

// GDNSD_NO_FATAL_COVERAGE is to allow coverage testing to skip
//   over fatal conditions.  If your tests don't cover those
//   for pragmatic reasons, this considerably reduces line noise.
//   Note that this is only going to work if your tests *never*
//   exercise a fatal case; it will probably cause random
//   bugs leading to test failures otherwise.
#ifdef GDNSD_NO_FATAL_COVERAGE
#  define gdnsd_log_fatal(...) ((void)(0))
#else
#  define gdnsd_log_fatal(...) do {\
     gdnsd_logger(LOG_CRIT, __VA_ARGS__);\
     exit(42);\
   } while (0)
#endif

// GDNSD_NO_UNREACH_BUILTIN is to work around gcov coverage testing, which
//   flags un-taken branches for all of the __builtin_unreachable()
// gdnsd_log_devdebug() is suppressed at the preprocessor level if -DNDEBUG
//   is set; use this in performance-critical areas (to avoid the runtime
//   check of the debug flag) or for spammy messages that only developers need
#ifdef NDEBUG
#  if defined(GDNSD_HAVE_UNREACH_BUILTIN) && !defined(GDNSD_NO_UNREACH_BUILTIN)
#    define gdnsd_assert(expr) do { if (!(expr)) __builtin_unreachable(); } while (0)
#  else
#    define gdnsd_assert(expr) ((void)(0))
#  endif
#  define gdnsd_log_devdebug(...) ((void)(0))
#else
#  define gdnsd_assert(expr) do {\
     if (!(expr)) {\
       gdnsd_logger(LOG_CRIT, "Assertion '%s' failed in %s() at %s:%i, backtrace:%s",\
       #expr, __func__, __FILE__, __LINE__, gdnsd_logf_bt());\
       abort();\
     }\
   } while (0)
#  define gdnsd_log_devdebug(...) do {\
     if (gdnsd_log_get_debug())\
         gdnsd_logger(LOG_DEBUG, __VA_ARGS__);\
     } while (0)
#endif // NDEBUG

//
// fmtbuf_alloc() allows you to make custom string-formatters
//  for use with the above logging functions.  You use this
//  function to allocate buffer space within your function,
//  and then return a pointer to the space.  All buffer space
//  comes from a shared per-pthread pool, and is reset
//  when you call a logging function above.
// Your custom formatter can use only log_fatal() to signal
//  bugs, but probably should avoid using custom formatters itself.
// "size" is not allowed to be zero, and this function never returns NULL
// Example:
//
//  const char* my_int_formatter(int foo)
//  {
//     char* buf = gdnsd_fmtbuf_alloc(22);
//     if (snprintf(buf, 22, "%i", foo) >= 22)
//       log_fatal("BUG: Integer formatting did not fit buffer space!");
//     return buf;
//  }
//
//  gdnsd_log_warn("The integer had value %s!", my_int_formatter(someint));
//
F_RETNN F_COLD
char* gdnsd_fmtbuf_alloc(const size_t size);

// Reset (free allocations within) the format buffer.  Do not use this
//  with the normal log functions.  If you use the fmtbuf-based formatters
//  *outside* of a log function, use this afterwards to reclaim the space.
F_COLD
void gdnsd_fmtbuf_reset(void);

// Use this as a thread-safe strerror() within the arguments
//  of the above logging functions.  This is built on gdnsd_fmtbuf_alloc()
//  above and takes care of the difference between the GNU
//  and POSIX strerror_r() variants.
F_RETNN F_COLD
const char* gdnsd_logf_strerror(const int errnum);
#define gdnsd_logf_errno() gdnsd_logf_strerror(errno)

// Adds a strack trace to the log message, iff built w/ libunwind
F_RETNN F_COLD
const char* gdnsd_logf_bt(void);

// custom log formatters for raw ipv6 data and dnames
F_RETNN F_COLD
const char* gdnsd_logf_ipv6(const uint8_t* ipv6);
F_RETNN F_COLD
const char* gdnsd_logf_in6a(const struct in6_addr* in6a);
F_RETNN F_COLD
const char* gdnsd_logf_dname(const uint8_t* dname);

// shortcut defines for basic log levels + formatters, avoids the gdnsd_ prefix
// in the common case to keep lines shorter, but doesn't pollute symbol table,
// where the full names are still used.

#define log_info gdnsd_log_info
#define log_warn gdnsd_log_warn
#define log_err gdnsd_log_err
#define log_fatal gdnsd_log_fatal
#define log_debug gdnsd_log_debug
#define log_devdebug gdnsd_log_devdebug

#define logf_errno() gdnsd_logf_strerror(errno)
#define logf_strerror gdnsd_logf_strerror
#define logf_bt gdnsd_logf_bt
#define logf_dname gdnsd_logf_dname
#define logf_ipv6 gdnsd_logf_ipv6
#define logf_in6a gdnsd_logf_in6a

#endif // GDNSD_LOG_H
