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

#ifndef _DMN_H
#define _DMN_H

#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <syslog.h>

// gcc function attributes
#if defined __GNUC__ && __GNUC__ >= 3 // gcc 3.0+
#  define DMN_F_PURE          __attribute__((__pure__))
#  define DMN_F_PRINTF(X,Y)   __attribute__((__format__(__printf__, X, Y)))
#  if __GNUC__ > 3 || __GNUC_MINOR__ > 2 // gcc 3.3+
#    define DMN_F_NONNULLX(...) __attribute__((__nonnull__(__VA_ARGS__)))
#    define DMN_F_NONNULL       __attribute__((__nonnull__))
#  else
#    define DMN_F_NONNULLX(...)
#    define DMN_F_NONNULL
#  endif
#  if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 4) // gcc 4.5+
#    define DMN_HAVE_UNREACH_BUILTIN 1
#  endif
#else
#  define DMN_F_PRINTF(X,Y)
#  define DMN_F_NONNULLX(...)
#  define DMN_F_NONNULL
#endif

/***
**** Daemonization interfaces
***/

// Attempt to daemonize the current process using "pidfile"
//  as the pidfile pathname.  logname is used as the daemon's
//  official name for openlog() purposes.
DMN_F_NONNULL
void dmn_daemonize(const char* logname, const char* pidfile);

// Check the status of a daemon using "pidfile".  Return value
//  of zero means not running, otherwise the return value is
//  the pid of the running daemon
DMN_F_NONNULL
int dmn_status(const char* pidfile);

// Attempt to stop any running daemon using "pidfile".  This function
//  will make several attempts (with an increasing delay) to terminate
//  via SIGTERM before giving up and aborting with an error message.
// retval == 0 means daemon was not running, or was successfully killed.
// retval != 0 means daemon is still running (and the pid is the retval)
DMN_F_NONNULL
int dmn_stop(const char* pidfile);

// Send an aribtrary signal to a running daemon using "pidfile".
DMN_F_NONNULL
void dmn_signal(const char* pidfile, int sig);

// Find out if the process is currently daemonized or not
DMN_F_PURE
bool dmn_is_daemonized(void);

/***
**** chroot/privdrop security interfaces
***/

// Takes a username and a chroot() path, does as much pre-validation
//  as possible and stores the results for a later call to dmn_secure_me().
// If chroot_fixup is true, this code will attempt to create any non-existent
//  chroot_path w/ mode 755, and/or fix an existing chroot_path's ownership
//  (set to uid/gid 0) and permissions (strip group/other write bits).
// If chroot_path is NULL, no chroot checking is done here, and no chroot()
//  is done during the following secure_me() call.
DMN_F_NONNULLX(1)
void dmn_secure_setup(const char* username, const char* chroot_path, const bool chroot_fixup);

// Executes the actual chroot()/chuid()/etc calls based on previous
//  dmn_secure_setup(), which must be called first.
void dmn_secure_me(void);

// This accessor indicates whether dmn_secure_me() has been called or not
DMN_F_PURE
bool dmn_is_secured(void);

// This accessor returns the chroot path configured through dmn_secure_setup(),
//   if that setup has occured yet.  If dmn_secure_setup() was not (yet) called,
//   or was called with chroot_path set to NULL, it returns NULL.  Note that
//   if this returns a path, dmn_is_secured() tells you whether we've already
//   chroot'd into that path.
DMN_F_PURE
const char* dmn_get_chroot(void);

/***
**** Logging interfaces
***/

// Get/Set debug flag:
// When the daemon is built in debug mode (!defined NDEBUG),
//  *and* this flag is set to true by the daemon,
//  dmn_log_debug() emits output.  This is not intended
//  to be toggled at runtime (especially from threads!),
//  it is meant to be set once at startup and left alone.
DMN_F_PURE
bool dmn_get_debug(void);
void dmn_set_debug(bool d);

// This is a syslog()-like interface that will log
//  to stderr and/or syslog as appropriate depending
//  on daemon lifecycle, and is thread-safe.
DMN_F_NONNULLX(2) DMN_F_PRINTF(2,3)
void dmn_logger(int level, const char* fmt, ...);

// As above, but with a va_list interface to make it
//  easier to integrate with your own custom wrapper code.
DMN_F_NONNULLX(2)
void dmn_loggerv(int level, const char* fmt, va_list ap);

// The intended simple API for logging with 5 separate
//  function-call-like interfaces with different levels.
// The _fatal variant exits after emitting the logged statement,
//  and the _debug variant becomes a no-op when your application
//  is built with -DNDEBUG.
#define dmn_log_info(...) dmn_logger(LOG_INFO,__VA_ARGS__)
#define dmn_log_warn(...) dmn_logger(LOG_WARNING,__VA_ARGS__)
#define dmn_log_err(...) dmn_logger(LOG_ERR,__VA_ARGS__)
#define dmn_log_fatal(...) do {\
    dmn_logger(LOG_CRIT,__VA_ARGS__);\
    exit(57);\
} while(0)

#ifdef NDEBUG
#  ifdef DMN_HAVE_UNREACH_BUILTIN
#    define dmn_assert(expr) do { if (!(expr)) __builtin_unreachable(); } while (0)
#  else
#    define dmn_assert(expr) ((void)(0))
#  endif
#  define dmn_log_debug(...) ((void)(0))
#else
#  define dmn_assert(expr) do {\
     if(!(expr)) {\
       dmn_logger(LOG_CRIT,"Assertion '%s' failed in %s() at %s:%u",\
       #expr, __func__, __FILE__, __LINE__);\
       abort();\
     }\
} while(0)
#  define dmn_log_debug(...) do {\
     if(dmn_get_debug())\
         dmn_logger(LOG_DEBUG,__VA_ARGS__);\
     } while(0)
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
// Example:
//
//  const char* my_int_formatter(int foo) {
//     char* buf = dmn_fmtbuf_alloc(22);
//     if(snprintf(buf, 22, "%i", foo) >= 22)
//       log_fatal("BUG: Integer formatting did not fit buffer space!");
//     return buf;
//  }
//
//  dmn_log_warn("The integer had value %s!", my_int_formatter(someint));
//
char* dmn_fmtbuf_alloc(unsigned size);

// Reset (free allocations within) the format buffer.  Do not use this
//  with the normal log functions.  If you use the fmtbuf-based formatters
//  *outside* of a dmn log function, use this afterwards to reclaim the
//  space.
void dmn_fmtbuf_reset(void);

// Use this as a thread-safe strerror() within the arguments
//  of the above logging functions.  This is built on dmn_fmtbuf_alloc()
//  above and takes care of the difference between the GNU
//  and POSIX strerror_r() variants.
const char* dmn_strerror(const int errnum);

#endif // _DMN_H
