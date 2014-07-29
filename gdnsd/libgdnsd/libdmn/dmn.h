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

#ifndef DMN_H
#define DMN_H

#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/types.h>

// For sockaddr structs
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

// gcc function attributes
#if defined __GNUC__ && __GNUC__ >= 3 // gcc 3.0+
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
#  elif defined __clang__ // clang needs a separate check for unreach
#    if __has_builtin(__builtin_unreachable)
#      define DMN_HAVE_UNREACH_BUILTIN 1
#    endif
#  endif
#else
#  define DMN_F_PRINTF(X,Y)
#  define DMN_F_NONNULLX(...)
#  define DMN_F_NONNULL
#endif

/***
**** Daemonization interfaces
***/

// the pcall stuff isn't very well designed yet :P
typedef void(*dmn_func_vv_t)(void);
DMN_F_NONNULL
unsigned dmn_add_pcall(dmn_func_vv_t func);
void dmn_pcall(unsigned id);

// dmn_init1() *must* be called before *any* other libdmn function!
// debug: if false, all potential messages from dmn_log_debug() and
//    dmn_log_devdebug() will be suppressed.
// foreground: if true, the caller has no intention of actually daemonizing
//    and will stay in the foreground, attached to the terminal.
// stderr_info: if true, log_info() level messages wll be sent to stderr
//    when applicable.  Otherwise, only log_warn() and higher are sent
//    to stderr when applicable.
// name: the name of your daemon/program.  Will be used for log outputs
//    and pidfile naming.
// Immediately after init1(), only the logging APIs (dmn_log_*, dmn_logf_*
//    dmn_fmtbuf_*) are available.
DMN_F_NONNULL
void dmn_init1(bool debug, bool foreground, bool stderr_info, bool use_syslog, const char* name);

// dmn_init2() must be called after dmn_init1() and before dmn_init3().
// pid_dir: This is the application-specific(!)
//   directory within which the pidfile exists (or will be created).  This
//   should not be, for example, "/run" or "/var/run", it should be something
//   like "/run/somedaemond" or "/var/run/somedaemond".
//   Must be an absolute path (begins with /).  If NULL, none of the pidfile
//   -related calls (_stop, _status, _signal) will do anything useful, and
//   _acquire_pidfile() will be a no-op).
// Immediately after dmn_init2() the basic daemon-control APIs
//   (dmn_status(), dmn_stop(), and dmn_signal()) are now
//   available for use (in addition to the log APIs allowed
//   by init1()).
void dmn_init2(const char* pid_dir);

// dmn_init3 must be called after dmn_init2() and before dmn_fork().
// username: optional - if set, the daemon will drop privileges
//   to the uid/gid of this user during dmn_secure() later.  If
//   the daemon was not started as root, this option is ignored.
// restart: if true, much later in dmn_acquire_pidfile() this
//   daemon will try to kill any conflicting instance of itself
//   (same pidfile) before acquiring the pidfile.
void dmn_init3(const char* username, const bool restart);

// In !foreground cases, does the whole 9 yards of proper daemonization,
//   with execution continuing in the final daemonized child.  The original
//   process that invoked dmn_fork lingers in a private subroutine inside
//   libdmn as a "helper" until dmn_finish(), thus keeping the terminal
//   or manager process tied up until it can return a correct exit value,
//   and helping with any pcall operations as root post-privdrop.
// In "foreground" cases using privdrop *and* pcalls, this will not do
//   any real daemonization, but will fork a helper process to retain root
//   for pcall execution later, which terminates at dmn_finish().
// In foreground cases with no privdrop (or no pcalls), does basically nothing.
void dmn_fork(void);

// If we're executing as the root user, this will privdrop
//   us as indicated by the earlier username option to init3.
// If pid_dir doesn't exist and/or isn't owned by username (if defined),
//   and we're running as root, the pid_dir will be created and/or chowned
//   as necessary/possible before the loss of privilege to do so here in
//   this function.
void dmn_secure(void);

// If the restart parameter was set in init3, this function will first
//   check for a running daemon via the pidfile lock mechanism and terminate it.
// Regardless, it will then acquire a proper pidfile lock (or die trying),
//   if pid_dir was defined back in init3 (otherwise this call is a no-op).
// When this returns without dying, the current process is now the official
//   runtime instance of this daemon for e.g. dmn_status().
void dmn_acquire_pidfile(void);

// Finish the daemon startup procedure by signalling the helper process
//   (if any) to exit with status 0.  If your daemon doesn't make it
//   far enough to call this, the helper will exit non-zero to indicate
//   failure to the shell/manager/etc.
void dmn_finish(void);

// retval == 0 means daemon is not running
// retval != 0 means daemon is still running (and the pid is the retval)
pid_t dmn_status(void);

// This can delay up to 15s while waiting for the old daemon to stop.
// retval == 0 means daemon was not running, or was successfully killed.
// retval != 0 means daemon is still running (and the pid is the retval)
pid_t dmn_stop(void);

// Send an arbitrary signal to the running daemon, retval zero indicates
//   success, non-zero indicates failure.
int dmn_signal(int sig);

/***
**** Watchdog interfaces:
**** Basically, iff dmn_wdog_get_msec() returns a non-zero value
****   (when called during startup, after init1()),
****   the daemon should call dmn_wdog_ping() at approximate
****   intervals of that many milliseconds during runtime.
**** For now this only wraps systemd's watchdog mechanism,
****   but could be extended to other stuff in the future.
***/
unsigned dmn_wdog_get_msec(void);
void dmn_wdog_ping(void);

/***
**** Logging interfaces
***/

// This is used "internally" by dmn_log_debug(), but gdnsd has
//   use-cases for this and the others two getters below for
//   the special case of plugin_extmon's helper process.
bool dmn_get_debug(void);
bool dmn_get_foreground(void);

// This is a syslog()-like interface that will log
//  to stderr and/or syslog (or sd_journal) as appropriate
//  depending on daemon lifecycle, and is thread-safe.
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

// log_debug() messages will only be emitted if the runtime debug flag is set
#define dmn_log_debug(...) do {\
     if(dmn_get_debug())\
         dmn_logger(LOG_DEBUG,__VA_ARGS__);\
     } while(0)

// DMN_NO_FATAL_COVERAGE is to allow coverage testing to skip
//   over fatal conditions.  If your tests don't cover those
//   for pragmatic reasons, this considerably reduces line noise.
// Note that this is only going to work if your tests *never*
//   exercise a fatal case; it will probably cause random
//   bugs leading to test failures otherwise.
#ifdef DMN_NO_FATAL_COVERAGE
#  define dmn_log_fatal(...) ((void)(0))
#else
#  define dmn_log_fatal(...) do {\
     dmn_logger(LOG_CRIT,__VA_ARGS__);\
     exit(57);\
   } while(0)
#endif

// DMN_NO_UNREACH_BUILTIN is to work around gcov coverage testing, which
//   flags un-taken branches for all of the __builtin_unreachable()
// dmn_log_devdebug() is suppressed at the preprocessor level if -DNDEBUG
//   is set; use this in performance-critical areas (to avoid the runtime
//   check of the debug flag) or for spammy messages that only developers need
#ifdef NDEBUG
#  if defined(DMN_HAVE_UNREACH_BUILTIN) && !defined(DMN_NO_UNREACH_BUILTIN)
#    define dmn_assert(expr) do { if (!(expr)) __builtin_unreachable(); } while (0)
#  else
#    define dmn_assert(expr) ((void)(0))
#  endif
#  define dmn_log_devdebug(...) ((void)(0))
#else
#  define dmn_assert(expr) do {\
     if(!(expr)) {\
       dmn_logger(LOG_CRIT,"Assertion '%s' failed in %s() at %s:%u",\
       #expr, __func__, __FILE__, __LINE__);\
       abort();\
     }\
} while(0)
#  define dmn_log_devdebug(...) do {\
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
const char* dmn_logf_strerror(const int errnum);
#define dmn_logf_errno() dmn_logf_strerror(errno)

/******** network utility stuff ***********/

/* Socket union type */
// note anonymous union here, which gcc has supported
//  forever, and is now becoming standard in C11
typedef struct {
    union {
        struct sockaddr_in6 sin6;
        struct sockaddr_in  sin;
        struct sockaddr     sa;
    };
    socklen_t len;
} dmn_anysin_t;

// This is a maximum for the value of dmn_anysin_t.len
#define DMN_ANYSIN_MAXLEN sizeof(struct sockaddr_in6)

// max length of ASCII numeric ipv6 addr, with room for trailing NUL
#ifndef INET6_ADDRSTRLEN
#  define INET6_ADDRSTRLEN 46
#endif

// maximum addr:port ASCII representation from dmn_anysin2str below
// maximal form is "[...IPv6...]:12345\0"
#define DMN_ANYSIN_MAXSTR (1 + ((INET6_ADDRSTRLEN) - 1) + 1 + 1 + 5 + 1)

// transforms addr_txt + port_txt -> result using getaddrinfo(), setting result->len
// if "numeric_only" is true:
//    input text fields must be numeric, not hostnames or port names.
// if false, hostnames and port names are possible, which may result
//    in the libc doing DNS lookups and such on your behalf.
// caller must allocate result to sizeof(dmn_anysin_t)
// port_txt can be NULL, in which case the proto-specific port field will be zero
// retval is retval from getaddrinfo() itself (if non-zero, error occurred and
//   string representation is available from gai_strerror()).
// result is unaffected if an error occurs.
DMN_F_NONNULLX(1,3)
int dmn_anysin_getaddrinfo(const char* addr_txt, const char* port_txt, dmn_anysin_t* result, bool numeric_only);

// As above, but for parsing the address and port from a single string of the form addr:port,
//   where :port is optional, and addr may be surround by [] (to help with ipv6 [::1]:53 issues).
// Port defaults to unsigned arg "def_port" if not specified in the input string.
DMN_F_NONNULLX(1,3)
int dmn_anysin_fromstr(const char* addr_port_text, const unsigned def_port, dmn_anysin_t* result, bool numeric_only);

// Check if the sockaddr is the V4 or V6 ANY-address (0.0.0.0, or ::)
DMN_F_NONNULL
bool dmn_anysin_is_anyaddr(const dmn_anysin_t* asin);

// convert "asin" to numeric ASCII of the form "ipv4:port" or "[ipv6]:port"
// NULL input results in the string "(null)"
// note that buf *must* be pre-allocated to at least DMN_ANYSIN_MAXSTR bytes!
// return value is from getaddrinfo() (0 for success, otherwise pass to gai_strerror())
DMN_F_NONNULLX(2)
int dmn_anysin2str(const dmn_anysin_t* asin, char* buf);

// convert just the address portion to ASCII in "buf"
// NULL input results in the string "(null)"
// note that buf *must* be pre-allocated to at least INET6_ADDRSTRLEN bytes!
// return value is from getaddrinfo() (0 for success, otherwise pass to gai_strerror())
DMN_F_NONNULLX(2)
int dmn_anysin2str_noport(const dmn_anysin_t* asin, char* buf);

// Log-formatters for dmn_anysin_t + dmn_log_*(), which use the above...
const char* dmn_logf_anysin(const dmn_anysin_t* asin);
const char* dmn_logf_anysin_noport(const dmn_anysin_t* asin);

#endif // DMN_H
