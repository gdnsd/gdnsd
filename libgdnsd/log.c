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

#include <config.h>

#include <gdnsd/log.h>
#include <gdnsd/compiler.h>
#include <gdnsd/net.h>
#include <gdnsd/stats.h>
#include <gdnsd/paths.h>
#include <gdnsd/dname.h>

#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <pthread.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#ifdef HAVE_LIBUNWIND
#  define UNW_LOCAL_ONLY
#  include <libunwind.h>
#endif

/***********************************************************
***** Constants ********************************************
***********************************************************/

// Text log message prefixes when using stderr
static const char PFX_DEBUG[] = "debug: ";
static const char PFX_INFO[] = "info: ";
static const char PFX_WARNING[] = "warning: ";
static const char PFX_ERR[] = "error: ";
static const char PFX_CRIT[] = "fatal: ";
static const char PFX_UNKNOWN[] = "???: ";

// If passed format string is stupidly-long:
static const char FMT_TOO_LONG[] = "BUG: log format string is way too long!";

// Max length of an errno string (for our buffer purposes)
#define GDNSD_ERRNO_MAXLEN 256U

/***********************************************************
***** Static process-global data ***************************
***********************************************************/

static bool do_dbg = false;
static bool do_syslog = false;

/***********************************************************
***** Logging **********************************************
***********************************************************/

void gdnsd_log_set_debug(bool debug)
{
    do_dbg = debug;
}

bool gdnsd_log_get_debug(void)
{
    return do_dbg;
}

void gdnsd_log_set_syslog(bool set_syslog, const char* ident)
{
    if (!do_syslog && set_syslog)
        openlog(ident ? ident : PACKAGE_NAME, LOG_NDELAY | LOG_PID, LOG_DAEMON);
    do_syslog = set_syslog;
}

bool gdnsd_log_get_syslog(void)
{
    return do_syslog;
}

// 4K is the limit for all strings formatted by the log formatters to use in a
// single log message.  In other words, for any invocation like:
// log_warn("...", logf_dname(x), logf_strerror(y))
// The space allocated by logf_dname() + logf_strerror() must be <= 4096.
#define FMTBUF_SIZE 4096U
// fmtbuf_common is private to the two functions below it
static char* fmtbuf_common(const size_t size)
{
    static __thread size_t buf_used = 0;
    static __thread char buf[FMTBUF_SIZE];

    char* rv = NULL;

    // Allocate a chunk from the per-thread format buffer
    if (size) {
        if ((FMTBUF_SIZE - buf_used) >= size) {
            rv = &buf[buf_used];
            buf_used += size;
        }
    } else {
        // Reset (free allocations within) the format buffer,
        buf_used = 0;
    }

    return rv;
}

// Public (including this file) interfaces to fmtbuf_common()

char* gdnsd_fmtbuf_alloc(const size_t size)
{
    if (!size)
        log_fatal("BUG: fmtbuf alloc of zero bytes");
    char* rv = fmtbuf_common(size);
    if (!rv)
        log_fatal("BUG: format buffer exhausted");
    return rv;
}

void gdnsd_fmtbuf_reset(void)
{
    fmtbuf_common(0);
}

// gdnsd_logf_strerror(), which hides GNU or POSIX strerror_r() thread-safe
//  errno->string translation behind a more strerror()-like interface
//  using gdnsd_fmtbuf_alloc()
const char* gdnsd_logf_strerror(const int errnum)
{
    char tmpbuf[GDNSD_ERRNO_MAXLEN];
    const char* tmpbuf_ptr;

#ifdef STRERROR_R_CHAR_P
    // GNU-style
    tmpbuf_ptr = strerror_r(errnum, tmpbuf, GDNSD_ERRNO_MAXLEN);
#else
    // POSIX style (+ older glibc bug-compat)
    int rv = strerror_r(errnum, tmpbuf, GDNSD_ERRNO_MAXLEN);
    if (rv) {
        if (rv == EINVAL || (rv < 0 && errno == EINVAL))
            snprintf(tmpbuf, GDNSD_ERRNO_MAXLEN, "Invalid errno: %i", errnum);
        else
            log_fatal("strerror_r(,,%u) failed", GDNSD_ERRNO_MAXLEN);
    }
    tmpbuf_ptr = tmpbuf;
#endif

    const unsigned len = strlen(tmpbuf_ptr) + 1;
    char* buf = gdnsd_fmtbuf_alloc(len);
    memcpy(buf, tmpbuf_ptr, len);
    return buf;
}

GDNSD_DIAG_PUSH_IGNORED("-Wformat-nonliteral")

static void gdnsd_loggerv(int level, const char* fmt, va_list ap)
{
    if (do_syslog) {
        vsyslog(level, fmt, ap);
        gdnsd_fmtbuf_reset();
        return;
    }

    const char* pfx;

    switch (level) {
    case LOG_DEBUG:
        pfx = PFX_DEBUG;
        break;
    case LOG_INFO:
        pfx = PFX_INFO;
        break;
    case LOG_WARNING:
        pfx = PFX_WARNING;
        break;
    case LOG_ERR:
        pfx = PFX_ERR;
        break;
    case LOG_CRIT:
        pfx = PFX_CRIT;
        break;
    default:
        pfx = PFX_UNKNOWN;
        break;
    }

    char f[1024];
    const int snp_rv = snprintf(f, 1024, "%s%s\n", pfx, fmt);
    if (unlikely(snp_rv >= 1024))
        memcpy(f, FMT_TOO_LONG, sizeof(FMT_TOO_LONG));

    va_list apcpy;
    va_copy(apcpy, ap);
    vdprintf(STDERR_FILENO, f, apcpy);
    va_end(apcpy);

    gdnsd_fmtbuf_reset();
}

void gdnsd_logger(int level, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    gdnsd_loggerv(level, fmt, ap);
    va_end(ap);
}

GDNSD_DIAG_POP

#define BT_SIZE 2048LU
#define BT_MAX_NAME 60LU

const char* gdnsd_logf_bt(void)
{
#ifdef HAVE_LIBUNWIND
    char* tbuf = gdnsd_fmtbuf_alloc(BT_SIZE);
    size_t tbuf_pos = 0;
    tbuf[tbuf_pos] = '\0'; // in case no output below

    unw_cursor_t cursor;
    unw_context_t uc;
    unw_getcontext(&uc);
    unw_init_local(&cursor, &uc);

    while (tbuf_pos < BT_SIZE && unw_step(&cursor) > 0) {
        unw_word_t ip = 0;
        unw_word_t sp = 0;
        unw_word_t offset = 0;
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        if (!ip)
            break;
        unw_get_reg(&cursor, UNW_REG_SP, &sp);

        char cbuf[BT_MAX_NAME];
        cbuf[0] = '\0'; // in case no output below
        (void)unw_get_proc_name(&cursor, cbuf, BT_MAX_NAME, &offset);

        int snp_rv = snprintf(&tbuf[tbuf_pos],
                              (BT_SIZE - tbuf_pos), "\n[ip:%#.16lx sp:%#.16lx] %s+%#lx",
                              (unsigned long)ip, (unsigned long)sp,
                              cbuf, (unsigned long)offset);
        if (snp_rv < 0 || (size_t)snp_rv >= (BT_SIZE - tbuf_pos))
            break;
        tbuf_pos += (size_t)snp_rv;
    }
    return tbuf;
#else
    return "(no libunwind)";
#endif
}

static const char generic_nullstr[] = "(null)";

const char* gdnsd_logf_ipv6(const uint8_t* ipv6)
{
    gdnsd_anysin_t tempsin;
    memset(&tempsin, 0, sizeof(tempsin));
    tempsin.sa.sa_family = AF_INET6;
    memcpy(tempsin.sin6.sin6_addr.s6_addr, ipv6, 16);
    tempsin.len = sizeof(struct sockaddr_in6);
    return gdnsd_logf_anysin_noport(&tempsin);
}

const char* gdnsd_logf_in6a(const struct in6_addr* in6a)
{
    return gdnsd_logf_ipv6(in6a->s6_addr);
}

const char* gdnsd_logf_dname(const uint8_t* dname)
{
    if (!dname)
        return generic_nullstr;

    char tmpbuf[1024];
    const unsigned len = gdnsd_dname_to_string(dname, tmpbuf);
    char* dnbuf = gdnsd_fmtbuf_alloc(len);
    memcpy(dnbuf, tmpbuf, len);
    return dnbuf;
}
