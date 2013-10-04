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

#include "config.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <pthread.h>

#include "dmn.h"

#if ! HAVE_DECL_FPUTS_UNLOCKED
#define fputs_unlocked fputs
#endif

#if ! HAVE_DECL_FFLUSH_UNLOCKED
#define fflush_unlocked fflush
#endif

// When the daemon is built in debug mode (!defined NDEBUG),
//  *and* this flag is set to true by the daemon,
//  dmn_log_debug() emits output
static bool dmn_debug = false;

// whether INFO -level messages get sent to stderr in
//   non-debug builds.
static bool send_stderr_info = true;

#ifndef NDEBUG
// Log message prefixes when using stderr
static const char* pfx_debug = " debug: ";
static const char* pfx_info = " info: ";
static const char* pfx_warning = " warning: ";
static const char* pfx_err = " error: ";
static const char* pfx_crit = " fatal: ";
static const char* pfx_unknown = " ???: ";
#endif

// current openlog() identifier, for stderr copies + syslog
static char* our_logname = NULL;

/*********************************************************************/
/*** fmtbuf code *****************************************************/
/*********************************************************************/

// These define the buffer count, size of first buffer, and shift
//   value sets how fast the buffer sizes grow
// At these settings (4, 10, 2), the buffer sizes are:
//   1024, 4096, 16384, 65536
#define FMTBUF_CT 4U
#define FMTBUF_START 10U
#define FMTBUF_STEP 2U

typedef struct {
    unsigned used[FMTBUF_CT];
    char* bufs[FMTBUF_CT];
} fmtbuf_t;

static pthread_key_t fmtbuf_key;
static pthread_once_t fmtbuf_key_once = PTHREAD_ONCE_INIT;
static void fmtbuf_make_key(void) { pthread_key_create(&fmtbuf_key, NULL); }

// Allocate a chunk from the format buffer
// Allocates the buffer itself on first use per-thread
char* dmn_fmtbuf_alloc(unsigned size) {
    fmtbuf_t* fmtbuf;
    pthread_once(&fmtbuf_key_once, fmtbuf_make_key);
    fmtbuf = pthread_getspecific(fmtbuf_key);
    if(!fmtbuf) {
        fmtbuf = calloc(1, sizeof(fmtbuf_t));
        pthread_setspecific(fmtbuf_key, (void*)fmtbuf);
    }

    char* rv = NULL;
    unsigned bsize = 1U << FMTBUF_START;
    for(unsigned i = 0; i < FMTBUF_CT; i++) {
        if(!fmtbuf->bufs[i])
            fmtbuf->bufs[i] = malloc(bsize);
        if((bsize - fmtbuf->used[i]) >= size) {
            rv = &fmtbuf->bufs[i][fmtbuf->used[i]];
            fmtbuf->used[i] += size;
            break;
        }
        bsize <<= FMTBUF_STEP;
    }

    if(!rv)
        dmn_log_fatal("BUG: format buffer exhausted");
    return rv;
}

// Reset (free allocations within) the format buffer,
//  but do not trigger initial allocation in the process
void dmn_fmtbuf_reset(void) {
    fmtbuf_t* fmtbuf;
    pthread_once(&fmtbuf_key_once, fmtbuf_make_key);
    fmtbuf = pthread_getspecific(fmtbuf_key);
    if(fmtbuf)
        for(unsigned i = 0; i < FMTBUF_CT; i++)
            fmtbuf->used[i] = 0;
}

/**********************************************************************
* dmn_strerror(), which hides GNU or POSIX strerror_r() thread-safe
* errno->string translation behind a more strerror()-like interface
* using dmn_fmtbuf_alloc()
***********************************************************************/

#define ERRNO_MAXLEN 256 // Max length of an errno string
const char* dmn_strerror(const int errnum) {
    char* buf = dmn_fmtbuf_alloc(ERRNO_MAXLEN);

#ifdef STRERROR_R_CHAR_P
    // GNU-style
    buf = strerror_r(errnum, buf, ERRNO_MAXLEN);
#else
    // POSIX style
    if(strerror_r(errnum, buf, ERRNO_MAXLEN)) {
        if(errno == EINVAL)
            snprintf(buf, 256, "Invalid errno: %i", errnum);
        else
            dmn_log_fatal("strerror_r(,,256) failed");
    }
#endif

    return buf;
}

static bool dmn_syslog_alive = false;
void dmn_start_syslog(void) {
    openlog(our_logname, LOG_NDELAY|LOG_PID, LOG_DAEMON);
    dmn_syslog_alive = true;
}

// Copy of stderr, so that we can properly /dev/null
//   the real stderr and still write to this for
//   a bit to report late errors (we can't just wait
//   to /dev/null the real stderr, because /dev/null
//   is gone after chroot...).
static FILE* alt_stderr = NULL;
void dmn_init_log(const char* logname, const bool stderr_info) {
    send_stderr_info = stderr_info;
    our_logname = strdup(logname);
    alt_stderr = fdopen(dup(fileno(stderr)), "w");
    if(!alt_stderr) {
        perror("Failed to fdopen(dup(fileno(stderr)))");
        abort();
    }
}

int dmn_log_get_alt_stderr_fd(void) {
    return fileno(alt_stderr);
}

void dmn_log_set_alt_stderr(const int fd) {
    alt_stderr = fdopen(fd, "w");
}

void dmn_log_close_alt_stderr(void) {
    fclose(alt_stderr);
    alt_stderr = NULL;
}

/*****************************************************************/
/*** The core logging funcs: dmn_loggerv and dmn_logger **********/
/*****************************************************************/

#pragma GCC diagnostic ignored "-Wformat-nonliteral"

void dmn_loggerv(int level, const char* fmt, va_list ap) {
    if(alt_stderr) {
#ifndef NDEBUG

        time_t t = time(NULL);
        struct tm tmp;
        localtime_r(&t, &tmp);
        char tstamp[10];
        if(!strftime(tstamp, 10, "%T ", &tmp))
            strcpy(tstamp, "--:--:-- ");

#  if defined SYS_gettid && !defined __APPLE__
        pid_t tid = syscall(SYS_gettid);
        char tidbuf[16];
        snprintf(tidbuf, 16, " [%i]", tid);
#  endif

        const char* pfx;
        switch(level) {
            case LOG_DEBUG: pfx = pfx_debug; break;
            case LOG_INFO: pfx = pfx_info; break;
            case LOG_WARNING: pfx = pfx_warning; break;
            case LOG_ERR: pfx = pfx_err; break;
            case LOG_CRIT: pfx = pfx_crit; break;
            default: pfx = pfx_unknown; break;
        }
        flockfile(alt_stderr);
        fputs_unlocked(tstamp, alt_stderr);
        if(our_logname)
            fputs_unlocked(our_logname, alt_stderr);
#  if defined SYS_gettid && !defined __APPLE__
        fputs_unlocked(tidbuf, alt_stderr);
#  endif
        fputs_unlocked(pfx, alt_stderr);
        va_list apcpy;
        va_copy(apcpy, ap);
        vfprintf(alt_stderr, fmt, apcpy);
        va_end(apcpy);
        putc_unlocked('\n', alt_stderr);
        fflush_unlocked(alt_stderr);
        funlockfile(alt_stderr);

#else // NDEBUG
        if(level != LOG_INFO || send_stderr_info) {
            va_list apcpy;
            va_copy(apcpy, ap);
            flockfile(alt_stderr);
            vfprintf(alt_stderr, fmt, apcpy);
            va_end(apcpy);
            putc_unlocked('\n', alt_stderr);
            fflush_unlocked(alt_stderr);
            funlockfile(alt_stderr);
        }
#endif // NDEBUG
    }

    if(dmn_syslog_alive)
        vsyslog(level, fmt, ap);

    dmn_fmtbuf_reset();
}

void dmn_logger(int level, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    dmn_loggerv(level, fmt, ap);
    va_end(ap);
}

bool dmn_get_debug(void) { return dmn_debug; }
void dmn_set_debug(bool d) { dmn_debug = d; }
