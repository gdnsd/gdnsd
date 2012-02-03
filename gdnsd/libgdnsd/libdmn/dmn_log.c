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
#include <sys/syscall.h>

#ifndef TLS
#include <pthread.h>
#endif

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

// Length of the whole format buffer
#ifndef DMN_FMTBUF_SIZE
#define DMN_FMTBUF_SIZE 4096U
#endif

// Log message prefixes when using stderr
static const char* pfx_debug = "debug: ";
static const char* pfx_info = "info: ";
static const char* pfx_warning = "warning: ";
static const char* pfx_err = "error: ";
static const char* pfx_crit = "fatal: ";
static const char* pfx_unknown = "???: ";

/*********************************************************************/
/*** fmtbuf code *****************************************************/
/*********************************************************************/

typedef struct {
    unsigned used;
    char buf[DMN_FMTBUF_SIZE];
} fmtbuf_t;

#ifdef TLS
static TLS fmtbuf_t* fmtbuf = NULL;
#else
static pthread_key_t fmtbuf_key;
static pthread_once_t fmtbuf_key_once = PTHREAD_ONCE_INIT;
static void fmtbuf_make_key(void) { pthread_key_create(&fmtbuf_key, NULL); }
#endif

// Allocate a chunk from the format buffer
// Allocates the buffer itself on first use per-thread
char* dmn_fmtbuf_alloc(unsigned size) {
#ifndef TLS
    fmtbuf_t* fmtbuf;
    pthread_once(&fmtbuf_key_once, fmtbuf_make_key);
    if((fmtbuf = pthread_getspecific(fmtbuf_key)) == NULL) {
        fmtbuf = calloc(1, sizeof(fmtbuf_t));
        pthread_setspecific(fmtbuf_key, (void*)fmtbuf);
    }
#else
    if(!fmtbuf)
        fmtbuf = calloc(1, sizeof(fmtbuf_t));
#endif
    if(fmtbuf->used + size > DMN_FMTBUF_SIZE)
        dmn_log_fatal("BUG: format buffer exhausted");
    char* retval = &fmtbuf->buf[fmtbuf->used];
    fmtbuf->used += size;
    return retval;
}

// Reset (free allocations within) the format buffer,
//  but do not trigger initial allocation in the process
void dmn_fmtbuf_reset(void) {
#ifndef TLS
    fmtbuf_t* fmtbuf;
    pthread_once(&fmtbuf_key_once, fmtbuf_make_key);
    if((fmtbuf = pthread_getspecific(fmtbuf_key)))
#else
    if(fmtbuf)
#endif
        fmtbuf->used = 0;
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

/*****************************************************************/
/*** The core logging funcs: dmn_loggerv and dmn_logger **********/
/*****************************************************************/

void dmn_loggerv(int level, const char* fmt, va_list ap) {
    dmn_assert(fmt);

    if(dmn_is_daemonized()) {
        vsyslog(level, fmt, ap);
    }
    else {
        time_t t = time(NULL);
        struct tm tmp;
        localtime_r(&t, &tmp);
        char tstamp[10];
        if(!strftime(tstamp, 10, "%T ", &tmp))
            strcpy(tstamp, "--:--:-- ");

#if defined SYS_gettid && !defined __APPLE__
        pid_t tid = syscall(SYS_gettid);
        char tidbuf[16];
        snprintf(tidbuf, 16, "[%i] ", tid);
#endif

        const char* pfx;
        switch(level) {
            case LOG_DEBUG: pfx = pfx_debug; break;
            case LOG_INFO: pfx = pfx_info; break;
            case LOG_WARNING: pfx = pfx_warning; break;
            case LOG_ERR: pfx = pfx_err; break;
            case LOG_CRIT: pfx = pfx_crit; break;
            default: pfx = pfx_unknown; break;
        }
        flockfile(stderr);
        fputs_unlocked(tstamp, stderr);
#if defined SYS_gettid && !defined __APPLE__
        fputs_unlocked(tidbuf, stderr);
#endif
        fputs_unlocked(pfx, stderr);
        vfprintf(stderr, fmt, ap);
        putc_unlocked('\n', stderr);
        fflush_unlocked(stderr);
        funlockfile(stderr);
    }

    dmn_fmtbuf_reset();
}

void dmn_logger(int level, const char* fmt, ...) {
    dmn_assert(fmt);
    va_list ap;
    va_start(ap, fmt);
    dmn_loggerv(level, fmt, ap);
    va_end(ap);
}

bool dmn_get_debug(void) { return dmn_debug; }
void dmn_set_debug(bool d) { dmn_debug = d; }
