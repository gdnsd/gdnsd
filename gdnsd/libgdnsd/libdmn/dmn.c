/* Copyright © 2014 Brandon L Black <blblack@gmail.com>
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
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#ifdef USE_SYSTEMD
   // because we funnel through a function here, the location
   // info would be useless repetitive line noise.
#  define SD_JOURNAL_SUPPRESS_LOCATION 1
#  include <systemd/sd-daemon.h>
#  include <systemd/sd-journal.h>
#endif

#include "dmn.h"

/***********************************************************
***** Defines **********************************************
***********************************************************/

// Since we explicitly lock the output stream,
//   these are merely for performance if they exist...
#if ! HAVE_DECL_FPUTS_UNLOCKED
#  define fputs_unlocked fputs
#endif
#if ! HAVE_DECL_FFLUSH_UNLOCKED
#  define fflush_unlocked fflush
#endif

// These control the growth of the log formatting-buffer space
// These define the buffer count, size of first buffer, and shift
//   value sets how fast the buffer sizes grow
// At these settings (4, 10, 2), the buffer sizes are:
//   1024, 4096, 16384, 65536
#define FMTBUF_CT     4U
#define FMTBUF_START 10U
#define FMTBUF_STEP   2U

/***********************************************************
***** Constants ********************************************
***********************************************************/

// Log message prefixes when using stderr
static const char PFX_DEBUG[] = "debug: ";
static const char PFX_INFO[] = "info: ";
static const char PFX_WARNING[] = "warning: ";
static const char PFX_ERR[] = "error: ";
static const char PFX_CRIT[] = "fatal: ";
static const char PFX_UNKNOWN[] = "???: ";

// Max length of an errno string (for our buffer purposes)
static const size_t DMN_ERRNO_MAXLEN = 256U;

// Standard file-permissions constants
static const mode_t PERMS750   = (S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP);
static const mode_t PERMS640   = (S_IRUSR|S_IWUSR|S_IRGRP);
static const mode_t PERMS_MASK = (S_IRWXU|S_IRWXG|S_IRWXO);

// These are phases used to enforce a strict ordering
//   of operations and dependencies between the functions in this file
// PHASE0_UNINIT is the default at library load, and the
//   code only allows forward, serial movement through this list
//   one entry at a time.
// Note that in PHASE0_UNINIT, *nothing* is valid to call except
//   dmn_init1(), including all of the log/assert functions.
typedef enum {
    PHASE0_UNINIT      = 0,
    PHASE1_INIT1,
    PHASE2_INIT2,
    PHASE3_INIT3,
    PHASE4_FORKED,
    PHASE5_SECURED,
    PHASE6_PIDLOCKED,
    PHASE7_FINISHED,
} phase_t;

// the functions which move the state forward
//   to each of the above phases, for use in BUG output
static const char* phase_actor[] = {
    NULL,
    "dmn_init1()",
    "dmn_init2()",
    "dmn_init3()",
    "dmn_fork()",
    "dmn_secure()",
    "dmn_acquire_pidfile()",
    "dmn_finish()",
};

// makes sides of int[] from pipe() clearer
static const unsigned PIPE_RD = 0;
static const unsigned PIPE_WR = 1;

/***********************************************************
***** Static per-thread data *******************************
***********************************************************/

// This is our log-formatting buffer.  It holds multiple buffers
//   of increasing size (see constants) above which are allocated
//   per-thread as-needed, permanently for the life of the thread.
typedef struct {
    unsigned used[FMTBUF_CT];
    char* bufs[FMTBUF_CT];
} fmtbuf_t;

static __thread fmtbuf_t fmtbuf = {{0},{NULL}};

/***********************************************************
***** Static process-global data ***************************
***********************************************************/

typedef struct {
    // directly supplied by caller
    bool  debug;
    bool  foreground;
    bool  stderr_info;
    bool  restart;
    char* name;
    char* username;

    // calculated/inferred/discovered
    bool     invoked_as_root; // !geteuid() during init1()
    bool     will_privdrop;   // invoked_as_root && non-null username from init3()
    bool     need_helper;     // depends on foreground, will_privdrop, and pcall registration - set in _fork
    bool     use_systemd;     // sd_booted() && !isatty(stdin) && !foreground (we think systemd ran us directly)
    uid_t    uid;             // uid of username from init3()
    gid_t    gid;             // gid of username from init3()
    char*    pid_dir;         // from init2()
    char*    pid_file;        // depends on pid_dir + name
    unsigned wdog_msec;       // watchdog milliseconds, system-dependent (systemd), set in init1
} params_t;

static params_t params = {
    .debug           = false,
    .foreground      = false,
    .stderr_info     = true,
    .restart         = false,
    .name            = NULL,
    .username        = NULL,
    .invoked_as_root = false,
    .will_privdrop   = false,
    .need_helper     = false,
    .use_systemd     = false,
    .uid             = 0,
    .gid             = 0,
    .pid_dir         = NULL,
    .pid_file        = NULL,
    .wdog_msec       = 0,
};

typedef struct {
    phase_t phase;
    bool    syslog_alive;
    int     pipe_to_helper[2];
    int     pipe_from_helper[2];
    FILE*   stderr_out;
} state_t;

static state_t state = {
    .phase            = PHASE0_UNINIT,
    .syslog_alive     = false,
    .pipe_to_helper   = { -1, -1 },
    .pipe_from_helper = { -1, -1 },
    .stderr_out       = NULL,
};

// pcall funcptrs
static dmn_func_vv_t* pcalls = NULL;
static unsigned num_pcalls = 0;

/***********************************************************
***** API usage checks *************************************
***********************************************************/

#define phase_check(_after, _before, _unique) do { \
    if(state.phase == PHASE0_UNINIT) { \
        fprintf(stderr, "BUG: dmn_init1() must be called before any other libdmn function!\n"); \
        abort(); \
    } \
    if(_unique) {\
        static unsigned _call_count = 0; \
        if(++_call_count > 1) \
            dmn_log_fatal("BUG: %s can only be called once and was already called!", __func__); \
    } \
    if(_after && state.phase < _after) \
        dmn_log_fatal("BUG: %s must be called after %s", __func__, phase_actor[_after]); \
    if(_before && state.phase >= _before) \
        dmn_log_fatal("BUG: %s must be called before %s", __func__, phase_actor[_before]); \
} while(0);

/***********************************************************
***** Logging **********************************************
***********************************************************/

// Allocate a chunk from the per-thread format buffer
char* dmn_fmtbuf_alloc(unsigned size) {
    phase_check(0, 0, 0);
    char* rv = NULL;

    unsigned bsize = 1U << FMTBUF_START;
    for(unsigned i = 0; i < FMTBUF_CT; i++) {
        if(!fmtbuf.bufs[i]) {
            fmtbuf.bufs[i] = malloc(bsize);
            if(!fmtbuf.bufs[i])
                dmn_log_fatal("memory allocation failure!");
        }
        if((bsize - fmtbuf.used[i]) >= size) {
            rv = &fmtbuf.bufs[i][fmtbuf.used[i]];
            fmtbuf.used[i] += size;
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
    phase_check(0, 0, 0);

    for(unsigned i = 0; i < FMTBUF_CT; i++)
        fmtbuf.used[i] = 0;
}

// dmn_logf_strerror(), which hides GNU or POSIX strerror_r() thread-safe
//  errno->string translation behind a more strerror()-like interface
//  using dmn_fmtbuf_alloc()
const char* dmn_logf_strerror(const int errnum) {
    phase_check(0, 0, 0);

    char tmpbuf[DMN_ERRNO_MAXLEN];
    const char* tmpbuf_ptr;

#ifdef STRERROR_R_CHAR_P
    // GNU-style
    tmpbuf_ptr = strerror_r(errnum, tmpbuf, DMN_ERRNO_MAXLEN);
#else
    // POSIX style (+ older glibc bug-compat)
    int rv = strerror_r(errnum, tmpbuf, DMN_ERRNO_MAXLEN);
    if(rv) {
        if(rv == EINVAL || (rv < 0 && errno == EINVAL))
            snprintf(tmpbuf, DMN_ERRNO_MAXLEN, "Invalid errno: %i", errnum);
        else
            dmn_log_fatal("strerror_r(,,%zu) failed", DMN_ERRNO_MAXLEN);
    }
    tmpbuf_ptr = tmpbuf;
#endif

    const unsigned len = strlen(tmpbuf_ptr) + 1;
    char* buf = dmn_fmtbuf_alloc(len);
    memcpy(buf, tmpbuf_ptr, len);
    return buf;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"

void dmn_loggerv(int level, const char* fmt, va_list ap) {
    phase_check(0, 0, 0);

#ifdef USE_SYSTEMD
    if(params.use_systemd) {
        sd_journal_printv(level, fmt, ap);
    }
    else {
#endif

        if(state.stderr_out && (level != LOG_INFO || params.stderr_info)) {
            const char* pfx;
            switch(level) {
                case LOG_DEBUG: pfx = PFX_DEBUG; break;
                case LOG_INFO: pfx = PFX_INFO; break;
                case LOG_WARNING: pfx = PFX_WARNING; break;
                case LOG_ERR: pfx = PFX_ERR; break;
                case LOG_CRIT: pfx = PFX_CRIT; break;
                default: pfx = PFX_UNKNOWN; break;
            }

            va_list apcpy;
            va_copy(apcpy, ap);
            flockfile(state.stderr_out);
            fputs_unlocked(pfx, state.stderr_out);
            vfprintf(state.stderr_out, fmt, apcpy);
            va_end(apcpy);
            putc_unlocked('\n', state.stderr_out);
            fflush_unlocked(state.stderr_out);
            funlockfile(state.stderr_out);
        }

#ifndef USE_SYSTEMD
        if(state.syslog_alive)
            vsyslog(level, fmt, ap);
#endif

#ifdef USE_SYSTEMD
    }
#endif

    dmn_fmtbuf_reset();
}

void dmn_logger(int level, const char* fmt, ...) {
    phase_check(0, 0, 0);
    va_list ap;
    va_start(ap, fmt);
    dmn_loggerv(level, fmt, ap);
    va_end(ap);
}

#pragma GCC diagnostic pop

bool dmn_get_debug(void) { phase_check(0, 0, 0); return params.debug; }
bool dmn_get_foreground(void) { phase_check(0, 0, 0); return params.foreground; }

/***********************************************************
***** Private subroutines used by daemonization ************
***********************************************************/

// The terminal signal SIGTERM is sent exactly once, then
//  the status of the daemon is polled repeatedly at 100ms
//  delay intervals
// Function returns when either the process is dead or
//  our delays all expired.  Total timeout is 15s.
// True retval indicates daemon is still running.
// It is critical that this function doesn't contain any
//   faliure-points (dmn_assert or dmn_log_fatal), see
//   the systemd restart code in _acquire_pidfile().
static bool terminate_pid_and_wait(pid_t pid) {
    bool still_running = false;

    if(!kill(pid, SIGTERM)) {
        still_running = true;
        const struct timespec ts = { 0, 100000000 };
        unsigned tries = 150;
        while(tries--) {
            nanosleep(&ts, NULL);
            if(kill(pid, 0)) {
                still_running = false;
                break;
            }
        }
    }

    return still_running;
}

// create a pipe with FD_CLOEXEC and fatal error-checking built in
static void pipe_create(int pipefd[2]) {
    if(pipe(pipefd))
        dmn_log_fatal("pipe() failed: %s", dmn_logf_errno());
    if(fcntl(pipefd[PIPE_RD], F_SETFD, FD_CLOEXEC))
        dmn_log_fatal("fcntl(FD_CLOEXEC) on pipe fd failed: %s", dmn_logf_errno());
    if(fcntl(pipefd[PIPE_WR], F_SETFD, FD_CLOEXEC))
        dmn_log_fatal("fcntl(FD_CLOEXEC) on pipe fd failed: %s", dmn_logf_errno());
}
// reset pipe fds to -1 on close
static void close_pipefd(int* fd_p) {
    if(close(*fd_p))
        dmn_log_fatal("close() of pipe() fd failed: %s", dmn_logf_errno());
    *fd_p = -1;
}

// the helper process executes here and does not return
static void helper_proc(const pid_t middle_pid) {
    dmn_assert(state.phase == PHASE3_INIT3);

    // if middle_pid is set, we're doing a full
    //   fork->setsid->fork, and middle_pid is
    //   the pid of the middle process.  Clean it
    //   up with waitpid before continuing.
    if(middle_pid)
        waitpid(middle_pid, NULL, 0);

    const int readpipe = state.pipe_to_helper[PIPE_RD];
    const int writepipe = state.pipe_from_helper[PIPE_WR];
    dmn_assert(readpipe >= 0);
    dmn_assert(writepipe >= 0);

    int exitval = 1;

    do {
        uint8_t msg;
        int readrv;
        do {
            errno = 0;
            readrv = read(readpipe, &msg, 1);
        } while(errno == EAGAIN || errno == EWOULDBLOCK);

        if(errno || readrv != 1)
            break; // pipe close or other error
        else if(msg >= 128U)
            break; // high-bit reserved for responses!
        else if(msg == 0U) // daemon success
            exitval = 0;
        else if(msg > 63U) // pcall
            pcalls[msg - 64U]();
        else
            break;
        errno = 0;
        msg |= 128U; // set high-bit for response
        int writerv = write(writepipe, &msg, 1);
        if(errno || writerv != 1)
            break;
    } while(1);

    // _exit avoids any atexit that may have been installed before fork
    _exit(exitval);
}

// this isn't meant to be high-speed or elegant, but it saves
//   some repetitive string-mod code elsewhere.
static char* str_combine_n(const unsigned count, ...) {
    dmn_assert(count > 1);

    struct {
        const char* ptr;
        unsigned len;
    } strs[count];

    unsigned oal = 1; // for terminating NUL
    va_list ap;
    va_start(ap, count);
    for(unsigned i = 0; i < count; i++) {
        const char* s = va_arg(ap, char*);
        const unsigned l = strlen(s);
        strs[i].ptr = s;
        strs[i].len = l;
        oal += l;
    }
    va_end(ap);

    char* out = malloc(oal);
    if(!out)
        dmn_log_fatal("memory allocation failure!");
    char* cur = out;
    for(unsigned i = 0; i < count; i++) {
        memcpy(cur, strs[i].ptr, strs[i].len);
        cur += strs[i].len;
    }
    *cur = '\0';

    return out;
}

/***********************************************************
***** Watchdog interface ***********************************
***********************************************************/

unsigned dmn_wdog_get_msec(void) {
    phase_check(0, 0, 0);
    return params.wdog_msec;
}

void dmn_wdog_ping(void) {
    phase_check(0, 0, 0);
#ifdef USE_SYSTEMD
    sd_notify(0, "WATCHDOG=1");
#endif
}

/***********************************************************
***** Daemonization ****************************************
***********************************************************/

void dmn_init1(bool debug, bool foreground, bool stderr_info, bool use_syslog, const char* name) {
#ifdef USE_SYSTEMD
    bool sdbooted = (sd_booted() < 0) ? false : true;
    params.use_systemd = sdbooted && !isatty(fileno(stdin)) && !foreground;
#endif

    // This lets us log to normal stderr for now
    state.stderr_out = params.use_systemd ? NULL : stderr;

    params.debug = debug;
    params.foreground = foreground;
    params.stderr_info = stderr_info;
    params.name = strdup(name);

    // set phase early so that dmn_log calls work!
    const phase_t prev_phase = state.phase;
    state.phase = PHASE1_INIT1;

    if(prev_phase != PHASE0_UNINIT)
        dmn_log_fatal("BUG: dmn_init1() can only be called once!");

    if(!name)
        dmn_log_fatal("BUG: dmn_init1(): argument 'name' is *required*");

    if(!params.use_systemd) {
        if(!params.foreground) {
            FILE* stderr_copy = fdopen(dup(fileno(stderr)), "w");
            if(!stderr_copy)
                dmn_log_fatal("Failed to fdopen(dup(fileno(stderr))): %s", dmn_logf_errno());
            state.stderr_out = stderr_copy;
        }

        if(use_syslog) {
            openlog(params.name, LOG_NDELAY|LOG_PID, LOG_DAEMON);
            state.syslog_alive = true;
        }
    }

#if defined USE_SYSTEMD && HAVE_DECL_SD_WATCHDOG_ENABLED && defined HAVE_SD_WATCHDOG_ENABLED
    if(params.use_systemd) {
        uint64_t usec;
        int we_rv = sd_watchdog_enabled(1, &usec);
        if(we_rv > 0) {
            dmn_assert(usec);
            params.wdog_msec = (usec >> 1) / 1000; // halve the time and truncate to ms
            if(params.wdog_msec < 10) // sub-10ms watchdog times are probably dangerous
                params.wdog_msec = 10;
            if(params.wdog_msec > 3600000) // >1hr also seems silly
                params.wdog_msec = 3600000;
        }
        else if(we_rv < 0) {
            dmn_log_err("sd_watchdog_enabled() failed: %s", dmn_logf_strerror(-we_rv));
        }
    }
#endif // USE_SYSTEMD

    params.invoked_as_root = !geteuid();
}

void dmn_init2(const char* pid_dir) {
    phase_check(PHASE1_INIT1, PHASE3_INIT3, 1);

    if(pid_dir) {
        if(pid_dir[0] != '/')
            dmn_log_fatal("pid directory path must be absolute!");
        params.pid_dir = strdup(pid_dir);
        params.pid_file = str_combine_n(4, pid_dir, "/", params.name, ".pid");
    }

    state.phase = PHASE2_INIT2;
}

pid_t dmn_status(void) {
    phase_check(PHASE2_INIT2, PHASE6_PIDLOCKED, 0);

    if(!params.pid_file)
        return 0;

    const int pidfd = open(params.pid_file, O_RDONLY);
    if(pidfd == -1) {
        if (errno == ENOENT) return 0;
        else dmn_log_fatal("open() of pidfile '%s' failed: %s", params.pid_file, dmn_logf_errno());
    }

    struct flock pidlock_info;
    memset(&pidlock_info, 0, sizeof(struct flock));
    pidlock_info.l_type = F_WRLCK;
    pidlock_info.l_whence = SEEK_SET;

    // should not fail unless something's horribly wrong
    if(fcntl(pidfd, F_GETLK, &pidlock_info))
        dmn_log_fatal("bug: fcntl(%s, F_GETLK) failed: %s", params.pid_file, dmn_logf_errno());

    close(pidfd);

    if(pidlock_info.l_type == F_UNLCK) {
        dmn_log_debug("Found stale pidfile at %s, ignoring", params.pid_file);
        return 0;
    }

    return pidlock_info.l_pid;
}

pid_t dmn_stop(void) {
    phase_check(PHASE2_INIT2, PHASE6_PIDLOCKED, 0);

    const pid_t pid = dmn_status();
    if(!pid) {
        dmn_log_info("Did not find a running daemon to stop!");
        return 0;
    }

    if(terminate_pid_and_wait(pid)) {
        dmn_log_err("Cannot stop daemon at pid %li", (long)pid);
        return pid;
    }

    dmn_log_info("Daemon instance at pid %li stopped", (long)pid);
    return 0;
}

int dmn_signal(int sig) {
    phase_check(PHASE2_INIT2, PHASE6_PIDLOCKED, 0);

    int rv = 1; // error
    const pid_t pid = dmn_status();
    if(!pid) {
        dmn_log_err("Did not find a running daemon to signal!");
    }
    else if(kill(pid, sig)) {
        dmn_log_err("Cannot signal daemon at pid %li", (long)pid);
    }
    else {
        dmn_log_info("Signal %i sent to daemon instance at pid %li", sig, (long)pid);
        rv = 0; // success
    }

    return rv;
}

void dmn_init3(const char* username, const bool restart) {
    phase_check(PHASE2_INIT2, PHASE4_FORKED, 1);

    params.restart = restart;

    if(username && params.invoked_as_root) {
        params.username = strdup(username);
        if(params.invoked_as_root) {
            errno = 0;
            struct passwd* p = getpwnam(username);
            if(!p) {
                if(errno)
                    dmn_log_fatal("getpwnam('%s') failed: %s", username, dmn_logf_errno());
                else
                    dmn_log_fatal("User '%s' does not exist", username);
            }
            if(!p->pw_uid || !p->pw_gid)
                dmn_log_fatal("User '%s' has root's uid and/or gid", username);
            params.uid = p->pw_uid;
            params.gid = p->pw_gid;
            params.will_privdrop = true;
        }
    }

    state.phase = PHASE3_INIT3;
}

unsigned dmn_add_pcall(dmn_func_vv_t func) {
    phase_check(0, PHASE4_FORKED, 0);
    if(!func)
        dmn_log_fatal("BUG: set_pcall requires a funcptr argument!");
    const unsigned idx = num_pcalls;
    if(idx >= 64)
        dmn_log_fatal("Too many pcalls registered (64+)!");
    pcalls = realloc(pcalls, sizeof(dmn_func_vv_t) * (++num_pcalls));
    if(!pcalls)
        dmn_log_fatal("memory allocation failure!");
    pcalls[idx] = func;
    return idx;
}

void dmn_fork(void) {
    phase_check(PHASE3_INIT3, PHASE5_SECURED, 1);

    // whether this invocation needs a forked helper process.
    // In background cases, we always need this to hold the
    //   terminal/parent open until final exit status is ready,
    //   and the "helper" is actually the original process instance
    //   from before any daemonization forks.
    // In foreground cases, we fork off a separate helper iff
    //   we plan to privdrop *and* pcalls have been registered, so
    //   that we have a root-owned process to execute the pcalls with.
    params.need_helper = true;

    // if foreground and not doing privdrop+pcalls, this
    //  whole phase basically does nothing
    if(params.foreground && (!params.will_privdrop || !num_pcalls)) {
        params.need_helper = false;
        state.phase = PHASE4_FORKED;
        return;
    }

    // These pipes are used to communicate with the "helper" process,
    //   which is the original parent when daemonizing properly, or
    //   a special forked helper when necessary in the foreground.
    pipe_create(state.pipe_to_helper);
    pipe_create(state.pipe_from_helper);

    // Fork for the first time...
    const pid_t first_fork_pid = fork();
    if(first_fork_pid == -1)
        dmn_log_fatal("fork() failed: %s", dmn_logf_errno());

    // The helper process role is the child of the above fork
    //   in the foreground case, but it is the parent
    //   in the non-foreground case.
    const bool is_helper = params.foreground
        ? !first_fork_pid
        : first_fork_pid;

    if(is_helper) {
        close_pipefd(&state.pipe_to_helper[PIPE_WR]);
        close_pipefd(&state.pipe_from_helper[PIPE_RD]);
        helper_proc(first_fork_pid);
        dmn_assert(0); // above never returns control
    }

    close_pipefd(&state.pipe_to_helper[PIPE_RD]);
    close_pipefd(&state.pipe_from_helper[PIPE_WR]);

    // foreground case doesn't use the daemonization steps below
    if(params.foreground) {
        state.phase = PHASE4_FORKED;
        return;
    }

    // setsid() and ignore HUP/PIPE before the second fork
    if(setsid() == -1)
        dmn_log_fatal("setsid() failed: %s", dmn_logf_errno());
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;

    if(sigaction(SIGHUP, &sa, NULL))
        dmn_log_fatal("sigaction to ignore SIGHUP failed: %s", dmn_logf_errno());

    if(sigaction(SIGPIPE, &sa, NULL))
        dmn_log_fatal("sigaction to ignore SIGPIPE failed: %s", dmn_logf_errno());

    // Fork again.  This time the intermediate parent exits immediately.
    const pid_t second_fork_pid = fork();
    if(second_fork_pid == -1)
        dmn_log_fatal("fork() failed: %s", dmn_logf_errno());
    if(second_fork_pid) // intermediate parent proc
        _exit(0);

    // we're now in the final child daemon
    umask(022);

    if(!freopen("/dev/null", "r", stdin))
        dmn_log_fatal("Cannot open /dev/null: %s", dmn_logf_errno());
    if(!freopen("/dev/null", "w", stdout))
        dmn_log_fatal("Cannot open /dev/null: %s", dmn_logf_errno());
    if(!freopen("/dev/null", "r+", stderr))
        dmn_log_fatal("Cannot open /dev/null: %s", dmn_logf_errno());
    dmn_log_info("Daemonized, final pid is %li", (long)getpid());

    state.phase = PHASE4_FORKED;
}

void dmn_secure(void) {
    phase_check(PHASE4_FORKED, PHASE6_PIDLOCKED, 1);

    if(chdir("/"))
        dmn_log_fatal("chdir(/) failed: %s", dmn_logf_errno());

    // Validate/correct pid_dir + pid_file on-disk...
    if(params.pid_dir) {
        struct stat st;
        if(stat(params.pid_dir, &st)) {
            if(mkdir(params.pid_dir, PERMS750))
                dmn_log_fatal("pidfile directory %s does not exist and mkdir() failed with: %s", params.pid_dir, dmn_logf_errno());
            if(stat(params.pid_dir, &st)) // reload st for privdrop below
                dmn_log_fatal("stat() of pidfile directory %s failed (post-mkdir): %s", params.pid_dir, dmn_logf_errno());
        }
        else if(!S_ISDIR(st.st_mode)) {
            dmn_log_fatal("pidfile directory %s is not a directory!", params.pid_dir);
        }
        else if((st.st_mode & PERMS_MASK) != PERMS750) {
            if(chmod(params.pid_dir, PERMS750))
                dmn_log_fatal("chmod('%s',%.4o) failed: %s", params.pid_dir, PERMS750, dmn_logf_errno());
        }

        // directory chown only applies in privdrop case
        if(params.will_privdrop) {
            if(st.st_uid != params.uid || st.st_gid != params.gid)
                if(chown(params.pid_dir, params.uid, params.gid))
                    dmn_log_fatal("chown('%s',%u,%u) failed: %s", params.pid_dir, params.uid, params.gid, dmn_logf_errno());
        }

        dmn_assert(params.pid_file);

        if(!lstat(params.pid_file, &st)) {
            if(!S_ISREG(st.st_mode))
                dmn_log_fatal("pidfile %s exists and is not a regular file!", params.pid_file);
            if((st.st_mode & PERMS_MASK) != PERMS640)
                if(chmod(params.pid_file, PERMS640))
                    dmn_log_fatal("chmod('%s',%.4o) failed: %s", params.pid_file, PERMS640, dmn_logf_errno());
            // file chown only if privdrop
            if(params.will_privdrop) {
                if(st.st_uid != params.uid || st.st_gid != params.gid)
                    if(chown(params.pid_file, params.uid, params.gid))
                        dmn_log_fatal("chown('%s',%u,%u) failed: %s", params.pid_file, params.uid, params.gid, dmn_logf_errno());
            }
        }
    }

    if(params.will_privdrop) {
        dmn_assert(params.invoked_as_root);
        dmn_assert(params.username);
        dmn_assert(params.uid);
        dmn_assert(params.gid);

        // drop privs
        if(setgid(params.gid))
            dmn_log_fatal("setgid(%u) failed: %s", params.gid, dmn_logf_errno());
        if(initgroups(params.username, params.gid))
            dmn_log_fatal("initgroups(%s,%u) failed: %s", params.username, params.gid, dmn_logf_errno());
        if(setuid(params.uid))
            dmn_log_fatal("setuid(%u) failed: %s", params.uid, dmn_logf_errno());

        // verify that regaining root privs fails, and [e][ug]id values are as expected
        if(    !setegid(0)
            || !seteuid(0)
            || geteuid() != params.uid
            || getuid() != params.uid
            || getegid() != params.gid
            || getgid() != params.gid
        )
            dmn_log_fatal("Platform-specific BUG: setgid() and/or setuid() do not permanently drop privs as expected!");
    }

    state.phase = PHASE5_SECURED;
}

void dmn_acquire_pidfile(void) {
    phase_check(PHASE5_SECURED, PHASE7_FINISHED, 1);

    if(!params.pid_file) {
        state.phase = PHASE6_PIDLOCKED;
        return;
    }

    // flock structure for acquiring pidfile lock
    struct flock pidlock_set;
    memset(&pidlock_set, 0, sizeof(struct flock));
    pidlock_set.l_type = F_WRLCK;
    pidlock_set.l_whence = SEEK_SET;

    // get an open write-handle on the pidfile for lock+update
    int pidfd = open(params.pid_file, O_WRONLY | O_CREAT, PERMS640);
    if(pidfd == -1)
        dmn_log_fatal("open(%s, O_WRONLY|O_CREAT) failed: %s", params.pid_file, dmn_logf_errno());
    if(fcntl(pidfd, F_SETFD, FD_CLOEXEC))
        dmn_log_fatal("fcntl(%s, F_SETFD, FD_CLOEXEC) failed: %s", params.pid_file, dmn_logf_errno());

    // this is only used in the restart case here, but moving it immediately above
    //   the first sd_notifyf() removes the only realistic failure-points between that
    //   and killing the old daemon, so that we don't die for a stupid reason
    //   after stealing another daemon's MAINPID and fail to set it back.
    const pid_t old_pid = dmn_status();
    const pid_t pid = getpid();

    bool really_restart = false;
    if(old_pid) {
        if(!params.restart)
            dmn_log_fatal("start: another daemon instance is already running at pid %li!", (long)old_pid);
        else
            really_restart = true;
    }
    else if(params.restart) {
        dmn_log_info("restart: No previous daemon instance to stop...");
    }

    // if restarting, TERM the old daemon and wait for it to exit for a bit...
    if(really_restart) {
        dmn_log_info("restart: Stopping previous daemon instance at pid %li...", (long)old_pid);
        if(terminate_pid_and_wait(old_pid))
            dmn_log_fatal("restart: failed, old daemon at pid %li did not die!", (long)old_pid);
    }

    // Attempt lock
    if(fcntl(pidfd, F_SETLK, &pidlock_set)) {
        // Various failure modes
        if(errno != EAGAIN && errno != EACCES)
            dmn_log_fatal("bug? fcntl(pidfile, F_SETLK) failed: %s", dmn_logf_errno());
        dmn_log_fatal("cannot acquire pidfile lock on pidfile: %s, owned by pid: %li)", params.pid_file, (long)dmn_status());
    }

    // Success - assuming writing to our locked pidfile doesn't fail!
    if(ftruncate(pidfd, 0))
        dmn_log_fatal("truncating pidfile failed: %s", dmn_logf_errno());
    if(dprintf(pidfd, "%li\n", (long)pid) < 2)
        dmn_log_fatal("dprintf to pidfile failed: %s", dmn_logf_errno());

#ifdef USE_SYSTEMD
    // notify *after* acquiring the pidfile lock
    if(params.use_systemd)
        sd_notifyf(0, "MAINPID=%li", (long)pid);
#endif

    // leak of pidfd here is intentional, it stays open/locked for the duration
    //   of the daemon's execution.  Daemon death by any means unlocks-on-close,
    //   signalling to other code that this instance is no longer running...
    state.phase = PHASE6_PIDLOCKED;
}

void dmn_pcall(unsigned id) {
    phase_check(PHASE4_FORKED, PHASE7_FINISHED, 0);

    if(id >= num_pcalls)
        dmn_log_fatal("BUG: dmn_daemon_pcall() on non-existent index %u", id);

    // if !will_privdrop, we can execute locally since privileges never changed
    if(!params.will_privdrop)
        return pcalls[id]();

    dmn_assert(state.pipe_to_helper[PIPE_WR] >= 0);
    dmn_assert(state.pipe_from_helper[PIPE_RD] >= 0);

    uint8_t msg = id + 64U;
    if(1 != write(state.pipe_to_helper[PIPE_WR], &msg, 1))
        dmn_log_fatal("Bug? failed to write pcall request for %u to helper! Errno was %s", id, dmn_logf_errno());
    if(1 != read(state.pipe_from_helper[PIPE_RD], &msg, 1))
        dmn_log_fatal("Bug? failed to read pcall return for %u from helper! Errno was %s", id, dmn_logf_errno());
    if(msg != ((id + 64U) | 128U))
        dmn_log_fatal("Bug? invalid pcall return of '%hhu' for %u from helper!", msg, id);
}

void dmn_finish(void) {
    phase_check(PHASE6_PIDLOCKED, 0, 1);

    if(params.need_helper) { // inform the helper of our success (bidirectional)
        dmn_assert(state.pipe_to_helper[PIPE_RD] == -1);
        dmn_assert(state.pipe_to_helper[PIPE_WR] >= 0);
        dmn_assert(state.pipe_from_helper[PIPE_RD] >= 0);
        dmn_assert(state.pipe_from_helper[PIPE_WR] == -1);

        errno = 0;
        uint8_t msg = 0;
        if(1 != write(state.pipe_to_helper[PIPE_WR], &msg, 1))
            dmn_log_fatal("Bug? failed to notify helper of daemon success! Errno was %s", dmn_logf_errno());
        if(1 != read(state.pipe_from_helper[PIPE_RD], &msg, 1))
            dmn_log_fatal("Bug? failed to read helper final status! Errno was %s", dmn_logf_errno());
        if(msg != 128U)
            dmn_log_fatal("Bug? final message from helper was '%hhu'", msg);

        close_pipefd(&state.pipe_to_helper[PIPE_WR]);
        close_pipefd(&state.pipe_from_helper[PIPE_RD]);
    }

    dmn_assert(state.pipe_to_helper[PIPE_RD] == -1);
    dmn_assert(state.pipe_to_helper[PIPE_WR] == -1);
    dmn_assert(state.pipe_from_helper[PIPE_RD] == -1);
    dmn_assert(state.pipe_from_helper[PIPE_WR] == -1);

    if(!params.foreground && state.stderr_out) {
        fclose(state.stderr_out);
        state.stderr_out = NULL;
    }

    state.phase = PHASE7_FINISHED;
    return;
}
