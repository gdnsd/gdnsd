/* Copyright © 2016 Brandon L Black <blblack@gmail.com>
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
#include <gdnsd/dmn.h>

#include <stdbool.h>
#include <stddef.h>
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
#include <sys/socket.h>
#include <sys/un.h>

#ifdef HAVE_LIBUNWIND
#  define UNW_LOCAL_ONLY
#  include <libunwind.h>
#endif

#ifdef __linux__
#  include <sys/prctl.h>
#endif

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
//   value for the size increases.
// At these settings (4, 8, 2), the buffer sizes are:
//   256, 1024, 4096, 16384
// This means the program will abort with a buffer exhaustion
//   message if someone tries to log a message containing
//   >~21K of custom-formatted strings (or less if they're
//   chunky, because we don't split allocations across
//   buffer boundaries).
#define FMTBUF_CT     4U
#define FMTBUF_START  8U
#define FMTBUF_STEP   2U

/***********************************************************
***** Constants ********************************************
***********************************************************/

// Log message prefixes when using stderr
static const char PFX_DEBUG[] = "# debug: ";
static const char PFX_INFO[] = "# info: ";
static const char PFX_WARNING[] = "# warning: ";
static const char PFX_ERR[] = "# error: ";
static const char PFX_CRIT[] = "# fatal: ";
static const char PFX_UNKNOWN[] = "# ???: ";

// Max length of an errno string (for our buffer purposes)
static const size_t DMN_ERRNO_MAXLEN = 256U;

// Standard file-permissions constants
static const mode_t PERMS750   = (S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP);
static const mode_t PERMS640   = (S_IRUSR|S_IWUSR|S_IRGRP);
static const mode_t PERMS_MASK = (S_IRWXU|S_IRWXG|S_IRWXO);

// These are phases used to enforce a strict ordering
//   of operations and dependencies between the functions in this file
// PHASE0_UNINIT is the default at library load, and the
//   code only allows forward, serial movement through this list.
// Note that in PHASE0_UNINIT, *nothing* is valid to call except
//   dmn_init(), including all of the log/assert functions.
typedef enum {
    PHASE0_UNINIT      = 0,
    PHASE1_INIT,
    PHASE2_PMCONF,
    PHASE3_FORKED,
    PHASE4_PIDLOCKED,
    PHASE5_FINISHED,
} phase_t;

/***********************************************************
***** Static process-global data ***************************
***********************************************************/

typedef struct {
    // directly supplied by caller
    bool  debug;
    bool  foreground;
    char* name;

    // calculated/inferred/discovered
    char*    pid_dir;         // from init2()
    char*    pid_file;        // depends on pid_dir + name
} params_t;

static params_t params = {
    .debug           = false,
    .foreground      = false,
    .name            = NULL,
    .pid_dir         = NULL,
    .pid_file        = NULL,
};

typedef struct {
    phase_t phase;
    bool    syslog_alive;
    bool    running_under_sd;
    int     pid_fd;
    int     dmn_sock;
    FILE*   stderr_out;
    FILE*   stdout_out;
} state_t;

static state_t state = {
    .phase            = PHASE0_UNINIT,
    .syslog_alive     = false,
    .running_under_sd = false,
    .pid_fd           = -1,
    .dmn_sock         = -1,
    .stderr_out       = NULL,
    .stdout_out       = NULL,
};

/***********************************************************
***** Logging **********************************************
***********************************************************/

// private to the two functions below it
static char* _fmtbuf_common(const unsigned size) {
    dmn_assert(state.phase > PHASE0_UNINIT);

    // This is our log-formatting buffer.  It holds multiple buffers
    //   of increasing size (see constants above) which are allocated
    //   per-thread as-needed, permanently for the life of the thread.
    static __thread struct {
        unsigned used[FMTBUF_CT];
        char* bufs[FMTBUF_CT];
    } fmtbuf = {{0},{NULL}};

    char* rv = NULL;

    // Allocate a chunk from the per-thread format buffer
    if(size) {
        unsigned bsize = 1U << FMTBUF_START;
        for(unsigned i = 0; i < FMTBUF_CT; i++) {
            if(!fmtbuf.bufs[i]) {
                fmtbuf.bufs[i] = malloc(bsize);
                if(!fmtbuf.bufs[i])
                    dmn_log_fatal("allocation failure in fmtbuf_alloc!");
            }
            if((bsize - fmtbuf.used[i]) >= size) {
                rv = &fmtbuf.bufs[i][fmtbuf.used[i]];
                fmtbuf.used[i] += size;
                break;
            }
            bsize <<= FMTBUF_STEP;
        }
    }
    // Reset (free allocations within) the format buffer,
    else {
        for(unsigned i = 0; i < FMTBUF_CT; i++)
            fmtbuf.used[i] = 0;
    }

    return rv;
}

// Public (including this file) interfaces to _fmtbuf_common()
char* dmn_fmtbuf_alloc(const unsigned size) {
    dmn_assert_ndebug(state.phase > PHASE0_UNINIT);
    char* rv = NULL;
    if(size) {
        rv = _fmtbuf_common(size);
        if(!rv)
            dmn_log_fatal("BUG: format buffer exhausted");
    }
    return rv;
}
void dmn_fmtbuf_reset(void) {
    dmn_assert_ndebug(state.phase > PHASE0_UNINIT);
    _fmtbuf_common(0);
}

// dmn_logf_strerror(), which hides GNU or POSIX strerror_r() thread-safe
//  errno->string translation behind a more strerror()-like interface
//  using dmn_fmtbuf_alloc()
const char* dmn_logf_strerror(const int errnum) {
    dmn_assert_ndebug(state.phase > PHASE0_UNINIT);

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

DMN_DIAG_PUSH_IGNORED("-Wformat-nonliteral")

void dmn_loggerv(int level, const char* fmt, va_list ap) {
    dmn_assert_ndebug(state.phase > PHASE0_UNINIT);

    if(state.stderr_out) {
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

    if(state.syslog_alive)
        vsyslog(level, fmt, ap);

    dmn_fmtbuf_reset();
}

void dmn_logger(int level, const char* fmt, ...) {
    dmn_assert_ndebug(state.phase > PHASE0_UNINIT);
    va_list ap;
    va_start(ap, fmt);
    dmn_loggerv(level, fmt, ap);
    va_end(ap);
}

DMN_DIAG_POP

const char* dmn_logf_bt(void) {
    dmn_assert_ndebug(state.phase > PHASE0_UNINIT);
#ifdef HAVE_LIBUNWIND
    static const unsigned bt_size = 1024U;
    static const unsigned bt_max_name = 60U;

    char* tbuf = dmn_fmtbuf_alloc(bt_size);
    unsigned tbuf_pos = 0;
    tbuf[tbuf_pos] = '\0'; // in case no output below

    unw_cursor_t cursor;
    unw_context_t uc;
    unw_getcontext(&uc);
    unw_init_local(&cursor, &uc);

    while(unw_step(&cursor) > 0 && tbuf_pos < bt_size) {
        unw_word_t ip = 0;
        unw_word_t sp = 0;
        unw_word_t offset = 0;
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        if(!ip)
            break;
        unw_get_reg(&cursor, UNW_REG_SP, &sp);

        char cbuf[bt_max_name];
        cbuf[0] = '\0'; // in case no output below
        (void)unw_get_proc_name(&cursor, cbuf, bt_max_name, &offset);

        int snp_rv = snprintf(&tbuf[tbuf_pos],
            (bt_size - tbuf_pos), "\n[ip:%#.16lx sp:%#.16lx] %s+%#lx",
            (unsigned long)ip, (unsigned long)sp,
            cbuf, (unsigned long)offset);
        if(snp_rv < 0)
            break;
        tbuf_pos += (unsigned)snp_rv;
    }
    return tbuf;
#else
    return "(no libunwind)";
#endif
}

bool dmn_get_debug(void) {
    dmn_assert_ndebug(state.phase > PHASE0_UNINIT);
    return params.debug;
}

bool dmn_get_syslog_alive(void) {
    dmn_assert_ndebug(state.phase > PHASE0_UNINIT);
    return state.syslog_alive;
}

/***********************************************************
***** systemd **********************************************
***********************************************************/

#ifndef __linux__

// skip all systemd-related things on non-linux
#define dmn_detect_systemd() ((void)0)

void dmn_sd_notify(const char* notify_msg, const bool optional) {
    dmn_assert_ndebug(notify_msg);
    dmn_assert_ndebug(state.phase > PHASE0_UNINIT);
    if(optional)
        dmn_log_debug("notify: %s", notify_msg);
    else
        dmn_log_info("notify: %s", notify_msg);
}

#else

// This goes a bit beyond sd_booted()'s lstat check, because
//   that only tells us that systemd is the init system in use,
//   not that we were invoked underneath it as a service unit.
// With a correct unit file, either of getppid() or the NOTIFY_SOCKET
//   check should suffice for ExecStart's purposes.  Using both
//   just ensures we're not surprised by future systemd changes in
//   either direction and that we generate better error output if
//   the unit file is set up incorrectly.
// It's not critical that ExecStop (and future ExecReload) detect
//   systemd properly as they don't actually make functional use
//   of NOTIFY_SOCKET.  As of systemd-208, they don't seem to get
//   it set anyways, in spite of NotifyAccess=all, so the getppid()
//   and MAINPID checks are their only recourse here.
static void dmn_detect_systemd(void) {
    dmn_assert(state.phase > PHASE0_UNINIT);
    struct stat st;
    state.running_under_sd = (
        (!lstat("/run/systemd/system/", &st) && S_ISDIR(st.st_mode))
        && (
            getenv("NOTIFY_SOCKET")
            || getenv("MAINPID")
            || getppid() == 1
        )
    );

    if(state.running_under_sd) {
        dmn_log_debug("Running within systemd control");
        if(!params.foreground)
            dmn_log_fatal("unit file settings incorrect: ExecStart should use '-f'");
    }
}

#define _sdnfail(_x, ...) \
    do { \
        if(!optional) \
            dmn_log_fatal("dmn_sd_notify('%s'): " _x " (unit file needs NotifyAccess=all?)", \
                notify_msg, ## __VA_ARGS__); \
        dmn_log_debug("dmn_sd_notify('%s'): " _x, notify_msg, ## __VA_ARGS__); \
        return; \
    } while(0)

// This is mostly copied from systemd sources (from before
// the sd_pid_notify() changes, which aren't relevant in
// our case), and just updated to match local style + conditions.
void dmn_sd_notify(const char *notify_msg, const bool optional) {
    dmn_assert_ndebug(notify_msg);
    dmn_assert_ndebug(state.phase > PHASE0_UNINIT);

    if(!state.running_under_sd)
        return;

    const char* spath = getenv("NOTIFY_SOCKET");
    if(!spath)
        _sdnfail("Missing NOTIFY_SOCKET value");

    /* Must be an abstract socket, or an absolute path */
    if((spath[0] != '@' && spath[0] != '/') || spath[1] == 0)
        _sdnfail("Invalid NOTIFY_SOCKET path '%s'", spath);

    int fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
    if(fd < 0)
        _sdnfail("Cannot create UNIX socket");

    struct sockaddr_un sun;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, spath, sizeof(sun.sun_path));

    if(sun.sun_path[0] == '@')
        sun.sun_path[0] = 0;

    struct iovec iovec;
    memset(&iovec, 0, sizeof(iovec));
    memcpy(&iovec.iov_base, &notify_msg, sizeof(void*)); // iov_base=const hack
    iovec.iov_len = strlen(notify_msg);

    struct msghdr msghdr;
    memset(&msghdr, 0, sizeof(msghdr));

    msghdr.msg_name = &sun;
    msghdr.msg_namelen = offsetof(struct sockaddr_un, sun_path) + strlen(spath);
    if (msghdr.msg_namelen > sizeof(struct sockaddr_un))
            msghdr.msg_namelen = sizeof(struct sockaddr_un);

    msghdr.msg_iov = &iovec;
    msghdr.msg_iovlen = 1;

    ssize_t sm_rv = sendmsg(fd, &msghdr, 0);
    close(fd);

    if(sm_rv < 0)
        _sdnfail("sendmsg() failed: %s", dmn_logf_errno());
}

#endif // __linux__

/***********************************************************
***** Public helper funcs **********************************
***********************************************************/

// create a socketpair with FD_CLOEXEC and fatal error-checking built in
void dmn_socketpair_cloexec(int sockets[2]) {
    dmn_assert_ndebug(state.phase > PHASE0_UNINIT);

    if(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets))
        dmn_log_fatal("socketpair(AF_UNIX, SOCK_STREAM) failed: %s", dmn_logf_errno());
    if(fcntl(sockets[0], F_SETFD, FD_CLOEXEC))
        dmn_log_fatal("fcntl(FD_CLOEXEC) on socketpair fd failed: %s", dmn_logf_errno());
    if(fcntl(sockets[1], F_SETFD, FD_CLOEXEC))
        dmn_log_fatal("fcntl(FD_CLOEXEC) on socketpair fd failed: %s", dmn_logf_errno());
}

// Privdrop (othgonal to phased stuff, mostly)
void dmn_privdrop(const char* username, const bool weak) {
    dmn_assert_ndebug(state.phase > PHASE0_UNINIT);

    if(!geteuid() && username) {
        errno = 0;
        struct passwd* p;
        // cppcheck-suppress nonreentrantFunctionsgetpwnam (init time, no threads)
        if(!(p = getpwnam(username))) {
            if(errno)
                dmn_log_fatal("getpwnam('%s') failed: %s", username, dmn_logf_errno());
            else
                dmn_log_fatal("User '%s' does not exist", username);
        }
        if(!p->pw_uid || !p->pw_gid)
            dmn_log_fatal("User '%s' has root's uid and/or gid", username);

        // drop privs
        if(setgid(p->pw_gid))
            dmn_log_fatal("setgid(%u) failed: %s", p->pw_gid, dmn_logf_errno());
        if(initgroups(username, p->pw_gid))
            dmn_log_fatal("initgroups(%s,%u) failed: %s", username, p->pw_gid, dmn_logf_errno());
        if(setuid(p->pw_uid))
            dmn_log_fatal("setuid(%u) failed: %s", p->pw_uid, dmn_logf_errno());

        // verify that regaining root privs fails, and [e][ug]id values are as expected
        if(    !setegid(0)
            || !seteuid(0)
            || geteuid() != p->pw_uid
            || getuid() != p->pw_uid
            || getegid() != p->pw_gid
            || getgid() != p->pw_gid
        )
            dmn_log_fatal("Platform-specific BUG: setgid() and/or setuid() do not permanently drop privs as expected!");
    }

    if(!weak) {
        // On linux 3.5+, immutably disallows regaining privileges (e.g. via
        // execve() of a binary with set[ug]id or capability bits) for this
        // process and all descendants.
#       if defined __linux__ && defined PR_SET_NO_NEW_PRIVS
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
#       endif
    }
}

// Total timeout is 15s.  True retval indicates daemon is still running.
bool dmn_terminate_pid_and_wait(int sig, pid_t pid) {
    dmn_assert_ndebug(state.phase > PHASE0_UNINIT);
    dmn_assert_ndebug(pid > 1);

    bool still_running = false;

    if(!kill(pid, sig)) {
        still_running = true;
        const struct timespec ts = { 0, 50000000 };
        unsigned tries = 300;
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

/***********************************************************
***** Private subroutines used by daemonization ************
***********************************************************/

// Wait for a pid to _exit(0), do not accept
//  any other result, survive interrupts
static void waitpid_zero(pid_t child) {
    dmn_assert(child >= 0);
    dmn_assert(state.phase > PHASE0_UNINIT);

    int status;
    do {
        pid_t wp_rv = waitpid(child, &status, 0);
        if(wp_rv < 0) {
            if(errno == EINTR)
                continue;
            else
                dmn_log_fatal("waitpid() on process %li failed: %s",
                    (long)child, dmn_logf_errno());
        }
        if(wp_rv != child)
            dmn_log_fatal("waitpid() for process %li caught process %li instead",
                (long)child, (long)wp_rv);
        if(status)
            dmn_log_fatal("waitpid(%li) returned bad status %i", (long)child, status);
        return;
    } while(1);
}

// the parent process executes here and does not return
DMN_F_NORETURN
static void parent_proc(const pid_t middle_pid, const int sock) {
    dmn_assert(state.phase == PHASE2_PMCONF);
    dmn_assert(middle_pid);

    // middle_pid is the temporary process in the midst
    //   of the fork->setsid->fork cycle and needs reaping
    waitpid_zero(middle_pid);

    // The point of all of this is to ensure that the outer parent process
    //   doesn't exit until dmn_finish() in the child.  This makes startup
    //   synchronous; when the outer process returns the invoker knows runtime
    //   service is available.
    //
    // Our protocol is:
    // child -> parent: 0x55 (when child done initializing)
    // parent -> exit(0)
    // child -> continues with normal runtime operations
    //
    // If anything goes wrong with that sequence or the socket closes early,
    //   both sides will abort with a bad exit value.

    int exitval = 1;

    uint8_t msg;
    ssize_t read_rv;
    do {
        errno = 0;
        read_rv = read(sock, &msg, 1);
    } while(read_rv < 0 && errno == EINTR);

    if(read_rv == 1 && msg == 0x55)
        exitval = 0;

    // _exit avoids any atexit that may have been installed before fork
    _exit(exitval);
}

// this isn't meant to be high-speed or elegant, but it saves
//   some repetitive string-mod code elsewhere.
static char* str_combine_n(const unsigned count, ...) {
    dmn_assert(state.phase > PHASE0_UNINIT);
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
***** Daemonization ****************************************
***********************************************************/

void dmn_init(bool debug, bool foreground, bool use_syslog, const char* name) {
    // All of this needs to be set up before we can even log failures below
    params.debug = debug;
    params.foreground = foreground;
    state.stderr_out = stderr;
    state.stdout_out = stdout;
    const phase_t prev_phase = state.phase;
    state.phase = PHASE1_INIT;

    // init1 phase checks are not handled by the usual macro
    if(prev_phase != PHASE0_UNINIT)
        dmn_log_fatal("BUG: dmn_init() can only be called once!");
    if(!name)
        dmn_log_fatal("BUG: dmn_init(): argument 'name' is *required*");

    params.name = strdup(name);

    dmn_detect_systemd();
    if(use_syslog) {
        openlog(params.name, LOG_NDELAY|LOG_PID, LOG_DAEMON);
        state.syslog_alive = true;
        // don't send duplicate messages over both channels to systemd
        if(state.running_under_sd) {
            state.stderr_out = NULL;
            state.stdout_out = NULL;
        }
    }

    // We never want SIGPIPE (and neither does any sane daemon, right?)
    struct sigaction sa_ign;
    sigemptyset(&sa_ign.sa_mask);
    sa_ign.sa_flags = 0;
    sa_ign.sa_handler = SIG_IGN;
    if(sigaction(SIGPIPE, &sa_ign, NULL))
        dmn_log_fatal("sigaction(SIGPIPE, SIG_IGN) failed: %s", dmn_logf_errno());

    // ignore SIGHUP if we're not in foreground mode
    if(!foreground)
        if(sigaction(SIGHUP, &sa_ign, NULL))
            dmn_log_fatal("sigaction(SIGHUP, SIG_IGN) failed: %s", dmn_logf_errno());

    // set umask early for consistency
    umask(022);
}

void dmn_pm_config(const char* pid_dir) {
    dmn_assert_ndebug(state.phase == PHASE1_INIT);

    if(pid_dir) {
        if(pid_dir[0] != '/')
            dmn_log_fatal("pid directory path must be absolute!");
        params.pid_dir = strdup(pid_dir);
        params.pid_file = str_combine_n(4, pid_dir, "/", params.name, ".pid");
    }

    state.phase = PHASE2_PMCONF;
}

pid_t dmn_status(void) {
    dmn_assert_ndebug(state.phase == PHASE2_PMCONF);

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
    dmn_assert_ndebug(state.phase == PHASE2_PMCONF);

    const pid_t pid = dmn_status();
    if(!pid) {
        dmn_log_info("Did not find a running daemon to stop!");
        return 0;
    }

    if(dmn_terminate_pid_and_wait(SIGTERM, pid)) {
        dmn_log_err("Cannot stop daemon at pid %li", (long)pid);
        return pid;
    }

    dmn_log_info("Daemon instance at pid %li stopped", (long)pid);
    return 0;
}

int dmn_signal(int sig) {
    dmn_assert_ndebug(state.phase == PHASE2_PMCONF);

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

// fully duplicate a stream and underlying fd for writing, with CLOEXEC set
DMN_F_NONNULL
static FILE* _dup_write_stream(FILE* old, const char* old_name) {
    dmn_assert(old); dmn_assert(old_name);
    dmn_assert(state.phase > PHASE0_UNINIT);

    const int old_fd = fileno(old);
    if(old_fd < 0)
        dmn_log_fatal("fileno(%s) failed: %s", old_name, dmn_logf_errno());
    const int new_fd = dup(old_fd);
    if(new_fd < 0)
        dmn_log_fatal("dup(fileno(%s)) failed: %s", old_name, dmn_logf_errno());
    if(fcntl(new_fd, F_SETFD, FD_CLOEXEC))
        dmn_log_fatal("fcntl(dup(fileno(%s)), F_SETFD, FD_CLOEXEC) failed: %s", old_name, dmn_logf_errno());
    FILE* new_stream = fdopen(new_fd, "w");
    if(!new_stream)
        dmn_log_fatal("fdopen(dup(fileno(%s))) failed: %s", old_name, dmn_logf_errno());

    return new_stream;
}

void dmn_fork(void) {
    dmn_assert_ndebug(state.phase == PHASE2_PMCONF);

    // I moved this up to init1() once, but that messed up
    //   relative configdir paths on the commandline because
    //   init1() happens after dealing with those in conf_load(), etc
    // Maybe this can be reconsidered during a later refactor.
    if(chdir("/"))
        dmn_log_fatal("chdir(/) failed: %s", dmn_logf_errno());

    // Foreground procs don't need to fork
    if(params.foreground) {
        state.phase = PHASE3_FORKED;
        return;
    }

    // This socketpair is used to communicate with the outer parent
    //   so that it can exit correctly after the daemon is up.
    // Our convention is that s[0] is the ancestor process, and
    //   s[1] is the descendant process.
    int sockets[2] = { -1, -1 };
    dmn_socketpair_cloexec(sockets);

    // Fork for the first time...
    const pid_t middle_pid = fork();
    if(middle_pid == -1)
        dmn_log_fatal("fork() failed: %s", dmn_logf_errno());

    // if parent, go run the parent code
    if(middle_pid) {
        if(close(sockets[1]))
            dmn_log_fatal("close() of socketpair fd in dmn parent failed: %s", dmn_logf_errno());
        parent_proc(middle_pid, sockets[0]);
        dmn_assert(0); // above never returns control
    }

    // child process (to become runtime daemon)
    if(close(sockets[0]))
        dmn_log_fatal("close() of socketpair fd in dmn child failed: %s", dmn_logf_errno());
    state.dmn_sock = sockets[1];

    // setsid() before the second fork
    if(setsid() == -1)
        dmn_log_fatal("setsid() failed: %s", dmn_logf_errno());

    // Fork again.  This time the intermediate parent exits immediately.
    const pid_t final_pid = fork();
    if(final_pid == -1)
        dmn_log_fatal("fork() failed: %s", dmn_logf_errno());
    if(final_pid) // is middle process, to be reaped immediately by parent
        _exit(0);

    // Make full copies (new fds + streams) of stderr + stdout for logging
    // so that we can continue outputting to the terminal's stderr as
    // warranted until dmn_finish()
    state.stdout_out = _dup_write_stream(stdout, "stdout");
    state.stderr_out = _dup_write_stream(stderr, "stderr");

    // Seal off normal stdio with /dev/null
    if(!freopen("/dev/null", "r", stdin))
        dmn_log_fatal("Cannot open /dev/null: %s", dmn_logf_errno());
    if(!freopen("/dev/null", "w", stdout))
        dmn_log_fatal("Cannot open /dev/null: %s", dmn_logf_errno());
    if(!freopen("/dev/null", "r+", stderr))
        dmn_log_fatal("Cannot open /dev/null: %s", dmn_logf_errno());

    dmn_log_info("Daemonized, final pid is %li", (long)getpid());
    state.phase = PHASE3_FORKED;
}

static void dmn_acquire_pid_fd(void) {
    dmn_assert(state.pid_fd == -1);
    dmn_assert(params.pid_file && params.pid_dir);

    const bool currently_root = !geteuid();
    struct stat st;

    // check/create/chmod pid_dir as appropriate
    if(stat(params.pid_dir, &st)) {
        if(mkdir(params.pid_dir, PERMS750))
            dmn_log_fatal("pidfile directory %s does not exist and mkdir() failed with: %s", params.pid_dir, dmn_logf_errno());
        if(stat(params.pid_dir, &st))
            dmn_log_fatal("stat() of pidfile directory %s failed (post-mkdir): %s", params.pid_dir, dmn_logf_errno());
    }
    if(!S_ISDIR(st.st_mode))
        dmn_log_fatal("pidfile directory %s is not a directory!", params.pid_dir);
    if(currently_root && (st.st_uid != 0 || st.st_gid != 0))
        if(chown(params.pid_dir, 0, 0))
            dmn_log_fatal("chown('%s',0,0) failed: %s", params.pid_dir, dmn_logf_errno());
    if((st.st_mode & PERMS_MASK) != PERMS750)
        if(chmod(params.pid_dir, PERMS750))
            dmn_log_fatal("chmod('%s',%.4o) failed: %s", params.pid_dir, PERMS750, dmn_logf_errno());

    // check/chmod pid_file as appropriate, if it exists
    if(!lstat(params.pid_file, &st)) {
        if(!S_ISREG(st.st_mode))
            dmn_log_fatal("pidfile %s exists and is not a regular file!", params.pid_file);
        if(currently_root && (st.st_uid != 0 || st.st_gid != 0))
            if(chown(params.pid_file, 0, 0))
                dmn_log_fatal("chown('%s',0,0) failed: %s", params.pid_file, dmn_logf_errno());
        if((st.st_mode & PERMS_MASK) != PERMS640)
            if(chmod(params.pid_file, PERMS640))
                dmn_log_fatal("chmod('%s',%.4o) failed: %s", params.pid_file, PERMS640, dmn_logf_errno());
    }

    // get an open handle on the pidfile...
    state.pid_fd = open(params.pid_file, O_RDWR | O_CREAT | O_SYNC, PERMS640);
    if(state.pid_fd == -1)
        dmn_log_fatal("open(%s, O_WRONLY|O_CREAT) failed: %s", params.pid_file, dmn_logf_errno());
    if(fcntl(state.pid_fd, F_SETFD, FD_CLOEXEC))
        dmn_log_fatal("fcntl(%s, F_SETFD, FD_CLOEXEC) failed: %s", params.pid_file, dmn_logf_errno());
}

static void dmn_pid_fd_lock(const dmn_lockflags_t flags) {
    const bool excl = !!(flags & DMN_LOCK_EX);
    const bool wait = !!(flags & DMN_LOCK_W);

    // get pid fd if this is the initial lock call
    if(state.pid_fd == -1)
        dmn_acquire_pid_fd();

    // flock structure for acquiring pidfile lock
    struct flock pidlock_set;
    memset(&pidlock_set, 0, sizeof(struct flock));
    pidlock_set.l_type = excl ? F_WRLCK : F_RDLCK;
    pidlock_set.l_whence = SEEK_SET;

    // Attempt lock - this is where we resolve a double-startup race
    // definitively, but it would be prudent for the daemon to have checked
    // dmn_status() for itself much earlier to detect common, un-racy cases.
    if(fcntl(state.pid_fd, wait ? F_SETLKW : F_SETLK, &pidlock_set)) {
        // Various failure modes
        if(errno != EAGAIN && errno != EACCES)
            dmn_log_fatal("bug? fcntl(pidfile, F_SETLK) failed: %s", dmn_logf_errno());
        dmn_log_fatal("cannot acquire fcntl lock on pidfile %s, another"
                      " instance of this daemon is conflicting!", params.pid_file);
    }

    // always write current pid on acquisition of exclusive lock
    if(excl) {
        if(ftruncate(state.pid_fd, 0))
            dmn_log_fatal("truncating pidfile failed: %s", dmn_logf_errno());
        if(dprintf(state.pid_fd, "%li\n", (long)getpid()) < 2)
            dmn_log_fatal("dprintf to pidfile failed: %s", dmn_logf_errno());
    }
}

int dmn_pidfile_lock(const dmn_lockflags_t flags) {
    dmn_assert_ndebug(state.phase >= PHASE3_FORKED);
    if(params.pid_file)
        dmn_pid_fd_lock(flags);
    if(state.phase == PHASE3_FORKED && (flags & DMN_LOCK_EX))
        state.phase = PHASE4_PIDLOCKED;
    return state.pid_fd;
}

void dmn_pidfile_release(void) {
    if(!params.pid_file)
        return;
    if(state.pid_fd != -1 && close(state.pid_fd))
        dmn_log_fatal("Cannot close pidfile fd for release: %s", dmn_logf_errno());
    state.pid_fd = -1;
}

void dmn_finish(void) {
    dmn_assert_ndebug(state.phase == PHASE4_PIDLOCKED);

    // notify systemd of full readiness if applicable
    dmn_sd_notify("READY=1", false);

    if(!params.foreground) {
        dmn_assert(state.dmn_sock >= 0);

        errno = 0;
        uint8_t msg = 0x55;
        if(1 != write(state.dmn_sock, &msg, 1))
            dmn_log_fatal("Bug? failed to notify parent of daemon success: %s", dmn_logf_errno());

        if(close(state.dmn_sock))
            dmn_log_fatal("close() of socketpair fd in dmn_finish failed: %s", dmn_logf_errno());

        // Close our copied streams if daemonized
        fclose(state.stdout_out);
        fclose(state.stderr_out);
        state.stdout_out = NULL;
        state.stderr_out = NULL;
    }
    else {
        dmn_assert(state.dmn_sock == -1);
    }

    state.phase = PHASE5_FINISHED;
}
