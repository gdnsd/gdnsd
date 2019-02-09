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
#include <gdnsd/misc.h>

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <limits.h>
#include <time.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <stddef.h>
#include <pthread.h>
#include <sys/wait.h>
#include <signal.h>
#include <math.h>
#include <sys/resource.h>

#ifdef HAVE_PTHREAD_NP_H
#  include <pthread_np.h>
#endif

/* misc */

char* gdnsd_str_combine(const char* s1, const char* s2, const char** s2_offs)
{
    const unsigned s1_len = strlen(s1);
    const unsigned s2_len = strlen(s2);
    char* out = xmalloc(s1_len + s2_len + 1);
    char* work = out;
    memcpy(work, s1, s1_len);
    work += s1_len;
    memcpy(work, s2, s2_len);
    work[s2_len] = 0;
    if (s2_offs)
        *s2_offs = work;
    return out;
}

// this isn't meant to be high-speed or elegant, it's just
//   saving a lot of mundane grunt-code during configuration stuff

typedef struct {
    const char* ptr;
    unsigned len;
} str_with_len_t;

char* gdnsd_str_combine_n(const unsigned count, ...)
{
    gdnsd_assert(count <= 16);
    str_with_len_t strs[16];
    unsigned oal = 1; // for terminating NUL

    va_list ap;
    va_start(ap, count);
    for (unsigned i = 0; i < count; i++) {
        const char* s = va_arg(ap, char*);
        const unsigned l = strlen(s);
        strs[i].ptr = s;
        strs[i].len = l;
        oal += l;
    }
    va_end(ap);

    char* out = xmalloc(oal);
    char* cur = out;
    for (unsigned i = 0; i < count; i++) {
        memcpy(cur, strs[i].ptr, strs[i].len);
        cur += strs[i].len;
    }
    *cur = '\0';

    return out;
}

char* gdnsd_str_subst(const char* haystack, const char* needle, const size_t needle_len, const char* repl, const size_t repl_len)
{
    gdnsd_assert(needle_len);
    static const size_t half_size_bits = SIZE_MAX >> (sizeof(size_t) * 8 / 2);
    const size_t haystack_len = strlen(haystack);
    if (unlikely(haystack_len >= half_size_bits || needle_len >= half_size_bits || repl_len >= half_size_bits))
        log_fatal("Oversized inputs during gdnsd_str_subst, backtrace:%s", logf_bt());

    // Readonly pre-count of the needles in the haystack
    const char* haystack_srch = haystack;
    const char* ssrv;
    size_t needle_count = 0;
    while ((ssrv = strstr(haystack_srch, needle))) {
        needle_count++;
        haystack_srch = ssrv + needle_len;
    }

    // The whole string can't be this big, and the needle len has to be non-zero...
    gdnsd_assert(needle_count < half_size_bits);

    // Fast-path out if no needles
    if (!needle_count)
        return xstrdup(haystack);

    // Figure out the final output size
    const ssize_t adjust = (ssize_t)repl_len - (ssize_t)needle_len;
    const size_t output_len = (size_t)((ssize_t)haystack_len
                                       + (adjust * (ssize_t)needle_count));

    // Even with the input size checks at the top, after the math above things
    // could get crazy in edge cases, so reject them:
    if (output_len >= half_size_bits)
        log_fatal("String sizing overflow, backtrace:%s", logf_bt());

    // Allocate output
    const size_t output_alloc = output_len + 1U; // extra byte for NUL
    char* output = xcalloc(output_alloc);
    char* outptr = output;

    // Actual search/replace into the output in chunks via memcpy
    haystack_srch = haystack;
    while ((ssrv = strstr(haystack_srch, needle))) {
        gdnsd_assert(ssrv >= haystack_srch);
        size_t before_bytes = (size_t)(ssrv - haystack_srch);
        if (before_bytes) {
            memcpy(outptr, haystack_srch, before_bytes);
            outptr += before_bytes;
            haystack_srch += before_bytes;
        }
        memcpy(outptr, repl, repl_len);
        outptr += repl_len;
        haystack_srch += needle_len;
    }

    // Handle final literal chunk, if any
    const char* haystack_nul = &haystack[haystack_len];
    gdnsd_assert(haystack_srch <= haystack_nul);
    if (haystack_srch < haystack_nul) {
        size_t trailing_bytes = (size_t)(haystack_nul - haystack_srch);
        memcpy(outptr, haystack_srch, trailing_bytes);
        outptr += trailing_bytes;
    }

    // Double-check sizing and NUL-termination for sanity
    gdnsd_assert((outptr - output) == (ssize_t)output_len);
    gdnsd_assert(output[output_len] == '\0');

    return output;
}

void gdnsd_thread_setname(const char* n V_UNUSED)
{
#if defined HAVE_PTHREAD_SETNAME_NP_2
    pthread_setname_np(pthread_self(), n);
#elif defined HAVE_PTHREAD_SET_NAME_NP_2
    pthread_set_name_np(pthread_self(), n);
#elif defined HAVE_PTHREAD_SETNAME_NP_3
    pthread_setname_np(pthread_self(), n, NULL);
#endif
}

void gdnsd_thread_reduce_prio(void)
{
#ifdef __linux__
    // On Linux, [sg]etpriority() can be used to set per-pthread nice values,
    // and pid zero defaults to threadid rather than the main PID, but this
    // isn't portable.  I think at least some of the *BSDs may offer similar
    // functionality through pthread_[sg]etschedparam() for SCHED_OTHER using
    // the dynamic min/max there with opposite directionality from nice
    errno = 0;
    const int current = getpriority(PRIO_PROCESS, 0);
    if (errno) {
        log_err("getpriority() failed: %s", logf_errno());
    } else if (current < 0) {
        const int newprio = current / 2;
        if (setpriority(PRIO_PROCESS, 0, newprio))
            log_warn("setpriority(%i) failed: %s", newprio, logf_errno());
    }
#endif
}

static pid_t* children = NULL;
static unsigned n_children = 0;

void gdnsd_register_child_pid(pid_t child)
{
    gdnsd_assert(child);
    children = xrealloc_n(children, n_children + 1, sizeof(*children));
    children[n_children++] = child;
}

static unsigned wait_for_children(unsigned attempts)
{
    unsigned remaining = n_children;

    while (remaining && attempts) {
        const struct timespec ms_10 = { 0, 10000000 };
        nanosleep(&ms_10, NULL);

        remaining = 0;
        for (unsigned i = 0; i < n_children; i++) {
            if (children[i]) {
                if (kill(children[i], 0))
                    remaining++;
                else
                    children[i] = 0;
            }
        }
        attempts--;
    }

    return remaining;
}

// The main thread's libev loop will auto-reap child processes for us, we just
// have to wait for the reaps to occur.
void gdnsd_kill_registered_children(void)
{
    if (!n_children)
        return;

    for (unsigned i = 0; i < n_children; i++) {
        log_info("Sending SIGTERM to child process %li", (long)children[i]);
        kill(children[i], SIGTERM);
    }
    unsigned notdone = wait_for_children(1000); // 10s

    if (notdone) {
        for (unsigned i = 0; i < n_children; i++) {
            if (children[i]) {
                log_info("Sending SIGKILL to child process %li", (long)children[i]);
                kill(children[i], SIGKILL);
            }
        }
        wait_for_children(500); // 5s max
    }
}

unsigned gdnsd_uscale_ceil(unsigned v, double s)
{
    gdnsd_assert(s >= 0.0);
    gdnsd_assert(s <= 1.0);
    const double sv = ceil(v * s);
    gdnsd_assert(sv <= (double)v);
    return (unsigned)sv;
}

// Keep updated if we add more signal handlers anywhere, even indirectly!
void gdnsd_reset_signals_for_exec(void)
{
    // reset handlers to default (but not PIPE/HUP, which may be SIG_IGN and we
    // want to preserve that)
    struct sigaction defaultme;
    sigemptyset(&defaultme.sa_mask);
    defaultme.sa_handler = SIG_DFL;
    defaultme.sa_flags = 0;
    if (sigaction(SIGTERM, &defaultme, NULL))
        log_fatal("sigaction() failed: %s", logf_errno());
    if (sigaction(SIGINT, &defaultme, NULL))
        log_fatal("sigaction() failed: %s", logf_errno());
    if (sigaction(SIGCHLD, &defaultme, NULL))
        log_fatal("sigaction() failed: %s", logf_errno());
    if (sigaction(SIGUSR1, &defaultme, NULL))
        log_fatal("sigaction() failed: %s", logf_errno());
    if (sigaction(SIGUSR2, &defaultme, NULL))
        log_fatal("sigaction() failed: %s", logf_errno());

    // unblock all signals
    sigset_t no_sigs;
    sigemptyset(&no_sigs);
    if (pthread_sigmask(SIG_SETMASK, &no_sigs, NULL))
        log_fatal("pthread_sigmask() failed");
}
