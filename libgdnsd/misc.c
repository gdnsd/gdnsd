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

void gdnsd_thread_setname(const char* n V_UNUSED)
{
#if defined HAVE_PTHREAD_SETNAME_NP_2
    pthread_setname_np(pthread_self(), n);
#elif defined HAVE_PTHREAD_SET_NAME_NP_2
    pthread_set_name_np(pthread_self(), n);
#elif defined HAVE_PTHREAD_SETNAME_NP_1
    pthread_setname_np(n);
#elif defined HAVE_PTHREAD_SETNAME_NP_3
    pthread_setname_np(pthread_self(), n, NULL);
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

static unsigned _wait_for_children(unsigned attempts)
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
    unsigned notdone = _wait_for_children(1000); // 10s

    if (notdone) {
        for (unsigned i = 0; i < n_children; i++) {
            if (children[i]) {
                log_info("Sending SIGKILL to child process %li", (long)children[i]);
                kill(children[i], SIGKILL);
            }
        }
        _wait_for_children(500); // 5s max
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
