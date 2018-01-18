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
#include <gdnsd-prot/misc.h>

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

char* gdnsd_str_combine(const char* s1, const char* s2, const char** s2_offs) {
    const unsigned s1_len = strlen(s1);
    const unsigned s2_len = strlen(s2);
    char* out = xmalloc(s1_len + s2_len + 1);
    char* work = out;
    memcpy(work, s1, s1_len);
    work += s1_len;
    memcpy(work, s2, s2_len);
    work[s2_len] = 0;
    if(s2_offs)
        *s2_offs = work;
    return out;
}

// this isn't meant to be high-speed or elegant, it's just
//   saving a lot of mundane grunt-code during configuration stuff

typedef struct {
   const char* ptr;
   unsigned len;
} str_with_len_t;

char* gdnsd_str_combine_n(const unsigned count, ...) {
    str_with_len_t strs[count];
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

    char* out = xmalloc(oal);
    char* cur = out;
    for(unsigned i = 0; i < count; i++) {
        memcpy(cur, strs[i].ptr, strs[i].len);
        cur += strs[i].len;
    }
    *cur = '\0';

    return out;
}

void gdnsd_thread_setname(const char* n V_UNUSED) {
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

static pthread_mutex_t rand_init_lock = PTHREAD_MUTEX_INITIALIZER;
static gdnsd_rstate64_t rand_init_state = { 0, 0, 0, 0, 0, 0 };

typedef union {
    uint64_t u64[5];
    uint32_t u32[10];
    uint16_t u16[20];
} urand_data_t;

// Try to get 5x uint64_t from /dev/urandom, ensuring
//   none of them are all-zeros at the u32 level.
F_NONNULL
static bool get_urand_data(urand_data_t* rdata) {
    int urfd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if(urfd < 0)
        return false;

    bool rv = false;
    unsigned attempts = 10;
    while(!rv && attempts) {
        memset(rdata, 0, sizeof(*rdata));
        if(read(urfd, rdata, sizeof(*rdata)) != sizeof(*rdata))
            break;
        rv = true;
        for(unsigned i = 0; i < ARRAY_SIZE(rdata->u32); i++)
            if(!rdata->u32[i])
                rv = false;
        attempts--;
    };

    close(urfd);
    return rv;
}

// We throw away the first N results from new PRNGs.
// N's range, given current constants below, is [31013 - 96548]
static const unsigned THROW_MIN = 31013;
static const unsigned THROW_MASK = 0xFFFF;

// Must be called early, before any consumers of the public PRNG
//  init interfaces from C<gdnsd/misc.h>
void gdnsd_init_rand(void) {
    static bool has_run = false;
    if(has_run)
        log_fatal("BUG: gdnsd_init_rand() should only be called once!");
    else
        has_run = true;

    urand_data_t rdata;
    unsigned throw_away;

    if(get_urand_data(&rdata)) {
        rand_init_state.x = rdata.u64[0];
        rand_init_state.y = rdata.u64[1];
        rand_init_state.z1 = rdata.u32[4];
        rand_init_state.c1 = rdata.u32[5];
        rand_init_state.z2 = rdata.u32[6];
        rand_init_state.c2 = rdata.u32[7];
        throw_away = (
            rdata.u16[16] ^ rdata.u16[17] ^ rdata.u16[18] ^ rdata.u16[19]
        );
    }
    else {
        log_warn("Did not get valid PRNG init via /dev/urandom, using iffy sources");
        struct timeval t;
        gettimeofday(&t, NULL);
        pid_t pidval = getpid();
        clock_t clockval = clock();
        rand_init_state.x = 123456789123ULL ^ (uint64_t)t.tv_sec;
        rand_init_state.y = 987654321987ULL ^ (uint64_t)t.tv_usec;
        rand_init_state.z1 = 43219876U ^ (uint32_t)clockval;
        rand_init_state.c1 = 6543217U;
        rand_init_state.z2 = 21987643U;
        rand_init_state.c2 = 1732654U ^ (uint32_t)pidval;
        throw_away = 0;
    }
    throw_away &= THROW_MASK;
    throw_away += THROW_MIN;
    while(throw_away--)
        gdnsd_rand64_get(&rand_init_state);
}

gdnsd_rstate64_t* gdnsd_rand64_init(void) {
    unsigned throw_away;
    gdnsd_rstate64_t* newstate = xmalloc(sizeof(*newstate));

    pthread_mutex_lock(&rand_init_lock);
    newstate->x  = gdnsd_rand64_get(&rand_init_state);
    do {
        newstate->y = gdnsd_rand64_get(&rand_init_state);
    } while(!newstate->y); // y==0 is bad for jlkiss64
    newstate->z1 = gdnsd_rand64_get(&rand_init_state);
    newstate->c1 = gdnsd_rand64_get(&rand_init_state);
    newstate->z2 = gdnsd_rand64_get(&rand_init_state);
    newstate->c2 = gdnsd_rand64_get(&rand_init_state);
    throw_away   = gdnsd_rand64_get(&rand_init_state);
    pthread_mutex_unlock(&rand_init_lock);

    throw_away &= THROW_MASK;
    throw_away += THROW_MIN;
    while(throw_away--)
        gdnsd_rand64_get(newstate);
    return newstate;
}

gdnsd_rstate32_t* gdnsd_rand32_init(void) {
    unsigned throw_away;
    gdnsd_rstate32_t* newstate = xmalloc(sizeof(*newstate));

    pthread_mutex_lock(&rand_init_lock);
    newstate->x = gdnsd_rand64_get(&rand_init_state);
    do {
        newstate->y = gdnsd_rand64_get(&rand_init_state);
    } while(!newstate->y); // y==0 is bad for jkisss32
    newstate->z = gdnsd_rand64_get(&rand_init_state);
    newstate->w = gdnsd_rand64_get(&rand_init_state);
    newstate->c = 0;
    throw_away  = gdnsd_rand64_get(&rand_init_state);
    pthread_mutex_unlock(&rand_init_lock);

    throw_away &= THROW_MASK;
    throw_away += THROW_MIN;
    while(throw_away--)
        gdnsd_rand32_get(newstate);
    return newstate;
}

static pid_t* children = NULL;
static unsigned n_children = 0;

void gdnsd_register_child_pid(pid_t child) {
    gdnsd_assert(child);
    children = xrealloc(children, sizeof(pid_t) * (n_children + 1));
    children[n_children++] = child;
}

static unsigned _wait_for_children(unsigned attempts) {
    unsigned remaining = n_children;

    while(remaining && attempts) {
        const struct timespec ms_10 = { 0, 10000000 };
        nanosleep(&ms_10, NULL);

        remaining = 0;
        for(unsigned i = 0; i < n_children; i++) {
            if(children[i]) {
                if(kill(children[i], 0))
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
void gdnsd_kill_registered_children(void) {
    if(!n_children)
        return;

    for(unsigned i = 0; i < n_children; i++) {
        log_info("Sending SIGTERM to child process %li", (long)children[i]);
        kill(children[i], SIGTERM);
    }
    unsigned notdone = _wait_for_children(1000); // 10s

    if(notdone) {
        for(unsigned i = 0; i < n_children; i++) {
            if(children[i]) {
                log_info("Sending SIGKILL to child process %li", (long)children[i]);
                kill(children[i], SIGKILL);
            }
        }
        _wait_for_children(500); // 5s max
    }
}

unsigned gdnsd_uscale_ceil(unsigned v, double s) {
    gdnsd_assert(s >= 0.0);
    gdnsd_assert(s <= 1.0);
    const double sv = ceil(v * s);
    gdnsd_assert(sv <= (double)v);
    return (unsigned)sv;
}
