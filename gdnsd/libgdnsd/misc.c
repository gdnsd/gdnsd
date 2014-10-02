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

#include <gdnsd/alloc.h>
#include <gdnsd/misc.h>
#include <gdnsd/misc-priv.h>
#include <gdnsd/log.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <limits.h>
#include <time.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <stddef.h>
#include <dirent.h>
#include <pthread.h>

#ifdef HAVE_PTHREAD_NP_H
#  include <pthread_np.h>
#endif

/* misc */

/**** lowercasing stuff ****/

// Map uppercase ASCII to lowercase while preserving other bytes.
const char gdnsd_lcmap[256] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
  0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
  0x40,

// The part that really matters:
//  0x41-0x5A (A-Z) => 0x61->0x7A (a-z)

        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
  0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
  0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
  0x78, 0x79, 0x7A,

                    0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
  0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
  0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
  0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
  0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
  0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
  0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
  0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
  0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
  0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
  0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
  0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
  0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
  0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
  0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
  0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
  0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
  0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
  0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
  0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
};

char* gdnsd_str_combine(const char* s1, const char* s2, const char** s2_offs) {
    dmn_assert(s1); dmn_assert(s2);
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

/***************
 * This Public-Domain JLKISS64 PRNG implementation is from:
 * http://www.cs.ucl.ac.uk/staff/d.jones/GoodPracticeRNG.pdf
 * I've made cosmetic modifications (style, C99)
 *  and given it a state pointer for threading, and renamed
 *  it into the gdnsd API namespace so it can be swapped out
 *  easily later.
 * I've also wrapped everything up such that there's one
 *  global PRNG initialized at startup from decent sources,
 *  which is mutex-protected and used to set seeds for later
 *  runtime per-thread/plugin PRNG initializations, and provided
 *  a buffer to use one iteration of jlkiss64 to generate
 *  2x numbers in 32-bit space.
 * This seems at least as fast as jkiss32 for the 32-bit
 *  results on modern 64-bit CPUs, has much longer periods
 *  and is more resilient in general, and it gives us the
 *  option to burn a little extra CPU on 64-bit PRNG results when
 *  warranted.
 ***************/

struct _gdnsd_rstate_t {
    uint64_t x;
    uint64_t y;
    uint32_t z1;
    uint32_t c1;
    uint32_t z2;
    uint32_t c2;
    uint32_t buf32;
    bool buf32_ok;
};

uint64_t gdnsd_rand_get64(gdnsd_rstate_t* rs) {
    dmn_assert(rs);

    uint64_t t;

    rs->x = 1490024343005336237ULL * rs->x + 123456789;
    rs->y ^= rs->y << 21;
    rs->y ^= rs->y >> 17;
    rs->y ^= rs->y << 30;
    t = 4294584393ULL * rs->z1 + rs->c1;
    rs->c1 = t >> 32; rs->z1 = t;
    t = 4246477509ULL * rs->z2 + rs->c2;
    rs->c2 = t >> 32; rs->z2 = t;
    return rs->x + rs->y + rs->z1 + ((uint64_t)rs->z2 << 32);
}

uint32_t gdnsd_rand_get32(gdnsd_rstate_t* rs) {
    dmn_assert(rs);

    if(rs->buf32_ok) {
       rs->buf32_ok = false;
       return rs->buf32;
    }
    else {
       rs->buf32_ok = true;
       uint64_t new = gdnsd_rand_get64(rs);
       rs->buf32 = (uint32_t)new;
       new >>= 32;
       return (uint32_t)new;
    }
}

static pthread_mutex_t rand_init_lock = PTHREAD_MUTEX_INITIALIZER;
static gdnsd_rstate_t rand_init_state = { 0, 0, 0, 0, 0, 0, 0, false };

// Try to get 5x uint64_t from /dev/urandom, ensuring
//   none of them are all-zeros.
F_NONNULL
static bool get_urand_data(uint64_t* rdata) {
    dmn_assert(rdata);

    bool rv = false;
    int urfd = open("/dev/urandom", O_RDONLY);
    if(urfd > -1) {
        unsigned attempts = 10;
        do {
            memset(rdata, 0, 40);
            if(read(urfd, rdata, 40) != 40)
                break;
            if(rdata[0] && rdata[1] && rdata[2]
               && rdata[3] && rdata[4]) {
                rv = true;
                break;
            }
        } while(attempts--);
        close(urfd);
    }
    return rv;
}

// We throw away the first N results from new PRNGs.
// N's range, given current constants below, is [31013 - 96548]
static const unsigned THROW_MIN = 31013;
static const unsigned THROW_MASK = 0xFFFF;

void gdnsd_rand_meta_init(void) {
    union {
        uint64_t u64[5];
        uint32_t u32[10];
    } rdata;

    unsigned throw_away = THROW_MIN;
    pthread_mutex_lock(&rand_init_lock);
    if(get_urand_data(rdata.u64)) {
        rand_init_state.x = rdata.u64[0];
        rand_init_state.y = rdata.u64[1];
        rand_init_state.z1 = rdata.u32[4];
        rand_init_state.c1 = rdata.u32[5];
        rand_init_state.z2 = rdata.u32[6];
        rand_init_state.c2 = rdata.u32[7];
        throw_away += (rdata.u32[8] & THROW_MASK);
    }
    else {
        log_warn("Did not get valid PRNG init via /dev/urandom, using iffy sources");
        struct timeval t;
        gettimeofday(&t, NULL);
        pid_t pidval = getpid();
        long clockval = clock();
        rand_init_state.x = 123456789123ULL ^ t.tv_sec;
        rand_init_state.y = 987654321987ULL ^ t.tv_usec;
        rand_init_state.z1 = 43219876 ^ clockval;
        rand_init_state.c1 = 6543217;
        rand_init_state.z2 = 21987643;
        rand_init_state.c2 = 1732654 ^ pidval;
    }
    while(throw_away--)
        gdnsd_rand_get64(&rand_init_state);
    pthread_mutex_unlock(&rand_init_lock);
}

gdnsd_rstate_t* gdnsd_rand_init(void) {
    unsigned throw_away;
    gdnsd_rstate_t* newstate = xcalloc(1, sizeof(gdnsd_rstate_t));
    pthread_mutex_lock(&rand_init_lock);
    newstate->x = gdnsd_rand_get64(&rand_init_state);
    newstate->y = gdnsd_rand_get64(&rand_init_state);
    newstate->z1 = gdnsd_rand_get32(&rand_init_state);
    newstate->c1 = gdnsd_rand_get32(&rand_init_state);
    newstate->z2 = gdnsd_rand_get32(&rand_init_state);
    newstate->c2 = gdnsd_rand_get32(&rand_init_state);
    throw_away  = gdnsd_rand_get64(&rand_init_state);
    pthread_mutex_unlock(&rand_init_lock);
    throw_away &= THROW_MASK;
    throw_away += THROW_MIN;
    while(throw_away--)
        gdnsd_rand_get64(newstate);
    return newstate;
}

// fold X.Y.Z to a single uint32_t, same as <linux/version.h>
F_CONST
static uint32_t _version_fold(const unsigned x, const unsigned y, const unsigned z) {
    dmn_assert(x < 65536); dmn_assert(y < 256); dmn_assert(z < 256);
    return (x << 16) + (y << 8) + z;
}

bool gdnsd_linux_min_version(const unsigned x, const unsigned y, const unsigned z) {
    bool rv = false;
    struct utsname uts;
    if(!uname(&uts) && !strcmp("Linux", uts.sysname)) {
        const uint32_t vers_wanted = _version_fold(x, y, z);
        uint32_t vers_have = _version_fold(0, 0, 0);

        unsigned sys_x, sys_y, sys_z;
        if(sscanf(uts.release, "%5u.%3u.%3u", &sys_x, &sys_y, &sys_z) == 3) {
            vers_have = _version_fold(sys_x, sys_y, sys_z);
        } else if(sscanf(uts.release, "%5u.%3u", &sys_x, &sys_y) == 2) {
            /* no patch version number, e.g. 3.2 */
            vers_have = _version_fold(sys_x, sys_y, 0);
        }

        if(vers_have >= vers_wanted)
            rv = true;
    }
    return rv;
}

// gdnsd_lookup2 is lookup2() by Bob Jenkins,
//   from http://www.burtleburtle.net/bob/c/lookup2.c,
//   which is in the public domain.
// It's just been reformatted/styled to match my code.

#define mix(a,b,c) { \
    a -= b; a -= c; a ^= (c>>13); \
    b -= c; b -= a; b ^= (a<<8);  \
    c -= a; c -= b; c ^= (b>>13); \
    a -= b; a -= c; a ^= (c>>12); \
    b -= c; b -= a; b ^= (a<<16); \
    c -= a; c -= b; c ^= (b>>5);  \
    a -= b; a -= c; a ^= (c>>3);  \
    b -= c; b -= a; b ^= (a<<10); \
    c -= a; c -= b; c ^= (b>>15); \
}

uint32_t gdnsd_lookup2(const char *k, uint32_t len) {
    dmn_assert(k || !len);

    const uint32_t orig_len = len;

    uint32_t a = 0x9e3779b9;
    uint32_t b = 0x9e3779b9;
    uint32_t c = 0xdeadbeef;

    while(len >= 12) {
        a += (k[0] + ((uint32_t)k[1]  << 8)
                   + ((uint32_t)k[2]  << 16)
                   + ((uint32_t)k[3]  << 24));
        b += (k[4] + ((uint32_t)k[5]  << 8)
                   + ((uint32_t)k[6]  << 16)
                   + ((uint32_t)k[7]  << 24));
        c += (k[8] + ((uint32_t)k[9]  << 8)
                   + ((uint32_t)k[10] << 16)
                   + ((uint32_t)k[11] << 24));
        mix(a,b,c);
        k += 12; len -= 12;
    }

    c += orig_len;

    switch(len) {
        case 11: c += ((uint32_t)k[10] << 24);
        case 10: c += ((uint32_t)k[9]  << 16);
        case 9 : c += ((uint32_t)k[8]  << 8);
        case 8 : b += ((uint32_t)k[7]  << 24);
        case 7 : b += ((uint32_t)k[6]  << 16);
        case 6 : b += ((uint32_t)k[5]  << 8);
        case 5 : b += k[4];
        case 4 : a += ((uint32_t)k[3]  << 24);
        case 3 : a += ((uint32_t)k[2]  << 16);
        case 2 : a += ((uint32_t)k[1]  << 8);
        case 1 : a += k[0];
    }

    mix(a,b,c);
    return c;
}

size_t gdnsd_dirent_bufsize(DIR* d, const char* dirname) {
    dmn_assert(d); dmn_assert(dirname);
    errno = 0;
    long name_max = fpathconf(dirfd(d), _PC_NAME_MAX);
    if(name_max < 0)
        log_fatal("fpathconf(%s, _PC_NAME_MAX) failed: %s",
            dirname, dmn_logf_errno());
    if(name_max < NAME_MAX)
        name_max = NAME_MAX;
    const size_t name_end = offsetof(struct dirent, d_name) + name_max + 1;
    return name_end > sizeof(struct dirent)
        ? name_end
        : sizeof(struct dirent);
}
