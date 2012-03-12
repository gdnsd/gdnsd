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

#include "gdnsd-misc.h"
#include "gdnsd-misc-priv.h"
#include "gdnsd-log.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

/* misc */

static char* rootdir = NULL;
static unsigned rdlen = 0;

const char* gdnsd_set_rootdir(const char* rootdir_in) {
    dmn_assert(rootdir_in);
    dmn_assert(!rootdir);
    rootdir = realpath(rootdir_in, NULL);
    if(!rootdir)
        log_fatal("Cleanup/validation of data root pathname '%s' failed: %s", rootdir_in, dmn_strerror(errno));
    log_debug("Root path cleaned up as '%s'", rootdir);
    rdlen = strlen(rootdir);
    return rootdir;
}

const char* gdnsd_get_rootdir(void) { return rootdir; }

char* gdnsd_make_rootdir_path(const char* suffix) {
    dmn_assert(rootdir); dmn_assert(suffix);
    const unsigned suflen = strlen(suffix);
    dmn_assert(suflen);
    dmn_assert(suflen > 1);
    dmn_assert(suffix[0] == '/');
    dmn_assert(suffix[suflen - 1] != '/');
    char* rv = malloc(rdlen + suflen + 1);
    memcpy(rv, rootdir, rdlen);
    memcpy(&rv[rdlen], suffix, suflen);
    rv[rdlen + suflen] = 0;
    return rv;
}

char* gdnsd_make_validated_rootpath(const char* suffix, const char* suffix2) {
    dmn_assert(rootdir); dmn_assert(suffix); dmn_assert(suffix2);
    const unsigned suflen = strlen(suffix);
    const unsigned suf2len = strlen(suffix2);
    dmn_assert(suflen);
    dmn_assert(suflen > 1);
    dmn_assert(suffix[0] == '/');
    dmn_assert(suffix[suflen - 1] != '/');

    // Construct "/rootdir/suffix/suffix2"
    char tmppath[rdlen + suflen + 1 + suf2len + 1];
    memcpy(tmppath, rootdir, rdlen);
    memcpy(&tmppath[rdlen], suffix, suflen);
    tmppath[rdlen + suflen] = '/';
    memcpy(&tmppath[rdlen + suflen + 1], suffix2, suf2len);
    tmppath[rdlen + suflen + 1 + suf2len] = 0;

    // Cleanup via realpath, return NULL if realpath fails,
    //   (which includes if the file doesn't exist)
    char* rv = realpath(tmppath, NULL);
    if(rv && (strlen(rv) < rdlen || strncmp(rv, rootdir, rdlen))) {
        free(rv);
        rv = NULL;
    }
    return rv;
}

char* gdnsd_strip_rootdir(const char* path_in) {
    dmn_assert(path_in); dmn_assert(rootdir);
    dmn_assert(strlen(path_in) > rdlen);
    dmn_assert(!strncmp(path_in, rootdir, rdlen));
    dmn_assert(path_in[rdlen] == '/');
    char* newpath = strdup(&path_in[rdlen]);
    return newpath;
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
static bool get_urand_data(uint64_t* rdata) {
    bool rv = false;
    int urfd = open("/dev/urandom", O_RDONLY);
    if(urfd > -1) {
        unsigned attempts = 10;
        do {
            memset(rdata, 0, 40);
            if(read(urfd, (void*)rdata, 40) != 40)
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
        log_info("Did not get valid PRNG init via /dev/urandom, using iffy sources");
        struct timeval t;
        gettimeofday(&t, NULL);
        pid_t pidval = getpid();
        rand_init_state.x = 123456789123ULL ^ t.tv_sec;
        rand_init_state.y = 987654321987ULL ^ t.tv_usec;
        rand_init_state.z1 = 43219876 ^ pidval;
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
    gdnsd_rstate_t* newstate = calloc(1, sizeof(gdnsd_rstate_t));
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
        unsigned sys_x, sys_y, sys_z;
        if(sscanf(uts.release, "%u.%u.%u", &sys_x, &sys_y, &sys_z) == 3) {
            const uint32_t vers_have = _version_fold(sys_x, sys_y, sys_z);
            const uint32_t vers_wanted = _version_fold(x, y, z);
            if(vers_have >= vers_wanted)
                rv = true;
        }
    }
    return rv;
}

