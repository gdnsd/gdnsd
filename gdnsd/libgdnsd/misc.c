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
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

/* misc */

static char* cfdir = NULL;

// Make a copy of inpath that's definitely absolute
F_MALLOC F_WUNUSED F_NONNULL
static char* absify(const char* inpath) {
    dmn_assert(inpath);
    if(*inpath == '/') return strdup(inpath);

    char* out = malloc(PATH_MAX);
    if(!getcwd(out, PATH_MAX))
        log_fatal("getcwd() failed: %s", logf_errno());

    size_t cwdlen = strlen(out);
    size_t inlen = strlen(inpath);
    size_t final = cwdlen + inlen + 2;

    if(final >= PATH_MAX)
        log_fatal("Fully-qualified config pathname exceeds PATH_MAX");

    out = realloc(out, final);
    out[cwdlen] = '/';
    memcpy(out + cwdlen + 1, inpath, inlen + 1);

    return out;
}

const char* gdnsd_get_cfdir(void) { return cfdir; }

void gdnsd_set_cfdir(const char* cfg_file) {
    dmn_assert(!cfdir);

    char* real_config_pathname = absify(cfg_file);
    char* tmp_cfg_dir = dirname(real_config_pathname);
    if(!tmp_cfg_dir)
        log_fatal("gdnsd_set_cfdir(%s): dirname(%s) failed: %s", cfg_file, real_config_pathname, logf_errno());
    unsigned tmp_cfg_dir_len = strlen(tmp_cfg_dir);
    cfdir = malloc(tmp_cfg_dir_len + 2);
    memcpy(cfdir, tmp_cfg_dir, tmp_cfg_dir_len);
    cfdir[tmp_cfg_dir_len] = '/';
    cfdir[tmp_cfg_dir_len + 1] = '\0';
    free(real_config_pathname);
}

char* gdnsd_make_abs_fn(const char* absdir, const char* fn) {
    dmn_assert(absdir); dmn_assert(fn);
    dmn_assert(absdir[0] == '/');

    if(fn[0] == '/')
        return strdup(fn);

    char* retval;

    const unsigned fn_len = strlen(fn);
    const unsigned absdir_len = strlen(absdir);
    if(absdir[absdir_len - 1] == '/') {
        retval = malloc(absdir_len + fn_len + 1);
        memcpy(retval, absdir, absdir_len);
        memcpy(retval + absdir_len, fn, fn_len + 1);
    }
    else {
        retval = malloc(absdir_len + fn_len + 2);
        memcpy(retval, absdir, absdir_len);
        retval[absdir_len] = '/';
        memcpy(retval + absdir_len + 1, fn, fn_len + 1);
    }

    return retval;
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

