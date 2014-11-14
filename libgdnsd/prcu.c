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

#include <gdnsd/prcu-priv.h>
#include <gdnsd/log.h>

#ifndef HAVE_QSBR

// externally visible
pthread_rwlock_t gdnsd_prcu_rwlock;

void gdnsd_prcu_setup_lock(void) {
    int pthread_err;
    pthread_rwlockattr_t lockatt;
    if((pthread_err = pthread_rwlockattr_init(&lockatt)))
        log_fatal("pthread_rwlockattr_init() failed: %s", dmn_logf_strerror(pthread_err));

    // Non-portable way to boost writer priority.  Our writelocks are held very briefly
    //  and very rarely, whereas the readlocks could be very spammy, and we don't want to
    //  block the write operation forever.  This works on Linux+glibc.
#   ifdef PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP
        if((pthread_err = pthread_rwlockattr_setkind_np(&lockatt, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)))
            log_fatal("pthread_rwlockattr_setkind_np(PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP) failed: %s", dmn_logf_strerror(pthread_err));
#   endif

    if((pthread_err = pthread_rwlock_init(&gdnsd_prcu_rwlock, &lockatt)))
        log_fatal("pthread_rwlock_init() failed: %s", dmn_logf_strerror(pthread_err));
    if((pthread_err = pthread_rwlockattr_destroy(&lockatt)))
        log_fatal("pthread_rwlockattr_destroy() failed: %s", dmn_logf_strerror(pthread_err));
}

void gdnsd_prcu_destroy_lock(void) {
    int pthread_err;
    if((pthread_err = pthread_rwlock_destroy(&gdnsd_prcu_rwlock)))
        log_fatal("pthread_rwlock_destroy() failed: %s", dmn_logf_strerror(pthread_err));
}

#endif
