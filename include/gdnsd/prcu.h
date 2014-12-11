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

#ifndef GDNSD_PRCU_H
#define GDNSD_PRCU_H

#include <pthread.h>

// source for GDNSD_B_QSBR definition for out-of-tree includers
#ifndef GDNSD_SOURCE_TREE
#include <gdnsd/bopts.h>
#endif

#pragma GCC visibility push(default)
extern pthread_rwlock_t gdnsd_prcu_rwlock_;
#pragma GCC visibility pop

// comes from config.h in-tree, or above if out-of-tree
#if GDNSD_B_QSBR

// in-tree we define _LGPL_SOURCE anyways which is a superset of
// URCU_INLINE_SMALL_FUNCTIONS, but this will help for consumers
// of this header which aren't LGPL-compat
#define URCU_INLINE_SMALL_FUNCTIONS 1
#include <urcu-qsbr.h>

#define gdnsd_prcu_rdr_thread_start() rcu_register_thread()
#define gdnsd_prcu_rdr_online() rcu_thread_online()
#define gdnsd_prcu_rdr_quiesce() rcu_quiescent_state()
#define gdnsd_prcu_rdr_lock() rcu_read_lock()
#define gdnsd_prcu_rdr_deref(s) rcu_dereference((s))
#define gdnsd_prcu_rdr_unlock() rcu_read_unlock()
#define gdnsd_prcu_rdr_offline() rcu_thread_offline()
#define gdnsd_prcu_rdr_thread_end() rcu_unregister_thread()

#define gdnsd_prcu_upd_lock() do { } while(0)
#define gdnsd_prcu_upd_assign(d,s) rcu_assign_pointer((d),(s))
#define gdnsd_prcu_upd_unlock() synchronize_rcu()

#else // !GDNSD_B_QSBR

#define gdnsd_prcu_rdr_thread_start() do { } while(0)
#define gdnsd_prcu_rdr_online() do { } while(0)
#define gdnsd_prcu_rdr_quiesce() do { } while(0)
#define gdnsd_prcu_rdr_lock() pthread_rwlock_rdlock(&gdnsd_prcu_rwlock_)
#define gdnsd_prcu_rdr_deref(s) (s)
#define gdnsd_prcu_rdr_unlock() pthread_rwlock_unlock(&gdnsd_prcu_rwlock_)
#define gdnsd_prcu_rdr_offline() do { } while(0)
#define gdnsd_prcu_rdr_thread_end() do { } while(0)

#define gdnsd_prcu_upd_lock() pthread_rwlock_wrlock(&gdnsd_prcu_rwlock_)
#define gdnsd_prcu_upd_assign(d,s) (d) = (s)
#define gdnsd_prcu_upd_unlock() pthread_rwlock_unlock(&gdnsd_prcu_rwlock_)

#endif // GDNSD_B_QSBR

#endif // GDNSD_PRCU_H
