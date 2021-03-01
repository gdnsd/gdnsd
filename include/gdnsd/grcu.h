/* Copyright © 2021 Brandon L Black <blblack@gmail.com>
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

/*****************************************************************************
 * This provides an abstract interface "grcu_*" which is just a thin renaming
 * of the userspace-rcu QSBR API calls we use, but it wraps RCU-protected
 * variables in structures to protect them from accidental non-API access.
 *****************************************************************************/

#ifndef GDNSD_GRCU_H
#define GDNSD_GRCU_H

#include <gdnsd/compiler.h>

#include <urcu-qsbr.h>

// All RCU-accessed variables must be created with these GRCU_* macros, and
// can only be accessed via grcu_* functions.  These use a hidden struct to
// ensure no accidental raw references to the underlying storage occur:
// _t is the type, _n is the name, and _i is the initial value

// For use as a field within a struct:
#define GRCU_FIELD(_t,_n) struct { _t val_; } _n
// For use as a static file-scope global:
#define GRCU_STATIC(_t,_n,_i) static struct { _t val_; } _n = { .val_ = _i }
// For split use as a global with an extern decl in a header
#define GRCU_PUB_DECL(_t,_n) extern struct _n##_s_ { _t val_; } _n;
#define GRCU_PUB_DEF(_n,_i) struct _n##_s_ _n = { .val_ = _i }

// This allows the owner (writer) thread, in the case of a single-writer var
// (which is always the case in gdnsd), to read its own data without an
// explicit dereference and any pointless barriers that entails:
#define GRCU_OWN_READ(_n) ((_n).val_)

// .. And these are the usual userspace-rcu API, using these wrappers:
#define grcu_register_thread() rcu_register_thread()
#define grcu_thread_online() rcu_thread_online()
#define grcu_quiescent_state() rcu_quiescent_state()
#define grcu_read_lock() rcu_read_lock()
#define grcu_dereference(d, s) (d) = rcu_dereference((s).val_)
#define grcu_read_unlock() rcu_read_unlock()
#define grcu_thread_offline() rcu_thread_offline()
#define grcu_unregister_thread() rcu_unregister_thread()
#define grcu_assign_pointer(d, s) rcu_assign_pointer((d).val_, (s))
#define grcu_synchronize_rcu() synchronize_rcu()

#endif // GDNSD_GRCU_H
