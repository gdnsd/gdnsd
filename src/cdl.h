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

#ifndef GDNSD_CDL_H
#define GDNSD_CDL_H

/* CDL - Counted Doubly-linked List
 *
 * Macro-based doubly-linked list with struct-internal pointers and a distinct
 * "root" structure which has pointers to the head and tail elements of the
 * real list.  Also tracks the count of elements, as this is common for our
 * use-cases which matter the most.
 *
 * We've chosen to avoid the Linux container_of() route over all the
 * complexities about types/typeof, alignment, aliasing, and/or standards
 * confusion, and instead we've done something closer to the BSD-style
 * sys/queue.h way of defining things.  The downside is the macro arguments and
 * the code are both a little more verbose than they need to be, and the list
 * root is a distinct type from the entries.  Either way we'd want the
 * implementation to be local here to be sure it's portable and that we can
 * fully control the detailed semantics and implications.  I find many of the
 * existing examples of this kind of thing to have really confusing terminology
 * (especially "head"), so we'll explain ours here.
 *
 * Terminology, when used in macro names, argument names, etc:
 * "root"  - The root structure of a list.  This is not a list member
 *           structure; it is a distinct type which only contains two pointers
 *           to the head (first) and tail (last) elements (which are of the
 *           real data type of the elements of the list).  It is initialized to
 *           the empty state with both pointers as NULL, and after adding some
 *           elements and then removing all elements, both pointers will again
 *           become to NULL to represent the empty state.
 * "type"  - The type of the actual list elements.
 * "entry" - The member of "type" which holds an element's next/prev pointers.
 * "obj"   - A pointer to an actual, existing input list element of type "type"
 *           (or in the case of for-loop iterators: the name of the iteration
 *           pointer that will be made available to the loop)
 * "head"  - The head element of type "type" in the list's ordering (its prev
 *           pointer is NULL).
 * "tail"  - The tail element of type "type" in the list's ordering (its next
 *           pointer is NULL).
 *
 * Initialization:
 * "root" objects must be initialized to zero (e.g. memset, calloc, or = { 0 }
 * as appropriate).  "entry" within a struct probably should be initialized to
 * zero in the general case, but can be left uninitialized so long as the first
 * operation on the entry is to add it to a list root.
 *
 * Also, macros/vars ending in "_" are meant to be private to this file!
 */

#include <gdnsd/compiler.h>
#include <gdnsd/log.h>
#include <stddef.h>

// Data type defs and initialization:

// CDL_ROOT - Define the root struct's contents.
#define CDL_ROOT(type) struct { type* head_; type* tail_; size_t count_; }

// Define the cdl entry contents that must exist in the listed structs.  The
// type argument should be the name of the containing struct.
#define CDL_ENTRY(type) struct { type* next_; type* prev_; }

// Roots' counts and head/tail NULL-ness should match up:
#define CDL_ASSUME_SANE_ROOT_(root) do {                                   \
    if ((root)->count_) {                                                  \
        gdnsd_assume((root)->head_);                                       \
        gdnsd_assume((root)->tail_);                                       \
    } else {                                                               \
        gdnsd_assume(!(root)->head_);                                      \
        gdnsd_assume(!(root)->tail_);                                      \
    }                                                                      \
} while(0)

// For move/del, assume the list has 1+ objects:
#define CDL_ASSUME_ROOT_HAS_OBJ_(root) do {                                \
    gdnsd_assume((root)->head_);                                           \
    gdnsd_assume((root)->tail_);                                           \
    gdnsd_assume((root)->count_);                                          \
} while(0)

// Simple conditions:
#define CDL_IS_EMPTY(root) (!(root)->head_)
#define CDL_IS_HEAD(root, obj) ((root)->head_ == (obj))
#define CDL_IS_TAIL(root, obj) ((root)->tail_ == (obj))

// Accessors - do not write to these as lvalues!  Keep in mind that
// CDL_GET_HEAD and CDL_GET_TAIL will return NULL if used on an empty list!
#define CDL_GET_COUNT(root) ((root)->count_)
#define CDL_GET_HEAD(root) ((root)->head_)
#define CDL_GET_TAIL(root) ((root)->tail_)

// Modifying functions:

// CDL_ADD_HEAD - Add "obj" to "root" as the new head entry
// "obj.entry" must *not* already be in this list!
#define CDL_ADD_HEAD(root, entry, obj) do {                                \
    CDL_ASSUME_SANE_ROOT_(root);                                           \
    (obj)->entry.next_ = (root)->head_;                                    \
    (obj)->entry.prev_ = NULL;                                             \
    if (!(root)->tail_)                                                    \
        (root)->tail_ = (obj);                                             \
    else                                                                   \
        (root)->head_->entry.prev_ = (obj);                                \
    (root)->head_ = (obj);                                                 \
    (root)->count_++;                                                      \
} while(0)

// CDL_ADD_TAIL - Add "obj" to "root" as the new tail entry
// "obj.entry" must *not* already be in this list!
#define CDL_ADD_TAIL(root, entry, obj) do {                                \
    CDL_ASSUME_SANE_ROOT_(root);                                           \
    (obj)->entry.next_ = NULL;                                             \
    (obj)->entry.prev_ = (root)->tail_;                                    \
    if (!(root)->head_)                                                    \
        (root)->head_ = (obj);                                             \
    else                                                                   \
        (root)->tail_->entry.next_ = (obj);                                \
    (root)->tail_ = (obj);                                                 \
    (root)->count_++;                                                      \
} while(0)

// CDL_DEL - Delete "obj" from "root"
// "obj.entry" *must* already be in this list!
#define CDL_DEL(root, entry, obj) do {                                     \
    CDL_ASSUME_ROOT_HAS_OBJ_(root);                                        \
    if (!(obj)->entry.next_) {                                             \
        gdnsd_assume((obj) == (root)->tail_);                              \
        (root)->tail_ = (obj)->entry.prev_;                                \
    } else {                                                               \
        (obj)->entry.next_->entry.prev_ = (obj)->entry.prev_;              \
    }                                                                      \
    if (!(obj)->entry.prev_) {                                             \
        gdnsd_assume((obj) == (root)->head_);                              \
        (root)->head_ = (obj)->entry.next_;                                \
    } else {                                                               \
        (obj)->entry.prev_->entry.next_ = (obj)->entry.next_;              \
    }                                                                      \
    (root)->count_--;                                                      \
} while(0)

// Equivalent to "CDL_DEL(r,e,o); CDL_ADD_HEAD(r,e,o)"
// "obj.entry" *must* already be in this list!
// Bails early with no writes if already at the head position
#define CDL_MOVE_TO_HEAD(root, entry, obj) do {                            \
    CDL_ASSUME_ROOT_HAS_OBJ_(root);                                        \
    if (!(obj)->entry.prev_) {                                             \
        gdnsd_assume((obj) == (root)->head_);                              \
        break;                                                             \
    }                                                                      \
    (obj)->entry.prev_->entry.next_ = (obj)->entry.next_;                  \
    if (!(obj)->entry.next_) {                                             \
        gdnsd_assume((obj) == (root)->tail_);                              \
        (root)->tail_ = (obj)->entry.prev_;                                \
    } else {                                                               \
        (obj)->entry.next_->entry.prev_ = (obj)->entry.prev_;              \
    }                                                                      \
    (obj)->entry.prev_ = NULL;                                             \
    (obj)->entry.next_ = (root)->head_;                                    \
    (root)->head_->entry.prev_ = (obj);                                    \
    (root)->head_ = (obj);                                                 \
} while(0)

// Equivalent to "CDL_DEL(r,e,o); CDL_ADD_TAIL(r,e,o)"
// "obj.entry" *must* already be in this list!
// Bails early with no writes if already at the tail position
#define CDL_MOVE_TO_TAIL(root, entry, obj) do {                            \
    CDL_ASSUME_ROOT_HAS_OBJ_(root);                                        \
    if (!(obj)->entry.next_) {                                             \
        gdnsd_assume((obj) == (root)->tail_);                              \
        break;                                                             \
    }                                                                      \
    (obj)->entry.next_->entry.prev_ = (obj)->entry.prev_;                  \
    if (!(obj)->entry.prev_) {                                             \
        gdnsd_assume((obj) == (root)->head_);                              \
        (root)->head_ = (obj)->entry.next_;                                \
    } else {                                                               \
        (obj)->entry.prev_->entry.next_ = (obj)->entry.next_;              \
    }                                                                      \
    (obj)->entry.next_ = NULL;                                             \
    (obj)->entry.prev_ = (root)->tail_;                                    \
    (root)->tail_->entry.next_ = (obj);                                    \
    (root)->tail_ = (obj);                                                 \
} while(0)

// Basic for-loop iterator which does *not* support CDL_DEL(obj) in the loop:
#define CDL_FOR_EACH(root, type, entry, obj)                               \
    for (type* (obj) = ((root)->head_); (obj); (obj) = ((obj)->entry.next_))

// Safely acquire the next object without a NULL deref for the below:
#define NXT_SAFE_(entry, obj) ((obj) ? (obj)->entry.next_ : NULL)

// "Safe" iterator which supports CDL_DEL(obj) in the loop
#define CDL_FOR_EACH_SAFE(root, type, entry, obj)                          \
    for (type* (obj) = ((root)->head_), *nxt_ = NXT_SAFE_(entry, (obj)); \
         (obj); (obj) = nxt_, nxt_ = NXT_SAFE_(entry, (obj)))

// There are many missing standard operations here such as add_(before|after),
// move_(before|after), splicers, splitters, bulk movers, etc.  Let's not add
// them until we have use-cases for them!

#endif // GDNSD_CDL_H
