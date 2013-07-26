/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
 *
 * This file is part of vscf.
 *
 * vscf is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * vscf is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with vscf.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef VSCF_H
#define VSCF_H

#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>

#include <gdnsd/dname.h>

// Opaque data type used for all complex data pointers in the public API
typedef union _vscf_data_t vscf_data_t;

// Used in hash sorting callbacks
typedef struct {
    const char* const  key;
    const unsigned     len;
} vscf_key_t;

// Invokes the scanner, returning the root-level hash or array on success
// On error, NULL is returned, and *err is set to a newly allocated
//  string containing a specific error message.  If you plan to
//  continue execution you should free this string to avoid leaks.
F_NONNULL
const vscf_data_t* vscf_scan_filename(const char* fn, char** err);

// Destroys (de-allocates) the entire tree of data returned by vscf_scan()
//  Do not call on sub-elements, only on the value actually returned by vscf_scan().
// Passing a NULL argument is harmless
void vscf_destroy(const vscf_data_t* d);

/*
 * These are the data types vscf_get_type (below) can return.
 * vscf_simple_ functions can only be called on data of type VSCF_SIMPLE_T
 * vscf_hash_ functions can only be called on data of type VSCF_HASH_T
 * vscf_array_ functions can be called on any data type.  In the
 *   actual array case they act as expected.  In the hash and simple cases,
 *   they act as if there was a virtual array of length 1 around the data.
 *   This allows (if you wish) syntax flexibility to use a single data item
 *   in place of an array (except in the array-of-arrays case).  e.g.:
 *   "foo = [ 1 ]" and "foo = 1" will look identical if you blindly call
 *   vscf_array_ funcs on foo's data without explicitly checking for the
 *   VSCF_ARRAY_T type.
 */
typedef enum {
    VSCF_HASH_T,
    VSCF_ARRAY_T,
    VSCF_SIMPLE_T
} vscf_type_t;

// Get the type of an otherwise opaque "const vscf_data_t*"
F_NONNULL F_PURE
vscf_type_t vscf_get_type(const vscf_data_t* d);

// Boolean explicit basic type checks, more convenient
//  than vscf_get_type(x) == VSCF_FOO_T
F_NONNULL F_PURE
bool vscf_is_simple(const vscf_data_t* d);
F_NONNULL F_PURE
bool vscf_is_array(const vscf_data_t* d);
F_NONNULL F_PURE
bool vscf_is_hash(const vscf_data_t* d);

// Boolean check for the root node from a vscf scan
F_NONNULL F_PURE
bool vscf_is_root(const vscf_data_t* d);

/* Returns the containing parent array or hash, or NULL if
   called on the root of the configuration */
F_NONNULL F_PURE
const vscf_data_t* vscf_get_parent(const vscf_data_t* d);

/*** Various type-specific accessor functions: ***/

// Get the length of a simple string value
F_NONNULL
unsigned vscf_simple_get_len(const vscf_data_t* d);

// Get a const pointer to the simple string itself (note that
//  the format allows embedded NULs, hence the need for a length).
// Also note that all simple strings get an extra NUL terminator
//  one byte past the official end of string data.  For many cases
//  this allows one to use them as NUL-terminated strings.
F_NONNULL
const char* vscf_simple_get_data(const vscf_data_t* d);

// Return value indicates type-conversion success or failure (whether the
//  data was exactly convertible), output stored in out.  The numeric
//  conversions are per the rules of strtoul, strtol, and strtod and must
//  consume the entire string.  The bool conversion requires the data
//  to be the string "true" or "false" in any mix of upper/lower case.
F_NONNULL bool vscf_simple_get_as_ulong(const vscf_data_t* d, unsigned long* out);
F_NONNULL bool vscf_simple_get_as_long(const vscf_data_t* d, long* out);
F_NONNULL bool vscf_simple_get_as_double(const vscf_data_t* d, double* out);
F_NONNULL bool vscf_simple_get_as_bool(const vscf_data_t* d, bool* out);

// Get a simple value as a "dname"-formatted domainname, according to
//  the same basic rules and return value as gdnsd_dname_from_string()
//  in gdnsd/dname.h.  The "dname" argument must be pre-allocated to
//  256 bytes.
F_NONNULL
dname_status_t vscf_simple_get_as_dname(const vscf_data_t* d, uint8_t* dname);

// Get the length of an array.  Zero means the array is empty.
F_NONNULL F_PURE
unsigned vscf_array_get_len(const vscf_data_t* d);

// Get a member of an array.  idx must be less than the length returned above.
F_NONNULL F_PURE
const vscf_data_t* vscf_array_get_data(const vscf_data_t* d, unsigned idx);

// Get the count of keys in the hash
F_NONNULL F_PURE
unsigned vscf_hash_get_len(const vscf_data_t* d);

// Get a member of a hash by key.
// The byconstkey version is a convenience macro for the common
//  case where the key is a constant string, as it fills in the length
//  for you via sizeof (and evaluates its key argument twice)
// The bystringkey version is a convenience macro for other NUL-terminated strings,
//  and evaluates its key argument twice.
// set_mark will mark any entries successfully retrieved, which affects, _iterate below.
F_NONNULL
const vscf_data_t* vscf_hash_get_data_bykey(const vscf_data_t* d, const char* key, unsigned klen, bool set_mark);
#define vscf_hash_get_data_byconstkey(_d, _key, _sm) \
    vscf_hash_get_data_bykey((_d), (_key), (sizeof(_key) - 1), (_sm))
#define vscf_hash_get_data_bystringkey(_d, _key, _sm) \
    vscf_hash_get_data_bykey((_d), (_key), strlen(_key), (_sm))

// Get hash keys and values by index number (0 -> (get_nkeys - 1))
F_NONNULLX(1)
const char* vscf_hash_get_key_byindex(const vscf_data_t* d, unsigned idx, unsigned* klen_ptr);
F_NONNULL F_PURE
const vscf_data_t* vscf_hash_get_data_byindex(const vscf_data_t* d, unsigned idx);

// Get the ordered index number for a given key
//  using a non-existent key will return -1
F_NONNULL F_PURE
int vscf_hash_get_index_bykey(const vscf_data_t* d, const char* key, unsigned klen);

/*
 * Iterate all members of a hash with a used-supplied callback function.
 * Return from your callback with true normally, or false to prematurely terminate iteration.
 * The "data" argument is passed verbatim as the final argument to your callback.  You can
 *  use (or not use) it however you wish.
 * Hash keys are iterated in the order they appeared in the input file.
 * If "ignore_mark" is true, vscf_hash_iterate will skip (not issue callbacks for) any hash
 *  elements which were marked via the "set_mark" option of vscf_hash_get_item earlier.
 * This is a generic mechanism for "retrieve certain keys explicitly one by one, and then iterate
 *  the remainder of the keys", which is useful in a lot of scenarios.  e.g., if you
 *  only have a limited set of explicitly legal keys in a given part of your configfile format,
 *  you can _get_item them all, and then run _iterate with a callback that generates an "illegal key"
 *  error.
 */
typedef bool (*vscf_hash_iter_cb_t)(const char* key, unsigned klen, const vscf_data_t* d, void* data);
F_NONNULLX(1,3)
void vscf_hash_iterate(const vscf_data_t* d, bool ignore_mark, vscf_hash_iter_cb_t f, void* data);

// Re-sort hash keys from default order (order defined in config file) to an arbitrary
//  order of your choosing, using a qsort()-like compare callback.  Calls to vscf_hash_iterate
//  after vscf_hash_sort will iterate in the new sort order.  Not thread-safe (all access to
//  a given hash should be locked if it's being sorted in a threaded environment).
typedef int (*vscf_key_cmp_cb_t)(const vscf_key_t* const * const a, const vscf_key_t* const * const b);
F_NONNULL
void vscf_hash_sort(const vscf_data_t* d, vscf_key_cmp_cb_t f);

/****** interfaces that modify the vscf data tree ******/
// These come with a lot of hidden caveats about affecting
//  ongoing iterators, thread safety, etc.  Not to mention
//  even higher than normal potential API breakage risk.
// Use at your own (and users') peril...

vscf_data_t* vscf_hash_new(void);
vscf_data_t* vscf_array_new(void);

// rval does not need to be 0-terminated, and rlen should not
//    account for any 0-termination that is present.  Embedded
//    nuls are fine.
// rval storage is copied, you own the original
F_NONNULL
vscf_data_t* vscf_simple_new(const char* rval, const unsigned rlen);
F_NONNULL
void vscf_array_add_val(vscf_data_t* a, vscf_data_t* v);

// k *does* need to be 0-terminated, but klen still should not account for it,
//   and k can have embedded nuls.
// k storage is copied, you own the original
F_NONNULL
bool vscf_hash_add_val(const char* k, const unsigned klen, vscf_data_t* h, vscf_data_t* v);

// deep-clone any type of data. detaches parent ptr at top.
//  if ignore_marked is set, any hashes (recursively) will not
//   copy marked items to the cloned copy.
F_NONNULL
vscf_data_t* vscf_clone(const vscf_data_t* d, const bool ignore_marked);

// "inherit" a key from src to dest.  If the key already exists in dest,
//   no action is taken.  If it does not, the key is created in dest,
//   with the value set to a clone of the key's value in src.
//  also takes no action if the key doesn't exist in src.
//  if mark_src is set, marks the key in src if it exists, regardless of whether
//   we actually cloned down the val
//  doesn't support NULs in keys.  All things considered, we're pretty much
//    not using that anyways...
F_NONNULL
void vscf_hash_inherit(const vscf_data_t* src, vscf_data_t* dest, const char* k, const bool mark_src);

// as above, for all keys in src -> dest, never marks src
// skips marked keys in src if skip_marked
F_NONNULL
void vscf_hash_inherit_all(const vscf_data_t* src, vscf_data_t* dest, const bool skip_marked);

// if key 'k' exists in src, iterate all other direct children of 'src' let them inherit
//   this key from above.  Skips children whose values are not hashes.
// if mark_src is set, marks key 'k' in src if it exists.
// if skip_marked is set, does not attempt to bequeath 'k' to marked children
// retval indicates whether 'k' existed in 'src' or not
// Obviously, it's easy to shoot yourself in the foot with this and cause strange results...
F_NONNULL
bool vscf_hash_bequeath_all(const vscf_data_t* src, const char* k, const bool mark_src, const bool skip_marked);

#endif /* VSCF_H */
