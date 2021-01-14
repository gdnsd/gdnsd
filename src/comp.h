/* Copyright © 2020 Brandon L Black <blblack@gmail.com>
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

#ifndef GDNSD_COMP_H
#define GDNSD_COMP_H

#include <gdnsd/compiler.h>

#include "ltree.h"

#include <stddef.h>
#include <inttypes.h>

F_NONNULL
void comp_do_mx_cname_ptr(struct ltree_rrset_raw* rrset, const uint8_t* node_dname);

F_WUNUSED F_NONNULL
bool comp_do_ns(struct ltree_rrset_raw* rrset, struct ltree_node_zroot* zroot, const uint8_t* node_dname, const bool in_deleg);

F_NONNULL
void comp_do_soa(struct ltree_rrset_raw* rrset, const uint8_t* node_dname);

#endif // GDNSD_COMP_H
