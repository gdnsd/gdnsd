/* Copyright © 2016 Brandon L Black <blblack@gmail.com>
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

#ifndef GDNSD_RUNTIME_H
#define GDNSD_RUNTIME_H

#include "socks.h"

#include <gdnsd/compiler.h>
#include <gdnsd/vscf.h>

#include <stdbool.h>

F_NONNULLX(2) DMN_F_NORETURN
void runtime(vscf_data_t* cfg_root, socks_cfg_t* socks_cfg, const bool force_zss, const bool force_zsd, const int mcp_sock);

F_NONNULL
void gdnsd_atexit_debug(void (*f)(void));

#endif // GDNSD_RUNTIME_H
