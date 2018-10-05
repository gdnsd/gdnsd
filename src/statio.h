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

#ifndef GDSND_STATIO_H
#define GDSND_STATIO_H

#include <gdnsd/compiler.h>
#include <sys/types.h>
#include <inttypes.h>

F_NONNULL
void statio_init(unsigned arg_num_dns_threads);

F_NONNULL F_RETNN
char* statio_get_json(time_t nowish, size_t* len);

F_NONNULL F_MALLOC
char* statio_serialize(size_t* dlen_p);

F_NONNULL
void statio_deserialize(uint64_t* data, size_t dlen);

#endif // GDSND_STATIO_H
