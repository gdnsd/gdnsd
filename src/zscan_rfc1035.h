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

#ifndef GDNSD_ZSCAN_H
#define GDNSD_ZSCAN_H

#include "ztree.h"

#include <gdnsd/compiler.h>

// Actually scan the zonefile, creating the data.  The failure type
//   distinction is useful for the filesystem-level code over in
//   zsrc_rfc1035.c in deciding whether and when to retry a failure.
// FAILED_FILE means that something went wrong with filesystem-level
//   operations (cannot open, lock, mmap, close, etc), whereas FAILED_PARSE
//   means the contents were no good.

typedef enum {
    ZSCAN_RFC1035_SUCCESS = 0,
    ZSCAN_RFC1035_FAILED_PARSE = 1,
    ZSCAN_RFC1035_FAILED_FILE = 2,
} zscan_rfc1035_status_t;

F_NONNULL
zscan_rfc1035_status_t zscan_rfc1035(zone_t* zone, const char* fn);

#endif // GDNSD_ZSCAN_H
