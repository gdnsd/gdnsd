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

#ifndef _GDNSD_PKTERR_H
#define _GDNSD_PKTERR_H

#include "config.h"
#include "gdnsd.h"

// like log_err, but only emitted when log_packet_errors is on (kill -USR1)
#define log_pkterr(...) do {\
    if(unlikely(satom_get(&log_packet_errors)))\
        gdnsd_logger(LOG_ERR,__VA_ARGS__);\
} while(0)

extern satom_t log_packet_errors;

#endif // _GDNSD_PKTERR_H
