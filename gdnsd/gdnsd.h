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

/***
At some point, the rest of the source needs to be refactored to use
proper includes in every file, instead of relying on this as a catch-all.
***/

#ifndef _GDNSD_H
#define _GDNSD_H

#include "config.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ev.h>

#include "gdnsd/compiler.h"
#include "gdnsd/vscf.h"
#include "gdnsd/dname.h"
#include "gdnsd/stats.h"
#include "gdnsd/net.h"
#include "gdnsd/log.h"
#include "gdnsd/mon.h"
#include "gdnsd/plugapi.h"
#include "gdnsd/dmn.h"

#endif // _GDNSD_H
