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

#ifndef GDNSD_MONIO_H
#define GDNSD_MONIO_H

#include "config.h"
#include "gdnsd/vscf.h"
#include "gdnsd/mon.h"
#include <ev.h>

// conf.c calls this for service_types vscf config and to process plugin monitoring requests
void monio_add_servicetypes(const vscf_data_t* svctypes_cfg);
void monio_add_addr(const char* svctype_name, const char* desc, const char* addr, mon_state_t* mon_state_ptr);

// main.c calls this for adding monio events to the main thread's eventloop
F_NONNULL void monio_start(struct ev_loop* mon_loop);

// statio.c calls these
unsigned monio_get_max_stats_len(void);
F_NONNULL unsigned monio_stats_out_csv(char* buf);
F_NONNULL unsigned monio_stats_out_json(char* buf);
F_NONNULL unsigned monio_stats_out_html(char* buf);

#endif // GDNSD_MONIO_H
