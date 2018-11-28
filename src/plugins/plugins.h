/* Copyright © 2018 Brandon L Black <blblack@gmail.com>
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

#ifndef GDNSD_PLUGINS_H
#define GDNSD_PLUGINS_H

#include "plugapi.h"

// This just declares the exported plugin_t to hook up libplugins to the core
// daemon's consuming code.
extern plugin_t plugin_geoip_funcs;
extern plugin_t plugin_metafo_funcs;
extern plugin_t plugin_http_status_funcs;
extern plugin_t plugin_multifo_funcs;
extern plugin_t plugin_null_funcs;
extern plugin_t plugin_reflect_funcs;
extern plugin_t plugin_simplefo_funcs;
extern plugin_t plugin_static_funcs;
extern plugin_t plugin_tcp_connect_funcs;
extern plugin_t plugin_weighted_funcs;
extern plugin_t plugin_extfile_funcs;
extern plugin_t plugin_extmon_funcs;

#endif // GDNSD_PLUGINS_H
