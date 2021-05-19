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

// This just declares the exported struct plugin to hook up libplugins to the core
// daemon's consuming code.
extern struct plugin plugin_geoip_funcs;
extern struct plugin plugin_metafo_funcs;
extern struct plugin plugin_http_status_funcs;
extern struct plugin plugin_multifo_funcs;
extern struct plugin plugin_null_funcs;
extern struct plugin plugin_reflect_funcs;
extern struct plugin plugin_simplefo_funcs;
extern struct plugin plugin_static_funcs;
extern struct plugin plugin_tcp_connect_funcs;
extern struct plugin plugin_weighted_funcs;
extern struct plugin plugin_extfile_funcs;
extern struct plugin plugin_extmon_funcs;

#endif // GDNSD_PLUGINS_H
