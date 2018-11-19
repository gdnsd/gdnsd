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

#ifndef GDNSD_CONF_H
#define GDNSD_CONF_H

#include "socks.h"

#include <gdnsd/compiler.h>
#include <gdnsd/vscf.h>

#include <stdbool.h>
#include <inttypes.h>

typedef struct {
    const uint8_t* chaos;
    const uint8_t* nsid;
    const char*    cookie_key_file;
    bool     lock_mem;
    bool     disable_text_autosplit;
    bool     edns_client_subnet;
    bool     zones_strict_data;
    bool     disable_cookies;
    unsigned max_nocookie_response;
    unsigned chaos_len;
    unsigned nsid_len;
    unsigned zones_default_ttl;
    unsigned max_ncache_ttl;
    unsigned max_ttl;
    unsigned min_ttl;
    unsigned max_edns_response;
    unsigned max_edns_response_v6;
    unsigned acme_challenge_ttl;
} cfg_t;

extern const cfg_t* gcfg;

F_NONNULLX(2) F_RETNN
cfg_t* conf_load(const vscf_data_t* cfg_root, const socks_cfg_t* socks_cfg, const bool force_zsd);

#endif // GDNSD_CONF_H
