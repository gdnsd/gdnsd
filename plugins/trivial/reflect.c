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

#define GDNSD_PLUGIN_NAME reflect

#include "config.h"
#include <gdnsd/plugin.h>
#include <string.h>

#define NUM_RTYPES 4

#define RESPONSE_DNS 0 // use dns_source only
#define RESPONSE_EDNS 1 // use edns_client only
#define RESPONSE_BEST 2 // use edns_client if available, else just dns_source
#define RESPONSE_BOTH 3 // return both if edns_client available, else just dns_source

static const char* response_text[NUM_RTYPES] = {
    "dns",
    "edns",
    "best",
    "both"
};

void plugin_reflect_load_config(vscf_data_t* config V_UNUSED, const unsigned num_threads V_UNUSED) {
    gdnsd_dyn_addr_max(2, 2); // up to two (dns+edns) in any address family
}

// resource names (and numbers) are used by this plugin to choose
//  one of four response types above, defaulting to "best".
int plugin_reflect_map_res(const char* resname, const uint8_t* origin V_UNUSED) {
    if(!resname)
        return RESPONSE_BEST;

    for(unsigned i = 0; i < NUM_RTYPES; i++)
        if(!strcasecmp(resname, response_text[i]))
            return (int)i;

    log_err("plugin_reflect: resource name '%s' invalid (must be one of 'dns', 'edns', 'best', 'both')", resname);
    return -1;
}

gdnsd_sttl_t plugin_reflect_resolve(unsigned resnum, const uint8_t* origin V_UNUSED, const client_info_t* cinfo, dyn_result_t* result) {
    dmn_assert(resnum < NUM_RTYPES);

    if(resnum == RESPONSE_BOTH || resnum == RESPONSE_DNS || (resnum == RESPONSE_BEST && !cinfo->edns_client_mask)) {
        gdnsd_result_add_anysin(result, &cinfo->dns_source);
        gdnsd_result_add_scope_mask(result, cinfo->edns_client_mask);
    }

    if(cinfo->edns_client_mask && resnum != RESPONSE_DNS) {
        gdnsd_result_add_anysin(result, &cinfo->edns_client);
        gdnsd_result_add_scope_mask(result, cinfo->edns_client_mask);
    }
    else if(!cinfo->edns_client_mask && resnum == RESPONSE_EDNS) {
        dmn_anysin_t tmpsin;
        gdnsd_anysin_fromstr("0.0.0.0", 0, &tmpsin);
        gdnsd_result_add_anysin(result, &tmpsin);
    }

    return GDNSD_STTL_TTL_MAX;
}
