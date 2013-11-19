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

bool plugin_reflect_resolve(unsigned threadnum V_UNUSED, unsigned resnum, const uint8_t* origin V_UNUSED, const client_info_t* cinfo, dyn_result_t* result) {
    dmn_assert(resnum < NUM_RTYPES);
    dmn_assert(!result->is_cname);
    dmn_assert(0 == (result->a.count_v4 + result->a.count_v6));
    dmn_assert(result->edns_scope_mask == 0);

    if(resnum == RESPONSE_BOTH || resnum == RESPONSE_DNS || (resnum == RESPONSE_BEST && !cinfo->edns_client_mask)) {
        const anysin_t* dns_client = &cinfo->dns_source;
        if(dns_client->sa.sa_family == AF_INET6) {
            memcpy(&result->a.addrs_v6[0], dns_client->sin6.sin6_addr.s6_addr, 16);
            result->a.count_v6 = 1U;
        }
        else {
            dmn_assert(dns_client->sa.sa_family == AF_INET);
            result->a.addrs_v4[0] = dns_client->sin.sin_addr.s_addr;
            result->a.count_v4 = 1U;
        }
        result->edns_scope_mask = cinfo->edns_client_mask;
    }

    if(cinfo->edns_client_mask && resnum != RESPONSE_DNS) {
        const anysin_t* edns_client = &cinfo->edns_client;
        if(edns_client->sa.sa_family == AF_INET6) {
            memcpy(&result->a.addrs_v6[16 * result->a.count_v6], edns_client->sin6.sin6_addr.s6_addr, 16);
            result->a.count_v6++;
        }
        else {
            dmn_assert(edns_client->sa.sa_family == AF_INET);
            result->a.addrs_v4[result->a.count_v4] = edns_client->sin.sin_addr.s_addr;
            result->a.count_v4++;
        }
        result->edns_scope_mask = cinfo->edns_client_mask;
    }
    else if(!cinfo->edns_client_mask && resnum == RESPONSE_EDNS) {
        dmn_assert(0 == (result->a.count_v4 + result->a.count_v6));
        result->a.addrs_v4[0] = 0U;
        result->a.count_v4 = 1U;
        dmn_assert(result->edns_scope_mask == 0);
    }

    dmn_assert(result->a.count_v4 + result->a.count_v6);

    return true;
}
