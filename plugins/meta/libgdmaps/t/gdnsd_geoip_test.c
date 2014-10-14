/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
 *
 * This file is part of gdnsd.
 *
 * gdnsd-plugin-geoip is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * gdnsd-plugin-geoip is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gdnsd.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// This source is for the gdnsd_geoip_test binary, which exercises
//  the core of the gdnsd-plugin-geoip plugin from the commandline.

#include "config.h"
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include <gdnsd/dmn.h>
#include <gdnsd/log.h>
#include <gdnsd/vscf.h>
#include <gdnsd/plugapi.h>
#include <gdnsd/paths-priv.h>

#include "gdmaps.h"
#include "gdmaps_test.h"

static gdmaps_t* gdmaps = NULL;

F_NONNULL F_NORETURN
static void usage(const char* argv0) {
    fprintf(stderr, "\nUsage: %s [-c %s] [map_name addr]\n"
        "  -c\t\tgdnsd config dir, see main gdnsd(8) manpage for details\n"
        "  map_name\tMapping name from geoip plugin config\n"
        "  addr\t\tClient IP address to map.\n\n",
        argv0, gdnsd_get_default_config_dir());
    exit(1);
}

F_NONNULL
static void do_lookup(const char* map_name, const char* ip_arg) {
    dmn_assert(gdmaps); dmn_assert(map_name); dmn_assert(ip_arg);

    int map_idx = gdmaps_name2idx(gdmaps, map_name);
    if(map_idx < 0) {
        log_err("Mapping name '%s' not found in configuration", map_name);
        return;
    }

    client_info_t cinfo;

    // mostly ignored, but needs to be nonzero, and 150 is interesting in that
    //  it easily differentiates source -> scope copies from actual database scope netmasks,
    //  since it's larger than any legal netmask in the database.
    cinfo.edns_client_mask = 150U;

    const int addr_err = gdnsd_anysin_getaddrinfo(ip_arg, NULL, &cinfo.edns_client);
    if(addr_err) {
        log_err("Could not parse address '%s': %s", ip_arg, gai_strerror(addr_err));
        return;
    }

    // To void gdmaps fallback pitfalls
    memcpy(&cinfo.dns_source, &cinfo.edns_client, sizeof(dmn_anysin_t));

    // w/ edns_client_mask set, scope_mask should *always* be set by gdmaps_lookup();
    // (and regardless, dclist should also always be set and contain something)
    unsigned scope_mask = 175U;
    const uint8_t* dclist = gdmaps_lookup(gdmaps, map_idx, &cinfo, &scope_mask);
    dmn_assert(scope_mask != 175U);
    dmn_assert(dclist);

    // Scope was set to Source.  Since we always query as edns, this implies
    //  the database was V4-only and the address input was a non-v4-compat v6 address,
    //  and the lookup code fell back to the default dclist (1).
    if(scope_mask == 150U) {
        printf(
            "%s => %s => %s\n",
            map_name, dmn_logf_anysin_noport(&cinfo.edns_client),
            gdmaps_logf_dclist(gdmaps, map_idx, dclist)
        );
    }
    else {
        printf(
            "%s => %s/%u => %s\n",
            map_name, dmn_logf_anysin_noport(&cinfo.edns_client), scope_mask,
            gdmaps_logf_dclist(gdmaps, map_idx, dclist)
        );
    }

    dmn_fmtbuf_reset();
}

static void do_repl(void) {
    dmn_assert(gdmaps);

    char linebuf[256];
    char map_name[128];
    char ip_addr[128];
    const bool have_tty = isatty(fileno(stdin)) && isatty(fileno(stdout));
    while(1) {
        if(have_tty) {
            fputs("> ", stdout);
            fflush(stdout);
        }
        if(!fgets(linebuf, 255, stdin)) {
            if(!feof(stdin))
                log_err("fgets(stdin) failed: %s", dmn_logf_strerror(ferror(stdin)));
            if(have_tty)
                fputs("\n", stdout);
            return;
        }

        if(2 != sscanf(linebuf, "%127[^ \t\n] %127[^ \t\n]\n", map_name, ip_addr)) {
            log_err("Invalid input.  Please enter a map name followed by an IP address");
            continue;
        }

        do_lookup(map_name, ip_addr);
    }
}

int main(int argc, char* argv[]) {
    const char* input_cfgdir = NULL;
    const char* map_name = NULL;
    const char* ip_arg = NULL;

    switch(argc) {
        // gdnsd_geoip_test -c x map_name ip
        case 5:
            if(strcmp(argv[1], "-c")) usage(argv[0]);
            input_cfgdir = argv[2];
            map_name = argv[3];
            ip_arg = argv[4];
            break;
        // gdnsd_geoip_test map_name ip
        //   -or-
        // gdnsd_geoip_test -c x
        case 3:
            if(!strcmp(argv[1], "-c")) {
                input_cfgdir = argv[2];
            }
            else {
                map_name = argv[1];
                ip_arg = argv[2];
            }
            break;
        // no args at all
        case 1:
            break;
        default:
            usage(argv[0]);
    }

    gdmaps = gdmaps_test_init(input_cfgdir);

    if(map_name) {
        dmn_assert(ip_arg);
        do_lookup(map_name, ip_arg);
    }
    else {
        do_repl();
    }

    return 0;
}
