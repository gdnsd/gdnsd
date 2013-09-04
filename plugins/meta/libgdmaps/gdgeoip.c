/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
 *
 * This file is part of gdnsd-plugin-geoip.
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

#include "config.h"
#include "gdgeoip.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <gdnsd/dmn.h>
#include <gdnsd/log.h>
#include <gdnsd/vscf.h>
#include <gdnsd/misc.h>


/*****************************************************************************
 * This portion of the code in this file is specific to parsing
 * MaxMind's various GeoIP databases, and much of it was obviously created by
 * examining the code of (and copying the constants from) MaxMind's own
 * libGeoIP, which is licensed under the LGPL.
 * The code in this file is licensed under the GPLv3, which is compatible,
 * but in any case it's mostly just constants that were copied.
 ****************************************************************************/

#define COUNTRY_BEGIN 16776960
#define LARGE_COUNTRY_BEGIN 16515072
#define STATE_BEGIN_REV1 16000000
#define US_OFFSET 1
#define CANADA_OFFSET 677
#define WORLD_OFFSET 1353
#define FIPS_RANGE 360
#define STRUCTURE_INFO_MAX_SIZE 20
#define GEOIP_COUNTRY_EDITION          1
#define GEOIP_CITY_EDITION_REV1        2
#define GEOIP_REGION_EDITION_REV1      3
#define GEOIP_CITY_EDITION_REV0        6
#define GEOIP_COUNTRY_EDITION_V6       12
#define GEOIP_LARGE_COUNTRY_EDITION    17
#define GEOIP_LARGE_COUNTRY_EDITION_V6 18
#define GEOIP_CITY_EDITION_REV1_V6     30
#define GEOIP_CITY_EDITION_REV0_V6     31

static const char GeoIP_country_continent[254][3] = { "--",
    "AS","EU","EU","AS","AS","NA","NA","EU","AS","NA",
    "AF","AN","SA","OC","EU","OC","NA","AS","EU","NA",
    "AS","EU","AF","EU","AS","AF","AF","NA","AS","SA",
    "SA","NA","AS","AN","AF","EU","NA","NA","AS","AF",
    "AF","AF","EU","AF","OC","SA","AF","AS","SA","NA",
    "NA","AF","AS","AS","EU","EU","AF","EU","NA","NA",
    "AF","SA","EU","AF","AF","AF","EU","AF","EU","OC",
    "SA","OC","EU","EU","NA","AF","EU","NA","AS","SA",
    "AF","EU","NA","AF","AF","NA","AF","EU","AN","NA",
    "OC","AF","SA","AS","AN","NA","EU","NA","EU","AS",
    "EU","AS","AS","AS","AS","AS","EU","EU","NA","AS",
    "AS","AF","AS","AS","OC","AF","NA","AS","AS","AS",
    "NA","AS","AS","AS","NA","EU","AS","AF","AF","EU",
    "EU","EU","AF","AF","EU","EU","AF","OC","EU","AF",
    "AS","AS","AS","OC","NA","AF","NA","EU","AF","AS",
    "AF","NA","AS","AF","AF","OC","AF","OC","AF","NA",
    "EU","EU","AS","OC","OC","OC","AS","NA","SA","OC",
    "OC","AS","AS","EU","NA","OC","NA","AS","EU","OC",
    "SA","AS","AF","EU","EU","AF","AS","OC","AF","AF",
    "EU","AS","AF","EU","EU","EU","AF","EU","AF","AF",
    "SA","AF","NA","AS","AF","NA","AF","AN","AF","AS",
    "AS","OC","AS","AF","OC","AS","EU","NA","OC","AS",
    "AF","EU","AF","OC","NA","SA","AS","EU","NA","SA",
    "NA","NA","AS","OC","OC","OC","AS","AF","EU","AF",
    "AF","EU","AF","--","--","--","EU","EU","EU","EU",
    "NA","NA","NA"
};

#define NUM_COUNTRIES 254
static const char GeoIP_country_code[NUM_COUNTRIES][3] = { "--",
    "AP","EU","AD","AE","AF","AG","AI","AL","AM","CW",
    "AO","AQ","AR","AS","AT","AU","AW","AZ","BA","BB",
    "BD","BE","BF","BG","BH","BI","BJ","BM","BN","BO",
    "BR","BS","BT","BV","BW","BY","BZ","CA","CC","CD",
    "CF","CG","CH","CI","CK","CL","CM","CN","CO","CR",
    "CU","CV","CX","CY","CZ","DE","DJ","DK","DM","DO",
    "DZ","EC","EE","EG","EH","ER","ES","ET","FI","FJ",
    "FK","FM","FO","FR","SX","GA","GB","GD","GE","GF",
    "GH","GI","GL","GM","GN","GP","GQ","GR","GS","GT",
    "GU","GW","GY","HK","HM","HN","HR","HT","HU","ID",
    "IE","IL","IN","IO","IQ","IR","IS","IT","JM","JO",
    "JP","KE","KG","KH","KI","KM","KN","KP","KR","KW",
    "KY","KZ","LA","LB","LC","LI","LK","LR","LS","LT",
    "LU","LV","LY","MA","MC","MD","MG","MH","MK","ML",
    "MM","MN","MO","MP","MQ","MR","MS","MT","MU","MV",
    "MW","MX","MY","MZ","NA","NC","NE","NF","NG","NI",
    "NL","NO","NP","NR","NU","NZ","OM","PA","PE","PF",
    "PG","PH","PK","PL","PM","PN","PR","PS","PT","PW",
    "PY","QA","RE","RO","RU","RW","SA","SB","SC","SD",
    "SE","SG","SH","SI","SJ","SK","SL","SM","SN","SO",
    "SR","ST","SV","SY","SZ","TC","TD","TF","TG","TH",
    "TJ","TK","TM","TN","TO","TL","TR","TT","TV","TW",
    "TZ","UA","UG","UM","US","UY","UZ","VA","VC","VE",
    "VG","VI","VN","VU","WF","WS","YE","YT","RS","ZA",
    "ZM","ME","ZW","A1","A2","O1","AX","GG","IM","JE",
    "BL","MF","BQ"
};

/*******************************
 * End copied MaxMind constants
 *******************************/

// this one's just for map validation
#define NUM_CONTINENTS 8
static const char continent_list[NUM_CONTINENTS][3] = {
   "--", "AS", "AF", "OC", "EU", "NA", "SA", "AN"
};

typedef struct {
    unsigned offset;
    unsigned dclist;
} offset_cache_item_t;
#define OFFSET_CACHE_SIZE 129113 // prime

struct _geoip_db;
typedef struct _geoip_db geoip_db_t;

typedef unsigned (*dclist_get_func_t)(const geoip_db_t* db, const unsigned offset);

struct _geoip_db {
    const char* pathname;
    const char* map_name;
    const fips_t* fips;
    const dcmap_t* dcmap;
    dclists_t* dclists;
    dclist_get_func_t dclist_get_func;
    uint8_t* data;
    unsigned base;
    unsigned size;
    int fd;
    int type;
    gdgeoip_v4o_t v4o_flag;
    bool ipv6;
    bool city_auto_mode;
    bool city_no_region;
    offset_cache_item_t *offset_cache[OFFSET_CACHE_SIZE];
};

void validate_country_code(const char* cc, const char* map_name) {
    dmn_assert(cc); dmn_assert(map_name);
    for(unsigned i = 0; i < NUM_COUNTRIES; i++)
        if( !((cc[0] ^ GeoIP_country_code[i][0]) & 0xDF)
         && !((cc[1] ^ GeoIP_country_code[i][1]) & 0xDF)
         && !cc[2])
            return;
    log_fatal("plugin_geoip: map '%s': Country code '%s' is illegal", map_name, cc);
}

void validate_continent_code(const char* cc, const char* map_name) {
    dmn_assert(cc); dmn_assert(map_name);
    for(unsigned i = 0; i < NUM_CONTINENTS; i++)
        if( !((cc[0] ^ continent_list[i][0]) & 0xDF)
         && !((cc[1] ^ continent_list[i][1]) & 0xDF)
         && !cc[2])
            return;
    log_fatal("plugin_geoip: map '%s': Continent code '%s' is illegal", map_name, cc);
}


F_NONNULL
static unsigned country_get_dclist(const geoip_db_t* db, const unsigned offset) {
    dmn_assert(db); dmn_assert(offset >= db->base);

    unsigned rv = 0;
    if(db->dcmap) {
        const unsigned ccid = offset - db->base;
        char locstr[7];

        locstr[0] = GeoIP_country_continent[ccid][0];
        locstr[1] = GeoIP_country_continent[ccid][1];
        locstr[2] = '\0';
        locstr[3] = GeoIP_country_code[ccid][0];
        locstr[4] = GeoIP_country_code[ccid][1];
        locstr[5] = '\0';
        locstr[6] = '\0';

        rv = dcmap_lookup_loc(db->dcmap, locstr);
    }

    return rv;
}

F_NONNULL
static unsigned region_get_dclist(const geoip_db_t* db, const unsigned offset) {
    dmn_assert(db); dmn_assert(offset >= db->base);

    unsigned rv = 0;
    if(db->dcmap) {
        const unsigned ccid = offset - db->base;
        char locstr[10];

        if (ccid < US_OFFSET) {
            locstr[0] = '-';
            locstr[1] = '-';
            locstr[2] = '\0';
            locstr[3] = '-';
            locstr[4] = '-';
            locstr[5] = '\0';
            locstr[6] = '\0';
        }
        else if (ccid < CANADA_OFFSET) {
            locstr[0] = 'N';
            locstr[1] = 'A';
            locstr[2] = '\0';
            locstr[3] = 'U';
            locstr[4] = 'S';
            locstr[5] = '\0';
            locstr[6] = (char) ((ccid - US_OFFSET) / 26 + 65);
            locstr[7] = (char) ((ccid - US_OFFSET) % 26 + 65);
            locstr[8] = '\0';
            locstr[9] = '\0';
        }
        else if (ccid < WORLD_OFFSET) {
            locstr[0] = 'N';
            locstr[1] = 'A';
            locstr[2] = '\0';
            locstr[3] = 'C';
            locstr[4] = 'A';
            locstr[5] = '\0';
            locstr[6] = (char) ((ccid - CANADA_OFFSET) / 26 + 65);
            locstr[7] = (char) ((ccid - CANADA_OFFSET) % 26 + 65);
            locstr[8] = '\0';
            locstr[9] = '\0';
        }
        else {
            const unsigned ccnum = (ccid - WORLD_OFFSET) / FIPS_RANGE;
            locstr[0] = GeoIP_country_continent[ccnum][0];
            locstr[1] = GeoIP_country_continent[ccnum][1];
            locstr[2] = '\0';
            locstr[3] = GeoIP_country_code[ccnum][0];
            locstr[4] = GeoIP_country_code[ccnum][1];
            locstr[5] = '\0';
            locstr[6] = '\0';
        }

        rv = dcmap_lookup_loc(db->dcmap, locstr);
    }

    return rv;
}

F_NONNULL
static unsigned city_get_dclist(const geoip_db_t* db, unsigned int offs) {
    dmn_assert(db); dmn_assert(offs >= db->base);

    char locstr[256];
    unsigned raw_lat = 0;
    unsigned raw_lon = 0;

    if(!db->city_auto_mode && !db->dcmap)
        return 0;

    // Not found in DB
    if(offs == db->base) {
        if(db->dcmap) {
            locstr[0] = '-';
            locstr[1] = '-';
            locstr[2] = '\0';
            locstr[3] = '-';
            locstr[4] = '-';
            locstr[5] = '\0';
            locstr[6] = '\0';
        }
        // 1800000 == 0.0 when raw is converted to floating-point degrees
        raw_lat = 1800000;
        raw_lon = 1800000;
    }
    else {
        offs += 5 * db->base;
        const uint8_t* rec = &db->data[offs];

        if(db->dcmap) {
            locstr[0] = GeoIP_country_continent[rec[0]][0];
            locstr[1] = GeoIP_country_continent[rec[0]][1];
            locstr[2] = '\0';
            locstr[3] = GeoIP_country_code[rec[0]][0];
            locstr[4] = GeoIP_country_code[rec[0]][1];
            locstr[5] = '\0';
        }

        unsigned loc_pos = 6;
        rec++;

        // Get ptr to region_name from db, get length, skip past it in db
        const char* region_name = (const char*)rec;
        unsigned region_len = strlen(region_name);
        rec += region_len;
        rec++;

        // If we want to use region-level info...
        if(db->dcmap && !db->city_no_region) {
            // Check for FIPS 10-4 conversion, replacing
            //  region_name/region_len if so.
            if(region_len == 2 && db->fips) {
                const uint32_t key = ((unsigned)locstr[3])
                    + ((unsigned)locstr[4] << 8U)
                    + ((unsigned)region_name[0] << 16U)
                    + ((unsigned)region_name[1] << 24U);
                const char* rname = fips_lookup(db->fips, key);
                if(rname) {
                    region_name = rname;
                    region_len = strlen(region_name);
                }
            }

            if(!region_len || !*region_name || region_len > 120U) {
                // Handle oversize and empty cases as "--"
                if(region_len > 120U)
                    log_err("plugin_geoip: Bug: GeoIP City region name much longer than expected: %u '%s'", region_len, rec);
                locstr[loc_pos++] = '-';
                locstr[loc_pos++] = '-';
            }
            else {
                memcpy(&locstr[loc_pos], region_name, region_len);
                loc_pos += region_len;
            }
            locstr[loc_pos++] = '\0';
        }

        const char* city_name = (const char*)rec;
        const unsigned city_len = strlen(city_name);
        rec += city_len;
        rec++;

        if(db->dcmap) {
            if(city_len > 120U) {
                log_err("plugin_geoip: Bug: GeoIP City city name much longer than expected: %u '%s'", city_len, rec);
            }
            else if(city_len) {
                memcpy(&locstr[loc_pos], city_name, city_len);
                loc_pos += city_len;
                locstr[loc_pos++] = '\0';
            }
        }

        // skip past postal code
        rec += strlen((const char*)rec);
        rec++;

        for(int j = 0; j < 3; ++j)
            raw_lat += (rec[j] << (j * 8));
        rec += 3;

        for(int j = 0; j < 3; ++j)
            raw_lon += (rec[j] << (j * 8));

        if(db->dcmap)
            locstr[loc_pos] = '\0';
    }

    int dclist = db->dcmap ? dcmap_lookup_loc(db->dcmap, locstr) : -1;
    if(dclist < 0) {
        dmn_assert(db->city_auto_mode);
        dmn_assert(dclist == -1);
        dclist = dclists_city_auto_map(db->dclists, db->map_name, raw_lat, raw_lon);
    }

    dmn_assert(dclist > -1);
    return dclist;
}

F_NONNULL
static unsigned get_dclist_cached(geoip_db_t* db, const unsigned offset) {
    dmn_assert(db);

    unsigned bucket_size = 0;
    const unsigned ndx = offset % OFFSET_CACHE_SIZE;

    if(db->offset_cache[ndx]) {
        for(bucket_size = 0; db->offset_cache[ndx][bucket_size].offset; bucket_size++)
            if(db->offset_cache[ndx][bucket_size].offset == offset)
                return db->offset_cache[ndx][bucket_size].dclist;
    }

    unsigned dclist = db->dclist_get_func(db, offset);
    db->offset_cache[ndx] = realloc(db->offset_cache[ndx], sizeof(offset_cache_item_t) * (bucket_size + 2));
    dmn_assert(db->offset_cache[ndx]);
    db->offset_cache[ndx][bucket_size].offset = offset;
    db->offset_cache[ndx][bucket_size].dclist = dclist;
    db->offset_cache[ndx][bucket_size + 1].offset = 0;
    return dclist;
}

F_NONNULL
static bool list_xlate_recurse(geoip_db_t* db, nlist_t* nl, struct in6_addr ip, const int depth, const unsigned db_off) {
    dmn_assert(db); dmn_assert(nl);
    dmn_assert(depth < 129);

    bool rv = false;

    do {
        if(unlikely(depth < 1 || ((3 * 2 * db_off) + 6) > db->size)) {
            log_err("plugin_geoip: map '%s': Error traversing GeoIP database, corrupt?", db->map_name);
            rv = true;
            break;
        }

        // skip v4-like spaces as applicable...
        if(depth == 32) {
            if(!memcmp(ip.s6_addr, start_v4compat, 12) && db->v4o_flag == V4O_PRIMARY)
                break;
            else if(!memcmp(ip.s6_addr, start_v4mapped, 12))
                break;
            else if(!memcmp(ip.s6_addr, start_siit, 12))
                break;
        }
        else if(depth == 96 && !memcmp(ip.s6_addr, start_teredo, 4)) {
            break;
        }
        else if(depth == 112 && !memcmp(ip.s6_addr, start_6to4, 2)) {
            break;
        }

        const unsigned char *db_buf = db->data + 3 * 2 * db_off;
        const unsigned db_zero_off = db_buf[0] + (db_buf[1] << 8) + (db_buf[2] << 16);
        const unsigned db_one_off = db_buf[3] + (db_buf[4] << 8) + (db_buf[5] << 16);

        const int next_depth = depth - 1;
        const unsigned mask = 128U - next_depth;

        if(db_zero_off >= db->base) {
            nlist_append(nl, ip.s6_addr, mask, get_dclist_cached(db, db_zero_off));
        }
        else if(list_xlate_recurse(db, nl, ip, next_depth, db_zero_off)) {
            rv = true;
            break;
        }

        SETBIT_v6(ip.s6_addr, mask - 1);

        if(db_one_off >= db->base) {
            nlist_append(nl, ip.s6_addr, mask, get_dclist_cached(db, db_one_off));
        }
        else if(list_xlate_recurse(db, nl, ip, next_depth, db_one_off)) {
            rv = true;
            break;
        }
    } while(0);

    return rv;
}

F_NONNULL
static bool geoip_db_close(geoip_db_t* db) {
    dmn_assert(db);
    bool rv = false;

    if(db->fd != -1) {
        if(db->data) {
            if(-1 == munmap(db->data, db->size)) {
                log_err("plugin_geoip: munmap() of '%s' failed: %s", logf_pathname(db->pathname), logf_errno());
                rv = true;
            }
        }
        if(close(db->fd) == -1) {
            log_err("plugin_geoip: close() of '%s' failed: %s", logf_pathname(db->pathname), logf_errno());
            rv = true;
        }
    }

    for (unsigned i = 0; i < OFFSET_CACHE_SIZE; i++)
        free(db->offset_cache[i]);
    free(db);

    return rv;
}

F_NONNULLX(1,2,3)
static geoip_db_t* geoip_db_open(const char* pathname, const char* map_name, dclists_t* dclists, const dcmap_t* dcmap, const fips_t* fips, const gdgeoip_v4o_t v4o_flag, const bool city_auto_mode, const bool city_no_region) {
    dmn_assert(pathname); dmn_assert(map_name); dmn_assert(dclists);

    geoip_db_t* db = calloc(1, sizeof(geoip_db_t));
    db->fd = -1;
    db->pathname = pathname;
    db->map_name = map_name;
    db->dclists = dclists;
    db->dcmap = dcmap;
    db->v4o_flag = v4o_flag;
    db->city_auto_mode = city_auto_mode;
    db->city_no_region = city_no_region;

    if((db->fd = open(pathname, O_RDONLY)) == -1) {
        log_err("plugin_geoip: map '%s': Cannot open '%s' for reading: %s", map_name, logf_pathname(pathname), logf_errno());
        geoip_db_close(db);
        return NULL;
    }

    struct stat db_stat;
    if(fstat(db->fd, &db_stat) == -1) {
        log_err("plugin_geoip: map '%s': Cannot fstat '%s': %s", map_name, logf_pathname(pathname), logf_errno());
        geoip_db_close(db);
        return NULL;
    }

    db->size = db_stat.st_size;

    // 9 bytes would be a single record splitting the IPv4
    //   space into 0.0.0.0/1 and 128.0.0.0/1, each mapped
    //   to a single countryid, plus the requisite 0xFFFFFF
    //   end marker.
    if(db->size < 9) {
        log_err("plugin_geoip: map '%s': GeoIP database '%s' too small", map_name, logf_pathname(pathname));
        geoip_db_close(db);
        return NULL;
    }

    if((db->data = mmap(NULL, db->size, PROT_READ, MAP_SHARED, db->fd, 0)) == MAP_FAILED) {
        db->data = 0;
        log_err("plugin_geoip: map '%s': Failed to mmap GeoIP DB '%s': %s", map_name, logf_pathname(pathname), logf_errno());
        geoip_db_close(db);
        return NULL;
    }

    /* This GeoIP structure info stuff is confusing...
     * Apparently the first structure info record is the final
     *   3 bytes of the file.  If that's 0xFFFFFF, we're done,
     *   and it's a plain country database.
     * If those 3 bytes aren't 0xFFFFFF, then we step back by
     *   one byte and try again.  From here on when we get
     *   our match on the first 3 bytes being 0xFFFFFF, the
     *   4th byte is the database type.
     */
    db->type = GEOIP_COUNTRY_EDITION;
    int offset = db->size - 3;
    for(unsigned i = 0; i < STRUCTURE_INFO_MAX_SIZE; i++) {
        if(db->data[offset] == 255 && db->data[offset + 1] == 255 && db->data[offset + 2] == 255) {
            if(i) db->type = db->data[offset + 3];
            break;
        }
        offset -= 1;
        if(offset < 0)
            break;
    }

    if(city_auto_mode) {
        switch(db->type) {
            case GEOIP_CITY_EDITION_REV0_V6:
            case GEOIP_CITY_EDITION_REV1_V6:
            case GEOIP_CITY_EDITION_REV0:
            case GEOIP_CITY_EDITION_REV1:
                break;
            default:
                log_err("plugin_geoip: map '%s': GeoIP DB '%s' is not a City-level database and this map uses auto_dc_coords", map_name, logf_pathname(db->pathname));
                geoip_db_close(db);
                return NULL;
        }
    }

    switch(db->type) {
        case GEOIP_COUNTRY_EDITION_V6:
            db->ipv6 = true;
            // fall-through intentional
        case GEOIP_COUNTRY_EDITION:
            db->base = COUNTRY_BEGIN;
            db->dclist_get_func = country_get_dclist;
            break;

        case GEOIP_LARGE_COUNTRY_EDITION_V6:
            db->ipv6 = true;
            // fall-through intentional
        case GEOIP_LARGE_COUNTRY_EDITION:
            db->base = LARGE_COUNTRY_BEGIN;
            db->dclist_get_func = country_get_dclist;
            break;

        case GEOIP_REGION_EDITION_REV1:
            db->base = STATE_BEGIN_REV1;
            db->dclist_get_func = region_get_dclist;
            break;

        case GEOIP_CITY_EDITION_REV0_V6:
        case GEOIP_CITY_EDITION_REV1_V6:
            db->ipv6 = true;
            // fall-through intentional
        case GEOIP_CITY_EDITION_REV0:
        case GEOIP_CITY_EDITION_REV1:
            offset += 4;
            for(unsigned i = 0; i < 3; i++)
                db->base += (db->data[offset + i] << (i * 8));
            if(fips)
                db->fips = fips;
            db->dclist_get_func = city_get_dclist;
            break;

        default:
            log_err("plugin_geoip: map '%s': GeoIP DB '%s': Unrecognized DB type %i", map_name, logf_pathname(db->pathname), db->type);
            geoip_db_close(db);
            return NULL;
    }

    if((v4o_flag == V4O_PRIMARY) && !db->ipv6) {
        log_err("plugin_geoip: map '%s': Primary GeoIP DB '%s' is not an IPv6 database and this map uses geoip_v4_overlay", map_name, logf_pathname(db->pathname));
        geoip_db_close(db);
        return NULL;
    }
    else if((v4o_flag == V4O_SECONDARY) && db->ipv6) {
        log_err("plugin_geoip: map '%s': geoip_v4_overlay database '%s' is not an IPv4 database", map_name, logf_pathname(db->pathname));
        geoip_db_close(db);
        return NULL;
    }

    return db;
}

nlist_t* gdgeoip_make_list(const char* pathname, const char* map_name, dclists_t* dclists, const dcmap_t* dcmap, const fips_t* fips, const gdgeoip_v4o_t v4o_flag, const bool city_auto_mode, const bool city_no_region) {
    dmn_assert(pathname); dmn_assert(map_name); dmn_assert(dclists);

    log_info("plugin_geoip: map '%s': Processing GeoIP database '%s'", map_name, logf_pathname(pathname));

    nlist_t* nl = NULL;

    geoip_db_t* geodb = geoip_db_open(pathname, map_name, dclists, dcmap, fips, v4o_flag, city_auto_mode, city_no_region);
    if(geodb) {
        nl = nlist_new(map_name, true);

        const unsigned start_depth = geodb->ipv6 ? 128 : 32;
        const bool rec_rv = list_xlate_recurse(geodb, nl, ip6_zero, start_depth, 0);
        const bool close_rv = geoip_db_close(geodb);

        if(rec_rv || close_rv) {
            nlist_destroy(nl);
            nl = NULL;
        }
        else {
            nlist_finish(nl);
        }
    }

    return nl;
}
