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

/* XXX XXX XXX
 *  This file is a temporary mid-refactor hack in its current state...
 */

#ifndef GDGEOIP_H
#define GDGEOIP_H

#include <gdnsd-log.h>

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

// this one's just for map validation
#define NUM_CONTINENTS 8
static const char continent_list[NUM_CONTINENTS][3] = {
   "--", "AS", "AF", "OC", "EU", "NA", "SA", "AN"
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

F_UNUSED
static void validate_country_code(const char* cc, const char* map_name) {
    for(unsigned i = 0; i < NUM_COUNTRIES; i++)
        if( !((cc[0] ^ GeoIP_country_code[i][0]) & 0xDF)
         && !((cc[1] ^ GeoIP_country_code[i][1]) & 0xDF)
         && !cc[2])
            return;
    log_fatal("plugin_geoip: map '%s': Country code '%s' is illegal", map_name, cc);
}

F_UNUSED
static void validate_continent_code(const char* cc, const char* map_name) {
    for(unsigned i = 0; i < NUM_CONTINENTS; i++)
        if( !((cc[0] ^ continent_list[i][0]) & 0xDF)
         && !((cc[1] ^ continent_list[i][1]) & 0xDF)
         && !cc[2])
            return;
    log_fatal("plugin_geoip: map '%s': Continent code '%s' is illegal", map_name, cc);
}

#endif // GDGEOIP_H
