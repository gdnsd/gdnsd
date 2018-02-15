/* Copyright © 2014 Brandon L Black <blblack@gmail.com>
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

#include <config.h>
#include "gdgeoip2.h"

#include "dclists.h"
#include "dcmap.h"
#include "nlist.h"
#include "ntree.h"

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <setjmp.h>

#ifdef HAVE_GEOIP2

#include <maxminddb.h>

#ifndef MMDB_GTE_120
// libmaxminddb broke assumptions for code which manual recurses the data with
// the bump from 1.1.4 to 1.1.5.  We use newer/better interfaces for 1.2.0, so
// this flag is only for 1.1.x where x > 4.
static bool libmmdb_gt_114 = false;
#endif

typedef struct {
    unsigned offset;
    uint32_t dclist;
} offset_cache_item_t;
#define OFFSET_CACHE_SIZE 129113 // prime

typedef struct {
    MMDB_s mmdb;
    const dcmap_t* dcmap;
    dclists_t* dclists;
    char* map_name;
    char* pathname;
    bool is_city;
    bool is_v4;
    bool city_auto_mode;
    bool city_no_region;
    sigjmp_buf jbuf;
    offset_cache_item_t *offset_cache[OFFSET_CACHE_SIZE];
} geoip2_t;

F_NONNULL
static bool geoip2_mmdb_log_meta(const MMDB_metadata_s* meta, const char* map_name, const char* pathname) {
    char btime_str[32];
    const time_t btime = (time_t)meta->build_epoch;
    struct tm btime_tm;
    if(!gmtime_r(&btime, &btime_tm)) {
        log_err("plugin_geoip: map '%s': gmtime_r() failed", map_name);
        return false;
    }
    if(!strftime(btime_str, 32, "%F %T UTC", &btime_tm)) {
        log_err("plugin_geoip: map '%s': strftime() failed", map_name);
        return false;
    }

    log_info("plugin_geoip: map '%s': Loading GeoIP2 database '%s':"
        " Version: %" PRIu16 ".%" PRIu16
        ", Type: %s"
        ", IPVersion: %" PRIu16
        ", Timestamp: %s",
        map_name, pathname,
        meta->binary_format_major_version,
        meta->binary_format_minor_version,
        meta->database_type,
        meta->ip_version,
        btime_str
    );

    log_debug("plugin_geoip: map '%s': GeoIP2 debug metadata for '%s':"
        " RecordSize: %" PRIu16 " bits, NodeCount: %" PRIu32,
        map_name, pathname, meta->record_size, meta->node_count
    );

    return true;
}

F_NONNULL
static void geoip2_destroy(geoip2_t* db) {
    MMDB_close(&db->mmdb);
    free(db->map_name);
    free(db->pathname);
    for(unsigned i = 0; i < OFFSET_CACHE_SIZE; i++)
        free(db->offset_cache[i]);
    free(db);
}

F_NONNULLX(1,2,3)
static geoip2_t* geoip2_new(const char* pathname, const char* map_name, dclists_t* dclists, const dcmap_t* dcmap, const bool city_auto_mode, const bool city_no_region) {
    geoip2_t* db = xcalloc(1, sizeof(*db));
    int status = MMDB_open(pathname, MMDB_MODE_MMAP, &db->mmdb);
    if(status != MMDB_SUCCESS) {
        dmn_log_err("plugin_geoip: map '%s': Failed to open GeoIP2 database '%s': %s",
            map_name, pathname, MMDB_strerror(status));
        free(db);
        return NULL;
    }

    MMDB_metadata_s* meta = &db->mmdb.metadata;
    if(!geoip2_mmdb_log_meta(meta, map_name, pathname)) {
        geoip2_destroy(db);
        return NULL;
    }

    // The database format spec indicates that minor version bumps
    //   should be backwards compatible, so we only need to check
    //   the major version here.
    if(meta->binary_format_major_version != 2U) {
        dmn_log_err("plugin_geoip: map '%s': GeoIP2 database '%s' has"
            " unsupported binfmt major version %" PRIu16,
            map_name, pathname, meta->binary_format_major_version
        );
        geoip2_destroy(db);
        return NULL;
    }

    // Both our own code and the current libmaxminddb seem to have
    //   built-in assumptions based on record_size of 32 or less,
    //   yet the spec allows for larger in the future.
    if(meta->record_size > 32U) {
        dmn_log_err("plugin_geoip: map '%s': GeoIP2 database '%s' has"
            " unsupported record_size %" PRIu16,
            map_name, pathname, meta->record_size
        );
        geoip2_destroy(db);
        return NULL;
    }

    if(meta->ip_version != 4U && meta->ip_version != 6U) {
        dmn_log_err("plugin_geoip: map '%s': GeoIP2 database '%s' has"
            " unsupported ip_version %" PRIu16,
            map_name, pathname, meta->ip_version
        );
        geoip2_destroy(db);
        return NULL;
    }

    // The check for /City/ is how the official Perl API detects
    //   the City-level data model, so it's probably a reliable bet.
    // We assume anything that didn't match /City/ is a Country-level
    //   database.  This will technically "work" for GeoIP2 if there is no
    //   Country-level info, but everything will default.  So, warn about the
    //   Country defaulting if the database_type does not match /Country/.
    db->is_city = !!strstr(meta->database_type, "City");

    if(db->is_city) {
        // 1546300799 == 2018-12-31T23:59:59
        if(city_auto_mode && strstr(meta->database_type, "GeoLite2") && meta->build_epoch > (uint64_t)1546300799LLU) {
            dmn_log_err("plugin_geoip: map '%s': GeoIP2 DB '%s' appears to be a post-2018 GeoLite2-City database, which will not work with auto_dc_coords as configured because these databases lack the latitude and longitude data present in the commercial version.  See the auto_dc_coords section of the gdnsd-plugin-geoip documentation for more details.", map_name, pathname);
            geoip2_destroy(db);
            return NULL;
        }
    } else {
        if(city_auto_mode) {
            dmn_log_err("plugin_geoip: map '%s': GeoIP2 DB '%s' is not a City-level"
                " database and this map uses auto_dc_coords",
                map_name, pathname);
            geoip2_destroy(db);
            return NULL;
        }
        if(!strstr(meta->database_type, "Country"))
            dmn_log_warn("plugin_geoip: map '%s': Assuming GeoIP2 database '%s'"
                " has standard MaxMind Country data, but type is actually '%s'",
                map_name, pathname, meta->database_type
            );
    }

    db->is_v4 = meta->ip_version == 4U;
    db->city_auto_mode = city_auto_mode;
    db->city_no_region = city_no_region;
    db->pathname = strdup(pathname);
    db->map_name = strdup(map_name);
    db->dclists = dclists;
    db->dcmap = dcmap;
    return db;
}

static const char* GEOIP2_PATH_CONTINENT[] = { "continent", "code", NULL };
static const char* GEOIP2_PATH_COUNTRY[] = { "country", "iso_code", NULL };
static const char* GEOIP2_PATH_CITY[] = { "city", "names", "en", NULL };

#define mmdb_lookup_utf8_(...) do {\
    int mmrv_ = MMDB_aget_value(state->entry, &val, __VA_ARGS__);\
    if(mmrv_ == MMDB_SUCCESS && val.has_data && val.type == MMDB_DATA_TYPE_UTF8_STRING && val.utf8_string) {\
        if(lookup) {\
            memcpy(lookup, val.utf8_string, val.data_size);\
            lookup[val.data_size] = '\0';\
        }\
    }\
    else if(mmrv_ != MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {\
        dmn_log_err("plugin_geoip: map %s: Unexpected error fetching GeoIP2 data (%s)",\
            state->db->map_name, MMDB_strerror(mmrv_));\
        siglongjmp(state->db->jbuf, 1);\
    }\
} while(0)

typedef struct {
    geoip2_t* db;
    MMDB_entry_s* entry;
    bool out_of_data;
} geoip2_dcmap_cb_data_t;

F_NONNULLX(1)
static void geoip2_dcmap_cb(void* data, char* lookup, const unsigned level) {
    geoip2_dcmap_cb_data_t* state = data;

    // Explicit out-of-data set from below
    if(state->out_of_data)
        return;

    MMDB_entry_data_s val;

    if(!level) {
        mmdb_lookup_utf8_(GEOIP2_PATH_CONTINENT);
        return;
    }

    if(level == 1U) {
        mmdb_lookup_utf8_(GEOIP2_PATH_COUNTRY);
        // No further data for Country-level databases
        if(!state->db->is_city)
            state->out_of_data = true;
        return;
    }

    if(state->db->city_no_region) {
        mmdb_lookup_utf8_(GEOIP2_PATH_CITY);
        state->out_of_data = true;
        return;
    }

    // We only allow for up to 8-9 subdivision levels
    // (9 will function correctly, but then we won't bother
    //   matching city data after.  8 levels will fully function
    //   and do the city-level at the end if there's not a 9th
    //   level in the database).
    // If any country actually needs more, we'll have to change
    //   the simplistic '0' + subd_level magic below for lookup strings.
    if(level > 11U) {
        state->out_of_data = true;
        return;
    }

    // used to search/fetch subdivision array elements
    dmn_assert(level >= 2U && level <= 11U);
    const unsigned subd_level = level - 2U;
    const char idx[2] = { '0' + subd_level, '\0' };
    const char* path_subd[] = { "subdivisions", &idx[0], "iso_code", NULL };

    // fetch this level of subdivision data if possible
    int mmrv = MMDB_aget_value(state->entry, &val, path_subd);
    if(mmrv == MMDB_SUCCESS && val.has_data && val.type == MMDB_DATA_TYPE_UTF8_STRING && val.utf8_string) {
        if(lookup) {
            memcpy(lookup, val.utf8_string, val.data_size);
            lookup[val.data_size] = '\0';
        }
    }
    else if(mmrv == MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {
        // no subdivision data left, or at all to begin with,
        //   switch to city and signal end of data depth
        mmdb_lookup_utf8_(GEOIP2_PATH_CITY);
        state->out_of_data = true;
    }
    else {
        dmn_log_err("plugin_geoip: map %s: Unexpected error fetching GeoIP2City subdivision data (%s)",
            state->db->map_name, MMDB_strerror(mmrv));
        siglongjmp(state->db->jbuf, 1);
    }
}

static const char* GEOIP2_PATH_LAT[] = { "location", "latitude", NULL };
static const char* GEOIP2_PATH_LON[] = { "location", "longitude", NULL };

#define mmdb_lookup_double_(d_out, d_set, ...) do {\
    int mmrv_ = MMDB_aget_value(state.entry, &val, __VA_ARGS__);\
    if(mmrv_ == MMDB_SUCCESS && val.has_data && val.type == MMDB_DATA_TYPE_DOUBLE) {\
        d_out = val.double_value;\
        d_set = true;\
    }\
    else if(mmrv_ != MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {\
        dmn_log_err("plugin_geoip: map %s: Unexpected error fetching GeoIP2City location data (%s)",\
            state.db->map_name, MMDB_strerror(mmrv_));\
        siglongjmp(state.db->jbuf, 1);\
    }\
} while(0)

F_NONNULL
static unsigned geoip2_get_dclist(geoip2_t* db, MMDB_entry_s* db_entry) {
    // lack of both would be pointless, and is checked at outer scope
    dmn_assert(db->dcmap || db->city_auto_mode);

    geoip2_dcmap_cb_data_t state = {
        .db = db,
        .entry = db_entry,
        .out_of_data = false,
    };

#ifndef MMDB_GTE_120
    // In GeoIP2 <1.2.0, an offset of zero (before the modification below)
    // means not found in the DB, so default it.
    if(!db_entry->offset)
        return 0;

    // for 1.1.5+ (but not 1.2.0+), we must subtract
    // MMDB_DATA_SECTION_SEPARATOR (which maxminddb.c internally defines as
    // the value 16) from the offset before calling functions like
    // MMDB_aget_value()
    if(libmmdb_gt_114)
        state.entry->offset -= 16;
#endif

    uint32_t dclist = DCLIST_AUTO;

    if(db->dcmap) {
        dclist = dcmap_lookup_loc_callback(db->dcmap, geoip2_dcmap_cb, &state);
        dmn_assert(dclist == DCLIST_AUTO || dclist <= DCLIST_MAX);
    }

    if(dclist == DCLIST_AUTO) {
        dmn_assert(db->city_auto_mode && db->is_city);
        dclist = 0; // default to the default dclist

        MMDB_entry_data_s val;
        double lat = 0.0;
        bool lat_set = false;
        mmdb_lookup_double_(lat, lat_set, GEOIP2_PATH_LAT);
        if(lat_set) {
            double lon = 0.0;
            bool lon_set = false;
            mmdb_lookup_double_(lon, lon_set, GEOIP2_PATH_LON);
            if(lon_set)
                dclist = dclists_city_auto_map(db->dclists, db->map_name, lat, lon);
        }
    }

    dmn_assert(dclist != DCLIST_AUTO);
    dmn_assert(dclist <= DCLIST_MAX);
    return dclist;
}

F_NONNULL
static uint32_t geoip2_get_dclist_cached(geoip2_t* db, MMDB_entry_s* db_entry) {
    const uint32_t offset = db_entry->offset;

    unsigned bucket_size = 0;
    const unsigned ndx = offset % OFFSET_CACHE_SIZE;

    if(db->offset_cache[ndx]) {
        for(bucket_size = 0; db->offset_cache[ndx][bucket_size].dclist != UINT32_MAX; bucket_size++)
            if(db->offset_cache[ndx][bucket_size].offset == offset)
                return db->offset_cache[ndx][bucket_size].dclist;
    }

    const uint32_t dclist = geoip2_get_dclist(db, db_entry);
    db->offset_cache[ndx] = xrealloc(db->offset_cache[ndx], sizeof(offset_cache_item_t) * (bucket_size + 2));
    dmn_assert(db->offset_cache[ndx]);
    db->offset_cache[ndx][bucket_size].offset = offset;
    db->offset_cache[ndx][bucket_size].dclist = dclist;
    db->offset_cache[ndx][bucket_size + 1].dclist = UINT32_MAX;
    dmn_assert(dclist <= DCLIST_MAX); // auto not allowed here, should have been resolved earlier
    return dclist;
}

F_NONNULL
static void geoip2_list_xlate_recurse(geoip2_t* db, nlist_t* nl, struct in6_addr ip, unsigned depth, const uint32_t node_num) {
    dmn_assert(depth < 129U);

    if(!depth) {
        log_err("plugin_geoip: map '%s': GeoIP2 database '%s': Error while traversing tree nodes: depth too low", db->map_name, db->pathname);
        siglongjmp(db->jbuf, 1);
    }

    // skip v4-like spaces other than canonical compat area
    if(
        (depth == 32 && (
               !memcmp(ip.s6_addr, start_v4mapped, 12U)
            || !memcmp(ip.s6_addr, start_siit, 12U)
            || !memcmp(ip.s6_addr, start_wkp, 12U)
        ))
        || (depth == 96U && !memcmp(ip.s6_addr, start_teredo, 4U))
        || (depth == 112U && !memcmp(ip.s6_addr, start_6to4, 2U))
    )
        return;

    MMDB_search_node_s node;
    int read_rv = MMDB_read_node(&db->mmdb, node_num, &node);
    if(read_rv != MMDB_SUCCESS) {
        log_err("plugin_geoip: map '%s': GeoIP2 database '%s': Error while traversing tree nodes: %s",
            db->map_name, db->pathname, MMDB_strerror(read_rv));
        siglongjmp(db->jbuf, 1);
    }

    const unsigned new_depth = depth - 1U;
    const unsigned mask = 128U - new_depth;

#ifdef MMDB_GTE_120

    switch(node.left_record_type) {
        case MMDB_RECORD_TYPE_SEARCH_NODE:
            geoip2_list_xlate_recurse(db, nl, ip, new_depth, node.left_record);
            break;
        case MMDB_RECORD_TYPE_EMPTY:
            nlist_append(nl, ip.s6_addr, mask, 0);
            break;
        case MMDB_RECORD_TYPE_DATA:
            nlist_append(nl, ip.s6_addr, mask,
                geoip2_get_dclist_cached(db, &node.left_record_entry));
            break;
        default:
            dmn_log_err("plugin_geoip: map %s: GeoIP2 data invalid left of node %u", db->map_name, node_num);
            siglongjmp(db->jbuf, 1);
    }

    SETBIT_v6(ip.s6_addr, mask - 1U);

    switch(node.right_record_type) {
        case MMDB_RECORD_TYPE_SEARCH_NODE:
            geoip2_list_xlate_recurse(db, nl, ip, new_depth, node.right_record);
            break;
        case MMDB_RECORD_TYPE_EMPTY:
            nlist_append(nl, ip.s6_addr, mask, 0);
            break;
        case MMDB_RECORD_TYPE_DATA:
            nlist_append(nl, ip.s6_addr, mask,
                geoip2_get_dclist_cached(db, &node.right_record_entry));
            break;
        default:
            dmn_log_err("plugin_geoip: map %s: GeoIP2 data invalid right of node %u", db->map_name, node_num);
            siglongjmp(db->jbuf, 1);
    }

#else // mmdb < 1.2.0

    const uint32_t node_count = db->mmdb.metadata.node_count;

    const uint32_t zero_node_num = node.left_record;
    if(zero_node_num >= node_count) {
        MMDB_entry_s e = { .mmdb = &db->mmdb, .offset = zero_node_num - node_count };
        nlist_append(nl, ip.s6_addr, mask, geoip2_get_dclist_cached(db, &e));
    }
    else {
        geoip2_list_xlate_recurse(db, nl, ip, new_depth, zero_node_num);
    }

    SETBIT_v6(ip.s6_addr, mask - 1U);

    const uint32_t one_node_num = node.right_record;
    if(one_node_num >= node_count) {
        MMDB_entry_s e = { .mmdb = &db->mmdb, .offset = one_node_num - node_count };
        nlist_append(nl, ip.s6_addr, mask, geoip2_get_dclist_cached(db, &e));
    }
    else {
        geoip2_list_xlate_recurse(db, nl, ip, new_depth, one_node_num);
    }
#endif
}

F_NONNULL
static void geoip2_list_xlate(geoip2_t* db, nlist_t* nl) {
    const unsigned start_depth = db->is_v4 ? 32U : 128U;
    geoip2_list_xlate_recurse(db, nl, ip6_zero, start_depth, 0U);
}

typedef void (*ij_func_t)(geoip2_t*,nlist_t**);
F_NONNULL F_NOINLINE
static void isolate_jmp(geoip2_t* db, nlist_t** nl) {
    *nl = nlist_new(db->map_name, true);
    if(!sigsetjmp(db->jbuf, 0)) {
        geoip2_list_xlate(db, *nl);
        nlist_finish(*nl);
    }
    else {
        nlist_destroy(*nl);
        *nl = NULL;
    }
}

nlist_t* gdgeoip2_make_list(const char* pathname, const char* map_name, dclists_t* dclists, const dcmap_t* dcmap, const bool city_auto_mode, const bool city_no_region) {
    nlist_t* nl = NULL;

    geoip2_t* db = geoip2_new(pathname, map_name, dclists, dcmap, city_auto_mode, city_no_region);
    if(db) {
        if(!city_auto_mode && !dcmap) {
            log_warn("plugin_geoip: map %s: not processing GeoIP2 database '%s': no auto_dc_coords and no actual 'map', therefore nothing to do", map_name, pathname);
        }
        else {
            ij_func_t ij = &isolate_jmp;
            ij(db, &nl);
        }
        geoip2_destroy(db);
    }

    return nl;
}

void gdgeoip2_init(void) {
    unsigned x, y, z;
    if(sscanf(MMDB_lib_version(), "%3u.%3u.%3u", &x, &y, &z) == 3) {
#ifdef MMDB_GTE_120
        if(x < 1 || (x == 1 && y < 2))
            log_fatal("plugin_geoip: compiled against libmaxminddb >= 1.2.0, but runtime reports version %u.%u.%u", x, y, z);
#else
        if(x > 1 || (x == 1 && y > 1))
            log_fatal("plugin_geoip: compiled against libmaxminddb <1.2.0, but runtime reports version %u.%u.%u", x, y, z);
        if(x == 1 && y == 1 && z > 4)
            libmmdb_gt_114 = true;
#endif
    }
    else {
        log_fatal("plugin_geoip: Cannot determine runtime version of libmaxminddb");
    }
}

#else // HAVE_GEOIP2

nlist_t* gdgeoip2_make_list(const char* pathname, const char* map_name, dclists_t* dclists V_UNUSED, const dcmap_t* dcmap V_UNUSED, const bool city_auto_mode V_UNUSED, const bool city_no_region V_UNUSED) {
    dmn_assert(pathname); dmn_assert(map_name); dmn_assert(dclists);
    log_fatal("plugin_geoip: map '%s': GeoIP2 support needed by '%s' not included in this build!", map_name, pathname);
    return NULL; // unreachable
}

void gdgeoip2_init(void) { }

#endif
