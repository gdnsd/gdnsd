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

// libmaxminddb broke assumptions for code which manual recurses the data
// with the bump from 1.1.4 to 1.1.5.  New interfaces to fix this in the
// long term will appear in 1.2.0, I think.  For now, we set a static flag
// early in startup to address the discrepancy.
static bool libmmdb_gt_114 = false;

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
    dmn_assert(meta); dmn_assert(map_name); dmn_assert(pathname);

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
    dmn_assert(pathname); dmn_assert(map_name); dmn_assert(dclists);

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

    if(!db->is_city) {
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
    int mmrv_ = MMDB_aget_value(&state->entry, &val, __VA_ARGS__);\
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
    MMDB_entry_s entry;
    bool out_of_data;
} geoip2_dcmap_cb_data_t;

static void geoip2_dcmap_cb(void* data, char* lookup, const unsigned level) {
    dmn_assert(data);

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
    int mmrv = MMDB_aget_value(&state->entry, &val, path_subd);
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

#define mmdb_lookup_double_(d_out, ...) do {\
    int mmrv_ = MMDB_aget_value(&state.entry, &val, __VA_ARGS__);\
    if(mmrv_ == MMDB_SUCCESS && val.has_data && val.type == MMDB_DATA_TYPE_DOUBLE) {\
        d_out = val.double_value;\
    }\
    else if(mmrv_ != MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {\
        dmn_log_err("plugin_geoip: map %s: Unexpected error fetching GeoIP2City location data (%s)",\
            state.db->map_name, MMDB_strerror(mmrv_));\
        siglongjmp(state.db->jbuf, 1);\
    }\
} while(0)

F_NONNULL
static unsigned geoip2_get_dclist(geoip2_t* db, const uint32_t offset) {
    dmn_assert(db);

    if(offset > db->mmdb.data_section_size) {
        dmn_log_err("plugin_geoip: map %s: GeoIP2 data has invalid offset %u (corrupt?)", db->map_name, offset);
        siglongjmp(db->jbuf, 1);
    }

    // lack of both would be pointless, and is checked at outer scope
    dmn_assert(db->dcmap || db->city_auto_mode);

    geoip2_dcmap_cb_data_t state = {
        .db = db,
        .entry = {
            .mmdb = &db->mmdb,
            .offset = offset,
        },
        .out_of_data = false,
    };

    // for 1.1.5+, we must subtract MMDB_DATA_SECTION_SEPARATOR
    // (which maxminddb.c internally defines as the value 16) from
    // the offset before calling functions like MMDB_aget_value()
    if(libmmdb_gt_114)
        state.entry.offset -= 16;

    uint32_t dclist = DCLIST_AUTO;

    if(db->dcmap) {
        dclist = dcmap_lookup_loc_callback(db->dcmap, geoip2_dcmap_cb, &state);
        dmn_assert(dclist == DCLIST_AUTO || dclist <= DCLIST_MAX);
    }

    if(dclist == DCLIST_AUTO) {
        dmn_assert(db->city_auto_mode && db->is_city);

        double lat = 0.0;
        double lon = 0.0;
        MMDB_entry_data_s val;
        mmdb_lookup_double_(lat, GEOIP2_PATH_LAT);
        mmdb_lookup_double_(lon, GEOIP2_PATH_LON);
        dclist = dclists_city_auto_map(db->dclists, db->map_name, lat, lon);
        dmn_assert(dclist != DCLIST_AUTO);
        dmn_assert(dclist <= DCLIST_MAX);
    }

    dmn_assert(dclist != DCLIST_AUTO);
    dmn_assert(dclist <= DCLIST_MAX);
    return dclist;
}

F_NONNULL
static uint32_t geoip2_get_dclist_cached(geoip2_t* db, const uint32_t offset) {
    dmn_assert(db);

    // In GeoIP2, an offset of zero means not found in the DB, so default it.
    // (even if it works in geoip2_get_dclist(), the offset cache can't handle
    // an offset of zero efficiently anyways).
    if(!offset)
        return 0;

    unsigned bucket_size = 0;
    const unsigned ndx = offset % OFFSET_CACHE_SIZE;

    if(db->offset_cache[ndx]) {
        for(bucket_size = 0; db->offset_cache[ndx][bucket_size].offset; bucket_size++)
            if(db->offset_cache[ndx][bucket_size].offset == offset)
                return db->offset_cache[ndx][bucket_size].dclist;
    }

    const uint32_t dclist = geoip2_get_dclist(db, offset);
    db->offset_cache[ndx] = xrealloc(db->offset_cache[ndx], sizeof(offset_cache_item_t) * (bucket_size + 2));
    dmn_assert(db->offset_cache[ndx]);
    db->offset_cache[ndx][bucket_size].offset = offset;
    db->offset_cache[ndx][bucket_size].dclist = dclist;
    db->offset_cache[ndx][bucket_size + 1].offset = 0;
    dmn_assert(dclist <= DCLIST_MAX); // auto not allowed here, should have been resolved earlier
    return dclist;
}

F_NONNULL
static void geoip2_list_xlate_recurse(geoip2_t* db, nlist_t* nl, struct in6_addr ip, unsigned depth, const uint32_t node_count, const uint32_t node_num) {
    dmn_assert(db); dmn_assert(nl);
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

    const uint32_t zero_node_num = node.left_record;
    const uint32_t one_node_num = node.right_record;
    const unsigned new_depth = depth - 1U;
    const unsigned mask = 128U - new_depth;

    if(zero_node_num >= node_count)
        nlist_append(nl, ip.s6_addr, mask, geoip2_get_dclist_cached(db, zero_node_num - node_count));
    else
        geoip2_list_xlate_recurse(db, nl, ip, new_depth, node_count, zero_node_num);

    SETBIT_v6(ip.s6_addr, mask - 1U);

    if(one_node_num >= node_count)
        nlist_append(nl, ip.s6_addr, mask, geoip2_get_dclist_cached(db, one_node_num - node_count));
    else
        geoip2_list_xlate_recurse(db, nl, ip, new_depth, node_count, one_node_num);
}

static void geoip2_list_xlate(geoip2_t* db, nlist_t* nl) {
    const uint32_t node_count = db->mmdb.metadata.node_count;
    const unsigned start_depth = db->is_v4 ? 32U : 128U;
    geoip2_list_xlate_recurse(db, nl, ip6_zero, start_depth, node_count, 0U);
}

typedef void (*ij_func_t)(geoip2_t*,nlist_t**);
F_NONNULL F_NOINLINE
static void isolate_jmp(geoip2_t* db, nlist_t** nl) {
    dmn_assert(db); dmn_assert(nl);

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
    dmn_assert(pathname); dmn_assert(map_name); dmn_assert(dclists);

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
    if(sscanf(MMDB_lib_version(), "%3u.%3u.%3u", &x, &y, &z) == 3)
        if(x > 1 || (x == 1 && (y > 1 || (y == 1 && z > 4))))
            libmmdb_gt_114 = true;
}

#else // HAVE_GEOIP2

nlist_t* gdgeoip2_make_list(const char* pathname, const char* map_name, dclists_t* dclists V_UNUSED, const dcmap_t* dcmap V_UNUSED, const bool city_auto_mode V_UNUSED, const bool city_no_region V_UNUSED) {
    dmn_assert(pathname); dmn_assert(map_name); dmn_assert(dclists);
    log_fatal("plugin_geoip: map '%s': GeoIP2 support needed by '%s' not included in this build!", map_name, pathname);
    return NULL; // unreachable
}

void gdgeoip2_init(void) { }

#endif
