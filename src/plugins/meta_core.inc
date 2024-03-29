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

// This isn't a valid whole source file, it is #included
//   from geoip.c and metafo.c as common, shared code
//   using macro constructs and pre-defined static function
//   names to differentiate.

// forward slashes are not allowed in configured
//  resource names for this plugin, because that's
//  used as a delimiter for synthetic resources...

// only 24 bits storage for true resource numbers,
//  which are indices to the resources[] array.

// upper 8-bits of resource numbers, as communicated
//  to/from the rest of gdnsd, are for synthetic
//  sub-resources that reference a particular datacenter
//  index within the resource directly. e.g. given
//  two datacenters named "us" and "eu":
//     www    DYNA metafo!web
//     www-us DYNA metafo!web/us
//     www-eu DYNA metafo!web/eu

static const unsigned DC_SHIFT      = 24U;
static const unsigned MAX_RESOURCES = 0x01000000U; // as a count
static const unsigned RES_MASK      = 0x00FFFFFFU;
static const unsigned DC_MASK       = 0xFF000000U;

static const char DEFAULT_SVCNAME[] = "up";

typedef struct {
    char* dc_name; // if NULL, the whole structure is invalid (dc not defined for this res)
    unsigned map_mon_idx; // admin state for map-level datacenter, only used by plugin_geoip
    unsigned dc_mon_idx; // admin state for the datacenter itself, in this resource
    bool is_cname; // which union member below
    union {
        struct { // sub-plugin case
            const plugin_t* plugin;
            char* plugin_name;
            char* res_name;
            unsigned res_num;
        };
        struct { // cname case
            uint8_t* dname;
            unsigned* indices;
            unsigned num_svcs;
        };
    };
} dc_t;

// resource_t:
// num_dcs - just copies the map-level total dc count
// num_dcs_defined - the count of DCs actually defined in this resource
// dcs - this is an array of structures, where the array indices are the dc
//       numbers from the map, and is allocated to num_dcs + 1.  Since dc
//       numbers from the map start at "1", the 0 index of this array is unused
//       and all-zeros.  Any dc from the map which is not defined for this
//       resource will also be all-zeros, and thus we detect this case by
//       checking NULL-ness of dcs[x].dc_name
// skip_first - Boolean - if true, if there is more than one defined datacenter
//       result for a resource, the first datacenter will be skipped.  This
//       allows defining a "second choice" resource from the same map
//       definition as the primary choice for geoip.

typedef struct {
    char* name;
    dc_t* dcs;
    unsigned map;
    unsigned num_dcs;
    unsigned num_dcs_defined;
    bool skip_first;
} resource_t;

static unsigned num_res;
static resource_t* resources;

// retval is new storage.
// "plugin", if existed in config, will be marked afterwards
F_NONNULL
static char* get_defaulted_plugname(const vscf_data_t* cfg, const char* resname, const char* dcname)
{
    char* rv;
    vscf_data_t* plugname_data = vscf_hash_get_data_byconstkey(cfg, "plugin", true);
    if (plugname_data) {
        if (!vscf_is_simple(plugname_data))
            log_fatal("plugin_" PNSTR ": resource '%s': datacenter '%s': value of 'plugin' must be a string", resname, dcname);
        rv = xstrdup(vscf_simple_get_data(plugname_data));
    } else {
        rv = xstrdup("multifo");
    }

    return rv;
}

F_NONNULL
static void inject_child_plugin_config(dc_t* this_dc, const char* resname, vscf_data_t* cfg)
{
    gdnsd_assert(this_dc->dc_name);

    char* child_resname = gdnsd_str_combine_n(5, PNSTR, "_", resname, "_", this_dc->dc_name);
    this_dc->res_name = child_resname;

    // Move up 2 layers: dcX -> dcmap -> resX
    vscf_data_t* res_cfg = cfg;
    for (unsigned i = 0; i < 2; i++) {
        res_cfg = vscf_get_parent(res_cfg);
        gdnsd_assert(res_cfg);
    }

    // Move up 3 more layers:
    //   resX -> resources -> metafo|geoip -> plugins
    vscf_data_t* plugins_top = res_cfg;
    for (unsigned i = 0; i < 3; i++) {
        plugins_top = vscf_get_parent(plugins_top);
        gdnsd_assert(plugins_top);
    }

    // synth multifo stanza for: dc1 => 192.0.2.1, or dc1 => [ 192.0.2.1, ... ]
    bool cfg_synthed = false;
    if (!vscf_is_hash(cfg)) { // synthesize a hash for multifo for single/array
        vscf_data_t* newhash = vscf_hash_new();
        vscf_data_t* plugname_cfg = vscf_simple_new("multifo", 7);
        gdnsd_assert(plugname_cfg);
        vscf_hash_add_val("plugin", 6, newhash, plugname_cfg);
        const unsigned alen = vscf_array_get_len(cfg);
        for (unsigned i = 0; i < alen; i++) {
            const vscf_data_t* this_addr_cfg = vscf_array_get_data(cfg, i);
            if (!vscf_is_simple(this_addr_cfg))
                log_fatal("plugin_" PNSTR ": resource '%s': datacenter '%s': if defined as an array, array values must all be address strings", resname, this_dc->dc_name);
            const unsigned lnum = i + 1;
            char lbuf[12];
            snprintf(lbuf, 12, "%u", lnum);
            vscf_hash_add_val(lbuf, strlen(lbuf), newhash, vscf_clone(this_addr_cfg, false));
        }
        cfg_synthed = true;
        cfg = newhash;
    }

    // inherit resource-level stuff down to dc-level
    vscf_hash_inherit_all(res_cfg, cfg, true);

    this_dc->plugin_name = get_defaulted_plugname(cfg, resname, this_dc->dc_name);
    if (!strcmp(this_dc->plugin_name, PNSTR))
        log_fatal("plugin_" PNSTR ": resource '%s': datacenter '%s': plugin_" PNSTR " cannot synthesize config for itself...", resname, this_dc->dc_name);

    // Create top-level plugins => { foo => {} } if necc
    vscf_data_t* plug_cfg = vscf_hash_get_data_bystringkey(plugins_top, this_dc->plugin_name, false);
    if (!plug_cfg) {
        plug_cfg = vscf_hash_new();
        vscf_hash_add_val(this_dc->plugin_name, strlen(this_dc->plugin_name), plugins_top, plug_cfg);
    }

    // special-case for geoip -> metafo synthesis, use resources sub-stanza
    if (!strcmp(this_dc->plugin_name, "metafo")) {
        vscf_data_t* synth_res_cfg = vscf_hash_get_data_byconstkey(plug_cfg, "resources", false);
        if (!synth_res_cfg) {
            synth_res_cfg = vscf_hash_new();
            vscf_hash_add_val("resources", strlen("resources"), plug_cfg, synth_res_cfg);
        }
        plug_cfg = synth_res_cfg; // for below
    }

    // Check if resource already exists
    if (vscf_hash_get_data_bystringkey(plug_cfg, child_resname, false))
        log_fatal("plugin_" PNSTR ": resource '%s': datacenter '%s': synthesis of resource '%s' for plugin '%s' failed (resource name already exists)", resname, this_dc->dc_name, child_resname, this_dc->plugin_name);

    // Add it, using clone() to skip marked key "plugin"
    vscf_hash_add_val(child_resname, strlen(child_resname), plug_cfg, vscf_clone(cfg, true));

    // destroy clone source if synthesized and disconnected from real config tree
    if (cfg_synthed)
        vscf_destroy(cfg);
}

F_NONNULL
static void config_res_perdc(const char* resname, const vscf_data_t* res_cfg, dc_t* this_dc, const char* dc_name, vscf_data_t* dc_data)
{
    this_dc->dc_name = xstrdup(dc_name);

    char* dc_mon_desc = gdnsd_str_combine_n(5, PNSTR, "/", resname, "/", dc_name);
    this_dc->dc_mon_idx = gdnsd_mon_admin(dc_mon_desc);
    free(dc_mon_desc);

    if (vscf_is_simple(dc_data)) {
        const char* textdata = vscf_simple_get_data(dc_data);
        if (*textdata == '%') {
            char* child_plugname = xstrdup(textdata + 1);
            this_dc->plugin_name = child_plugname;
            char* child_resname = strchr(child_plugname, '!');
            if (child_resname) {
                *child_resname++ = '\0';
                this_dc->res_name = xstrdup(child_resname);
            }
            if (!strcmp(this_dc->plugin_name, PNSTR) && !strcmp(this_dc->res_name, resname))
                log_fatal("plugin_" PNSTR ": resource '%s': not allowed to reference itself!", resname);
        } else if (*textdata == '!') {
            this_dc->res_name = xstrdup(textdata + 1);
            this_dc->plugin_name = get_defaulted_plugname(res_cfg, resname, dc_name);
            if (!strcmp(this_dc->plugin_name, PNSTR) && !strcmp(this_dc->res_name, resname))
                log_fatal("plugin_" PNSTR ": resource '%s': not allowed to reference itself!", resname);
        } else {
            gdnsd_anysin_t tempsin;
            if (gdnsd_anysin_getaddrinfo(textdata, NULL, &tempsin)) {
                // failed to parse as address, so set up direct CNAME if possible
                this_dc->is_cname = true;
                uint8_t* dname = xmalloc(256);
                dname_status_t dnstat = vscf_simple_get_as_dname(dc_data, dname);
                if (dnstat == DNAME_INVALID)
                    log_fatal("plugin_" PNSTR ": resource '%s': CNAME for datacenter '%s' is not a legal domainname", resname, dc_name);
                if (dnstat == DNAME_PARTIAL)
                    log_fatal("plugin_" PNSTR ": resource '%s': CNAME for datacenter '%s' must be fully qualified (end in dot)", resname, dc_name);
                gdnsd_assert(dnstat == DNAME_VALID);
                dname = dname_trim(dname);
                this_dc->dname = dname;

                // service_types is already inherited from top-level to res-level, this gets
                //   it from res-level.  We don't currently allow for a per-dc sevice_types for CNAME,
                //   although it could be done, probably...
                vscf_data_t* res_stypes = vscf_hash_get_data_byconstkey(res_cfg, "service_types", false);
                if (res_stypes) {
                    this_dc->num_svcs = vscf_array_get_len(res_stypes);
                    if (this_dc->num_svcs) {
                        this_dc->indices = xmalloc_n(this_dc->num_svcs, sizeof(*this_dc->indices));
                        for (unsigned i = 0; i < this_dc->num_svcs; i++) {
                            vscf_data_t* this_svc_cfg = vscf_array_get_data(res_stypes, i);
                            if (!vscf_is_simple(this_svc_cfg))
                                log_fatal("plugin_" PNSTR ": resource '%s': service_types values must be strings", resname);
                            this_dc->indices[i] = gdnsd_mon_cname(vscf_simple_get_data(this_svc_cfg), textdata, dname);
                        }
                    }
                } else {
                    this_dc->num_svcs = 1;
                    this_dc->indices = xmalloc(sizeof(*this_dc->indices));
                    this_dc->indices[0] = gdnsd_mon_cname(DEFAULT_SVCNAME, textdata, dname);
                }
            } else {
                inject_child_plugin_config(this_dc, resname, dc_data);
            }
        }
    } else {
        inject_child_plugin_config(this_dc, resname, dc_data);
    }

}

F_NONNULL
static void config_res_dcmap(resource_t* res, const vscf_data_t* res_cfg, const vscf_data_t* dcmap_cfg, const char* resname)
{
    gdnsd_assert(vscf_is_hash(dcmap_cfg));

    res->dcs = xcalloc_n((res->num_dcs + 1), sizeof(*res->dcs));
    const unsigned num_dcs_defined = res->num_dcs_defined;
    for (unsigned i = 0; i < num_dcs_defined; i++) {
        const char* dc_name = vscf_hash_get_key_byindex(dcmap_cfg, i, NULL);
        const unsigned dc_idx = map_get_dcidx(res->map, dc_name);
        if (!dc_idx)
            log_fatal("plugin_" PNSTR ": resource '%s': datacenter name '%s' is not valid", resname, dc_name);
        gdnsd_assert(dc_idx <= res->num_dcs);
        dc_t* this_dc = &res->dcs[dc_idx];
#if META_MAP_ADMIN == 1
        this_dc->map_mon_idx = map_get_mon_idx(res->map, dc_idx);
#endif
        vscf_data_t* dc_data = vscf_hash_get_data_byindex(dcmap_cfg, i);
        config_res_perdc(resname, res_cfg, this_dc, dc_name, dc_data);
    }
}

F_NONNULL
static void make_resource(resource_t* res, const char* res_name, const vscf_data_t* res_cfg, const bool undef_dc_ok)
{
    res->name = xstrdup(res_name);

    if (!vscf_is_hash(res_cfg))
        log_fatal("plugin_" PNSTR ": the value of resource '%s' must be a hash", res_name);

    res->map = res_get_mapnum(res_cfg, res_name);
    res->num_dcs = map_get_len(res->map);
    gdnsd_assert(res->num_dcs); // empty lists not allowed!

    res->skip_first = false;
    vscf_data_t* skip_first_cfg = vscf_hash_get_data_byconstkey(res_cfg, "skip_first", true);
    if (skip_first_cfg && !vscf_simple_get_as_bool(skip_first_cfg, &res->skip_first))
        log_fatal("plugin_" PNSTR ": resource '%s': option 'skip_first' must have the value 'true' or 'false'", res_name);

    // the core item: dcmap (dc -> result map)
    const vscf_data_t* dcs_cfg = vscf_hash_get_data_byconstkey(res_cfg, "dcmap", true);
    if (!dcs_cfg)
        log_fatal("plugin_" PNSTR ": resource '%s': missing required stanza 'dcmap'", res_name);
    if (!vscf_is_hash(dcs_cfg))
        log_fatal("plugin_" PNSTR ": resource '%s': 'dcmap' value must be a hash structure", res_name);
    res->num_dcs_defined = vscf_hash_get_len(dcs_cfg);

    if (undef_dc_ok) {
        if (!res->num_dcs_defined)
            log_fatal("plugin_" PNSTR ": resource '%s': 'dcmap' must define at least one datacenter", res_name);
    } else {
        if (res->num_dcs_defined != res->num_dcs)
            log_fatal("plugin_" PNSTR ": resource '%s': the dcmap does not match the datacenters list", res_name);
    }

    config_res_dcmap(res, res_cfg, dcs_cfg, res_name);
}

F_NONNULL
static gdnsd_sttl_t resolve_dc(const gdnsd_sttl_t* sttl_tbl, const dc_t* dc, const client_info_t* cinfo, dyn_result_t* result)
{
    gdnsd_sttl_t rv;

    if (dc->is_cname) { // direct CNAME
        gdnsd_assert(dc->dname);
        gdnsd_result_add_cname(result, dc->dname);
        rv = gdnsd_sttl_min(sttl_tbl, dc->indices, dc->num_svcs);
    } else {
        gdnsd_assert(dc->plugin && dc->plugin->resolve); // detected at map_res time
        rv = dc->plugin->resolve(dc->res_num, cinfo, result);
    }

#if META_MAP_ADMIN == 1
    // let forced sttl at the map level override "real" results
    if (sttl_tbl[dc->map_mon_idx] & GDNSD_STTL_FORCED)
        rv = sttl_tbl[dc->map_mon_idx];
#endif

    // let forced sttl at the dc level override both real results
    //   and map-level forcing (if both are forced and they differ,
    //   this is the more-specific of the two...)
    if (sttl_tbl[dc->dc_mon_idx] & GDNSD_STTL_FORCED)
        rv = sttl_tbl[dc->dc_mon_idx];

    return rv;
}

F_UNUSED F_NONNULL
static void resource_destroy(resource_t* res)
{
    free(res->name);
    if (res->dcs) {
        for (unsigned i = 1; i <= res->num_dcs; i++) {
            dc_t* dc = &res->dcs[i];
            if (dc->dc_name) {
                free(dc->dc_name);
                if (dc->is_cname) {
                    free(dc->dname);
                    if (dc->num_svcs)
                        free(dc->indices);
                } else {
                    free(dc->plugin_name);
                    free(dc->res_name);
                }
            }
        }
        free(res->dcs);
    }
}

F_NONNULLX(1)
static int map_res_inner(const char* resname, const uint8_t* zone_name, const char* dcname)
{
    for (unsigned i = 0; i < num_res; i++) {
        if (!strcmp(resname, resources[i].name)) { // match!
            const resource_t* res = &resources[i];
            unsigned fixed_dc_idx = 0;
            if (dcname) { // synthetic /dcname resource
                fixed_dc_idx = map_get_dcidx(resources[i].map, dcname);
                if (!fixed_dc_idx)
                    map_res_err("plugin_" PNSTR ": synthetic resource '%s/%s': datacenter '%s' does not exist for this resource", resname, dcname, dcname);
                gdnsd_assert(fixed_dc_idx < 256);
            }

            const unsigned min_dc = fixed_dc_idx ? fixed_dc_idx : 1;
            const unsigned max_dc = fixed_dc_idx ? fixed_dc_idx : res->num_dcs;
            for (unsigned j = min_dc; j <= max_dc; j++) {
                // skip if this dc is not defined for this resource
                if (!res->dcs[j].dc_name)
                    continue;
                dc_t* this_dc = &res->dcs[j];
                if (this_dc->is_cname) {
                    if (!zone_name)
                        map_res_err("plugin_" PNSTR ": resource '%s': datacenter '%s' is configured as the fixed CNAME '%s', therefore this resource cannot be used in an address-only DYNA RR", res->name, this_dc->dc_name, logf_dname(this_dc->dname));
                    const uint8_t* dname = this_dc->dname;
                    if (dname_isinzone(zone_name, dname))
                        map_res_err("plugin_" PNSTR ": resource '%s': datacenter '%s': CNAME value '%s' cannot be used from DYNC in its own zone '%s'", res->name, this_dc->dc_name, logf_dname(dname), logf_dname(zone_name));
                } else {
                    if (!this_dc->plugin) {
                        this_dc->plugin = gdnsd_plugin_find(this_dc->plugin_name);
                        if (!this_dc->plugin)
                            map_res_err("plugin_" PNSTR ": resource '%s': datacenter '%s': invalid plugin name '%s'", res->name, this_dc->dc_name, this_dc->plugin_name);
                    }

                    if (!this_dc->plugin->resolve)
                        map_res_err("plugin_" PNSTR ": resource '%s': datacenter '%s': plugin '%s' is not a resolver plugin", res->name, this_dc->dc_name, this_dc->plugin_name);

                    this_dc->res_num = 0;
                    if (this_dc->plugin->map_res) {
                        const int resnum = this_dc->plugin->map_res(this_dc->res_name, zone_name);
                        if (resnum < 0) {
                            if (zone_name)
                                map_res_err("plugin_" PNSTR ": resource '%s': datacenter '%s': plugin '%s' rejected DYNC resource name '%s' within zone '%s'", res->name, this_dc->dc_name, this_dc->plugin_name, this_dc->res_name, logf_dname(zone_name));
                            else
                                map_res_err("plugin_" PNSTR ": resource '%s': datacenter '%s': plugin '%s' rejected DYNA resource name '%s'", res->name, this_dc->dc_name, this_dc->plugin_name, this_dc->res_name);
                        }
                        this_dc->res_num = (unsigned)resnum;
                    }
                }
            }

            // Handle synthetic resname/dcname virtual resnum
            if (fixed_dc_idx)
                i |= (fixed_dc_idx << DC_SHIFT);
            return (int)i;
        }
    }

    map_res_err("plugin_" PNSTR ": Invalid resource name '%s' detected from zonefile lookup", resname);
}

/********** Callbacks from gdnsd **************/

static void CB_LOAD_CONFIG(vscf_data_t* config)
{
    if (!config)
        log_fatal("plugin_" PNSTR ": configuration required in 'plugins' stanza");

    gdnsd_assert(vscf_is_hash(config));

    const bool undef_dc_ok = top_config_hook(config);

    const vscf_data_t* resources_cfg = vscf_hash_get_data_byconstkey(config, "resources", true);
    if (!resources_cfg)
        log_fatal("plugin_" PNSTR ": config has no 'resources' stanza");
    if (!vscf_is_hash(resources_cfg))
        log_fatal("plugin_" PNSTR ": 'resources' stanza must be a hash");

    num_res = vscf_hash_get_len(resources_cfg);
    if (num_res > MAX_RESOURCES)
        log_fatal("plugin_" PNSTR ": Maximum number of resources (%u) exceeded", MAX_RESOURCES);
    if (!num_res)
        log_fatal("plugin_" PNSTR ": No resources defined");

    resources = xcalloc_n(num_res, sizeof(*resources));

    for (unsigned i = 0; i < num_res; i++) {
        resource_t* res = &resources[i];
        const char* res_name = vscf_hash_get_key_byindex(resources_cfg, i, NULL);
        vscf_data_t* res_cfg = vscf_hash_get_data_byindex(resources_cfg, i);
        if (!vscf_is_hash(res_cfg))
            log_fatal("plugin_" PNSTR ": the value of resource '%s' must be a hash", res_name);
        vscf_hash_inherit_all(config, res_cfg, true);
        make_resource(res, res_name, res_cfg, undef_dc_ok);
    }

    bottom_config_hook();
}

static int CB_MAP(const char* resname, const uint8_t* zone_name)
{
    int rv = -1;

    if (!resname) {
        log_err("plugin_" PNSTR ": a resource name is required for plugin zonefile records");
    } else {
        const char* slash = strchr(resname, '/');
        if (slash) {
            // Handle synthetic resname/dcname resources
            char* resname_copy = xstrdup(resname);
            const unsigned reslen = slash - resname;
            resname_copy[reslen] = '\0';
            const char* dcname = resname_copy + reslen + 1;
            rv = map_res_inner(resname_copy, zone_name, dcname);
            free(resname_copy);
        } else {
            rv = map_res_inner(resname, zone_name, NULL);
        }
    }

    return rv;
}

static gdnsd_sttl_t CB_RES(unsigned resnum, const client_info_t* cinfo, dyn_result_t* result)
{
    // extract and clear any datacenter index from upper 8 bits
    //  (used for synthetic resname/dcname resources)
    const unsigned synth_dc = (resnum & DC_MASK) >> DC_SHIFT;
    const uint8_t synth_dclist[2] = { synth_dc, 0 };
    resnum &= RES_MASK;

    const resource_t* res = &resources[resnum];

    unsigned scope_mask_out = 0;
    const uint8_t* dclist;
    if (synth_dc)
        dclist = synth_dclist;
    else
        dclist = map_get_dclist(res->map, cinfo, &scope_mask_out);

    const gdnsd_sttl_t* sttl_tbl = gdnsd_mon_get_sttl_table();

    gdnsd_sttl_t rv = GDNSD_STTL_TTL_MAX;
    unsigned dcnum;

    // If the resource does not define all DCs, filter the map's dclist
    uint8_t dclist_filtered[255];
    if (res->num_dcs != res->num_dcs_defined) {
        const uint8_t* dclist_iter = dclist;
        uint8_t* dclist_filtered_iter = dclist_filtered;
        while ((dcnum = *dclist_iter++))
            if (res->dcs[dcnum].dc_name)
                *dclist_filtered_iter++ = dcnum; // *NOPAD*
        *dclist_filtered_iter = 0;
        dclist = dclist_filtered;
    }

    // If the real dclist has 2+ entries, allow skip_first to take effect
    if (res->skip_first && dclist[0] && dclist[1])
        dclist++;

    const unsigned first_dc_num = *dclist;
    if (first_dc_num) {
        // iterate datacenters until we find a success or exhaust the list
        while ((dcnum = *dclist++)) {
            gdnsd_assert(dcnum <= res->num_dcs);
            gdnsd_result_wipe(result);
            gdnsd_result_reset_scope_mask(result);
            gdnsd_sttl_t this_rv = resolve_dc(sttl_tbl, &res->dcs[dcnum], cinfo, result);
            assert_valid_sttl(this_rv);
            rv = gdnsd_sttl_min2(rv, this_rv);
            if (!(this_rv & GDNSD_STTL_DOWN)) {
                rv &= ~GDNSD_STTL_DOWN;
                break;
            }
        }

        // all datacenters failed, in which case we keep the sttl from above...
        if (rv & GDNSD_STTL_DOWN) {
            gdnsd_result_wipe(result);
            gdnsd_result_reset_scope_mask(result);
            resolve_dc(sttl_tbl, &res->dcs[first_dc_num], cinfo, result);
        }
    }

    // This automatically combines in a sane way with any scope set by a subplugin
    gdnsd_result_add_scope_mask(result, scope_mask_out);

    assert_valid_sttl(rv);
    return rv;
}
