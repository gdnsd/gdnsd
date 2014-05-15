/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
 *
 * This file is part of gdnsd
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

static const char DEFAULT_SVCNAME[] = "default";

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

typedef struct {
    const plugin_t* plugin;
    unsigned res_num_dyna;
    unsigned res_num_dync;
    char* plugin_name;
    char* res_name;
    char* dc_name;
    uint8_t* dname; // for direct DYNC, and the "invalid" case
} dc_t;

typedef struct {
    char* name;
    dc_t* dcs;
    unsigned map;
    unsigned num_dcs;
} resource_t;

static unsigned num_res;
static resource_t* resources;

F_NONNULL
static char* make_synth_resname(const char* resname, const char* dcname) {
    dmn_assert(resname); dmn_assert(dcname);
    const unsigned rnlen = strlen(resname);
    const unsigned dclen = strlen(dcname);
    const unsigned pnlen = strlen(PNSTR);
    char* synth_resname = malloc(rnlen + dclen + pnlen + 3);
    char* srptr = synth_resname;
    memcpy(srptr, PNSTR, pnlen); srptr += pnlen;
    *srptr++ = '_';
    memcpy(srptr, resname, rnlen); srptr += rnlen;
    *srptr++ = '_';
    memcpy(srptr, dcname, dclen); srptr += dclen;
    *srptr++ = '\0';
    return synth_resname;
}

// retval is new storage.
// "plugin", if existed in config, will be marked afterwards
F_NONNULL
static char* get_defaulted_plugname(const vscf_data_t* cfg, const char* resname, const char* dcname) {
    dmn_assert(cfg);

    char* rv;
    const vscf_data_t* plugname_data = vscf_hash_get_data_byconstkey(cfg, "plugin", true);
    if(plugname_data) {
        if(!vscf_is_simple(plugname_data))
            log_fatal("plugin_" PNSTR ": resource '%s': datacenter '%s': value of 'plugin' must be a string", resname, dcname);
        rv = strdup(vscf_simple_get_data(plugname_data));
    }
    else {
        rv = strdup("multifo");
    }

    return rv;
}

F_NONNULL
static void inject_child_plugin_config(dc_t* this_dc, const char* resname, vscf_data_t* cfg) {
    dmn_assert(this_dc); dmn_assert(resname); dmn_assert(cfg);

    char* child_resname = make_synth_resname(resname, this_dc->dc_name);
    this_dc->res_name = child_resname;

    // Move up 2 layers: dcX -> dcmap -> resX
    vscf_data_t* res_cfg = (vscf_data_t*)cfg;
    for(unsigned i = 0; i < 2; i++) {
        res_cfg = (vscf_data_t*)vscf_get_parent(res_cfg);
        dmn_assert(res_cfg);
    }

    // Move up 3 more layers:
    //   resX -> resources -> metafo|geoip -> plugins
    vscf_data_t* plugins_top = res_cfg;
    for(unsigned i = 0; i < 3; i++) {
        plugins_top = (vscf_data_t*)vscf_get_parent(plugins_top);
        dmn_assert(plugins_top);
    }

    // synth multifo stanza for: dc1 => 192.0.2.1, or dc1 => [ 192.0.2.1, ... ]
    bool cfg_synthed = false;
    if(!vscf_is_hash(cfg)) { // synthesize a hash for multifo for single/array
        vscf_data_t* newhash = vscf_hash_new();
        vscf_data_t* plugname_cfg = vscf_simple_new("multifo", 7);
        vscf_hash_add_val("plugin", 6, newhash, plugname_cfg);
        const unsigned alen = vscf_array_get_len(cfg);
        for(unsigned i = 0; i < alen; i++) {
            const vscf_data_t* this_addr_cfg = vscf_array_get_data(cfg, i);
            if(!vscf_is_simple(this_addr_cfg))
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
    if(!strcmp(this_dc->plugin_name, PNSTR))
        log_fatal("plugin_" PNSTR ": resource '%s': datacenter '%s': plugin_" PNSTR " cannot synthesize config for itself...", resname, this_dc->dc_name);

    // Create top-level plugins => { foo => {} } if necc
    vscf_data_t* plug_cfg = (vscf_data_t*)vscf_hash_get_data_bystringkey(plugins_top, this_dc->plugin_name, false);
    if(!plug_cfg) {
        plug_cfg = vscf_hash_new();
        vscf_hash_add_val(this_dc->plugin_name, strlen(this_dc->plugin_name), plugins_top, plug_cfg);
    }

    // special-case for geoip -> metafo synthesis, use resources sub-stanza
    if(!strcmp(this_dc->plugin_name, "metafo")) {
        vscf_data_t* synth_res_cfg = (vscf_data_t*)vscf_hash_get_data_byconstkey(plug_cfg, "resources", false);
        if(!synth_res_cfg) {
            synth_res_cfg = vscf_hash_new();
            vscf_hash_add_val("resources", strlen("resources"), plug_cfg, synth_res_cfg);
        }
        plug_cfg = synth_res_cfg; // for below
    }

    // Check if resource already exists
    if(vscf_hash_get_data_bystringkey(plug_cfg, child_resname, false))
        log_fatal("plugin_" PNSTR ": resource '%s': datacenter '%s': synthesis of resource '%s' for plugin '%s' failed (resource name already exists)", resname, this_dc->dc_name, child_resname, this_dc->plugin_name);

    // Add it, using clone() to skip marked key "plugin"
    vscf_hash_add_val(child_resname, strlen(child_resname), plug_cfg, vscf_clone(cfg, true));

    // destroy clone source if synthesized and disconnected from real config tree
    if(cfg_synthed) vscf_destroy(cfg);
}

F_NONNULL
static dc_t* config_res_perdc(const unsigned mapnum, const vscf_data_t* cfg, const char* resname) {
    dmn_assert(cfg); dmn_assert(resname);
    dmn_assert(vscf_is_hash(cfg));

    const unsigned num_dcs = vscf_hash_get_len(cfg);
    dc_t* store = calloc((num_dcs + 1), sizeof(dc_t));
    for(unsigned i = 0; i < num_dcs; i++) {
        const char* dcname = vscf_hash_get_key_byindex(cfg, i, NULL);
        const unsigned dc_idx = map_get_dcidx(mapnum, dcname);
        if(!dc_idx)
            log_fatal("plugin_" PNSTR ": resource '%s': datacenter name '%s' is not valid", resname, dcname);
        dmn_assert(dc_idx <= num_dcs);
        dc_t* this_dc = &store[dc_idx];
        this_dc->dc_name = strdup(dcname);
        const vscf_data_t* plugdata = vscf_hash_get_data_byindex(cfg, i);
        if(vscf_is_simple(plugdata)) {
            const char* textdata = vscf_simple_get_data(plugdata);
            if(*textdata == '%') {
                char* child_plugname = strdup(textdata + 1);
                this_dc->plugin_name = child_plugname;
                char* child_resname = strchr(child_plugname, '!');
                if(child_resname) {
                    *child_resname++ = '\0';
                    this_dc->res_name = strdup(child_resname);
                }
                if(!strcmp(this_dc->plugin_name, PNSTR) && !strcmp(this_dc->res_name, resname))
                    log_fatal("plugin_" PNSTR ": resource '%s': not allowed to reference itself!", resname);
            }
            else if(*textdata == '!') {
                this_dc->res_name = strdup(textdata + 1);
                const vscf_data_t* res_cfg = vscf_get_parent(cfg);
                this_dc->plugin_name = get_defaulted_plugname(res_cfg, resname, dcname);
                if(!strcmp(this_dc->plugin_name, PNSTR) && !strcmp(this_dc->res_name, resname))
                    log_fatal("plugin_" PNSTR ": resource '%s': not allowed to reference itself!", resname);
            }
            else {
                anysin_t tempsin;
                if(gdnsd_anysin_getaddrinfo(textdata, NULL, &tempsin)) {
                    // failed to parse as address, so set up direct CNAME if possible
                    uint8_t* dname = malloc(256);
                    dname_status_t dnstat = vscf_simple_get_as_dname(plugdata, dname);
                    if(dnstat == DNAME_INVALID)
                        log_fatal("plugin_" PNSTR ": resource '%s': CNAME for datacenter '%s' is not a legal domainname", resname, dcname);
                    if(dnstat == DNAME_VALID)
                        dname = dname_trim(dname);
                    this_dc->dname = dname;
                }
                else {
                    inject_child_plugin_config(this_dc, resname, (vscf_data_t*)plugdata);
                }
            }
        }
        else {
            inject_child_plugin_config(this_dc, resname, (vscf_data_t*)plugdata);
        }
    }
    return store;
}

F_NONNULL
static void make_resource(resource_t* res, const char* res_name, const vscf_data_t* res_cfg) {
    dmn_assert(res);
    dmn_assert(res_name);
    dmn_assert(res_cfg);

    res->name = strdup(res_name);

    if(!vscf_is_hash(res_cfg))
        log_fatal("plugin_" PNSTR ": the value of resource '%s' must be a hash", res_name);

    res->map = res_get_mapnum(res_cfg, res_name);
    unsigned dc_count = map_get_len(res->map);
    dmn_assert(dc_count); // empty lists not allowed!

    // the core item: dcmap (dc -> result map)
    const vscf_data_t* dcs_cfg = vscf_hash_get_data_byconstkey(res_cfg, "dcmap", true);
    if(!dcs_cfg)
        log_fatal("plugin_" PNSTR ": resource '%s': missing required stanza 'dcmap'", res_name);
    if(!vscf_is_hash(dcs_cfg))
        log_fatal("plugin_" PNSTR ": resource '%s': 'dcmap' value must be a hash structure", res_name);

    // Get/check datacenter count
    res->num_dcs = vscf_hash_get_len(dcs_cfg);

    if(res->num_dcs != dc_count)
        log_fatal("plugin_" PNSTR ": resource '%s': the dcmap does not match the datacenters list", res_name);

    res->dcs = config_res_perdc(res->map, dcs_cfg, res_name);
}

F_UNUSED F_NONNULL
static void resource_destroy(resource_t* res) {
    dmn_assert(res);
    free(res->name);
    if(res->dcs) {
        for(unsigned i = 1; i <= res->num_dcs; i++) {
            dc_t* dc = &res->dcs[i];
            free(dc->plugin_name);
            free(dc->res_name);
            free(dc->dc_name);
            if(dc->dname)
                free(dc->dname);
        }
        free(res->dcs);
    }
}

F_NONNULLX(1)
static int map_res_inner(const char* resname, const uint8_t* origin V_UNUSED, const char* dcname) {
    dmn_assert(resname);

    for(unsigned i = 0; i < num_res; i++) {
        if(!strcmp(resname, resources[i].name)) { // match!
            const resource_t* res = &resources[i];
            unsigned fixed_dc_idx = 0;
            if(dcname) { // synthetic /dcname resource
                fixed_dc_idx = map_get_dcidx(resources[i].map, dcname);
                if(!fixed_dc_idx) {
                    log_err("plugin_" PNSTR ": synthetic resource '%s/%s': datacenter '%s' does not exist for this resource", resname, dcname, dcname);
                    return -1;
                }
                dmn_assert(fixed_dc_idx < 256);
            }

#if DYNC_OK
            // DYNC case, check origin + applicable datacenter(s)
            if(origin) {
                const unsigned min_dc = fixed_dc_idx ? fixed_dc_idx : 1;
                const unsigned max_dc = fixed_dc_idx ? fixed_dc_idx : res->num_dcs;
                for(unsigned j = min_dc; j <= max_dc; j++) {
                    dc_t* this_dc = &res->dcs[j];
                    if(this_dc->dname) {
                        const uint8_t* dname = this_dc->dname;
                        if(dname_status(dname) == DNAME_PARTIAL) {
                            uint8_t dnbuf[256];
                            dname_copy(dnbuf, dname);
                            if(dname_cat(dnbuf, origin) != DNAME_VALID) {
                                log_err("plugin_" PNSTR ": Name '%s' of resource '%s', when used at origin '%s', produces an invalid domainname", logf_dname(dname), res->name, logf_dname(origin));
                                return -1;
                            }
                        }
                    }
                    else {
                        if(!this_dc->plugin)
                            this_dc->plugin = gdnsd_plugin_find(this_dc->plugin_name);
                        // XXX shouldn't these basic find/check operations on plugin_name be up at full_config time?
                        if(!this_dc->plugin) {
                            log_err("plugin_" PNSTR ": resource '%s': addrs datacenter '%s': invalid plugin name '%s'", res->name, this_dc->dc_name, this_dc->plugin_name);
                            return -1;
                        }
                        if(!this_dc->plugin->resolve_dyncname) {
                            log_err("plugin_" PNSTR ": resource '%s': addrs datacenter '%s': plugin '%s' does not support DYNC resources", res->name, this_dc->dc_name, this_dc->plugin_name);
                            return -1;
                        }
                        if(this_dc->plugin->map_resource_dync) {
                            const int resnum = this_dc->plugin->map_resource_dync(this_dc->res_name, origin);
                            if(resnum < 0) {
                                log_err("plugin_" PNSTR ": resource '%s': addrs datacenter '%s': plugin '%s' rejected DYNC resource name '%s' at origin '%s'", res->name, this_dc->dc_name, this_dc->plugin_name, this_dc->res_name, logf_dname(origin));
                                return -1;
                            }
                            this_dc->res_num_dync = (unsigned)resnum;
                        }
                        else {
                            this_dc->res_num_dync = 0;
                        }
                    }
                }
            }
            else {
#else
            dmn_assert(!origin);
            {
#endif // DYNC_OK
                // DYNA case, check applicable datacenter(s)
                const unsigned min_dc = fixed_dc_idx ? fixed_dc_idx : 1;
                const unsigned max_dc = fixed_dc_idx ? fixed_dc_idx : res->num_dcs;
                for(unsigned j = min_dc; j <= max_dc; j++) {
                    dc_t* this_dc = &res->dcs[j];
                    if(this_dc->dname) {
                        log_err("plugin_" PNSTR ": resource '%s': datacenter '%s': DYNC-only (fixed cname), used as DYNA data in a zonefile", res->name, this_dc->dc_name);
                        return -1;
                    }
                    // XXX shouldn't these basic find/check operations on plugin_name be up at full_config time?
                    if(!this_dc->plugin)
                        this_dc->plugin = gdnsd_plugin_find(this_dc->plugin_name);
                    if(!this_dc->plugin) {
                        log_err("plugin_" PNSTR ": resource '%s': addrs datacenter '%s': invalid plugin name '%s'", res->name, this_dc->dc_name, this_dc->plugin_name);
                        return -1;
                    }
                    if(!this_dc->plugin->resolve_dynaddr) {
                        log_err("plugin_" PNSTR ": resource '%s': addrs datacenter '%s': plugin '%s' does not support DYNA resources", res->name, this_dc->dc_name, this_dc->plugin_name);
                        return -1;
                    }
                    if(this_dc->plugin->map_resource_dyna) {
                        const int resnum = this_dc->plugin->map_resource_dyna(this_dc->res_name);
                        if(resnum < 0) {
                            log_err("plugin_" PNSTR ": resource '%s': addrs datacenter '%s': plugin '%s' rejected DYNA resource name '%s'", res->name, this_dc->dc_name, this_dc->plugin_name, this_dc->res_name);
                            return -1;
                        }
                        this_dc->res_num_dyna = (unsigned)resnum;
                    }
                    else {
                        this_dc->res_num_dyna = 0;
                    }
                }
            }

            // Handle synthetic resname/dcname virtual resnum
            if(fixed_dc_idx)
                i |= (fixed_dc_idx << DC_SHIFT);
            return (int)i;
        }
    }

    log_err("plugin_" PNSTR ": Invalid resource name '%s' detected from zonefile lookup", resname);
    return -1;
}

// NULL-ness of "origin" indicates DYNC vs DYNA lookup here...
static int map_res(const char* resname, const uint8_t* origin) {
    int rv = -1;

    if(!resname) {
        log_err("plugin_" PNSTR ": a resource name is required for plugin zonefile records");
    }
    else {
        const char* slash = strchr(resname, '/');
        if(slash) {
            // Handle synthetic resname/dcname resources
            char* resname_copy = strdup(resname);
            const unsigned reslen = slash - resname;
            resname_copy[reslen] = '\0';
            char* dcname = resname_copy + reslen + 1;
            rv = map_res_inner(resname_copy, origin, dcname);
            free(resname_copy);
        }
        else {
            rv = map_res_inner(resname, origin, NULL);
        }
    }

    return rv;
}

/********** Callbacks from gdnsd **************/

mon_list_t* CB_LOAD_CONFIG(const vscf_data_t* config) {
    if(!config)
        log_fatal("plugin_" PNSTR ": configuration required in 'plugins' stanza");

    dmn_assert(vscf_is_hash(config));

    top_config_hook(config);
    const vscf_data_t* resources_cfg = vscf_hash_get_data_byconstkey(config, "resources", true);
    if(!resources_cfg)
        log_fatal("plugin_" PNSTR ": config has no 'resources' stanza");
    if(!vscf_is_hash(resources_cfg))
        log_fatal("plugin_" PNSTR ": 'resources' stanza must be a hash");

    num_res = vscf_hash_get_len(resources_cfg);
    if(num_res > MAX_RESOURCES)
        log_fatal("plugin_" PNSTR ": Maximum number of resources (%u) exceeded", MAX_RESOURCES);

    resources = calloc(num_res, sizeof(resource_t));

    for(unsigned i = 0; i < num_res; i++) {
        resource_t* res = &resources[i];
        const char* res_name = vscf_hash_get_key_byindex(resources_cfg, i, NULL);
        vscf_data_t* res_cfg = (vscf_data_t*)vscf_hash_get_data_byindex(resources_cfg, i);
        if(!vscf_is_hash(res_cfg))
            log_fatal("plugin_" PNSTR ": the value of resource '%s' must be a hash", res_name);
        vscf_hash_inherit_all(config, res_cfg, true);
        make_resource(res, res_name, res_cfg);
    }

    return NULL;
}

int CB_MAP_A(const char* resname) {
    return map_res(resname, NULL);
}

#if DYNC_OK
int CB_MAP_C(const char* resname, const uint8_t* origin) {
    return map_res(resname, origin);
}
#endif

F_NONNULL
bool CB_RES_A(unsigned threadnum V_UNUSED, unsigned resnum, const client_info_t* cinfo, dynaddr_result_t* result) {
    dmn_assert(cinfo); dmn_assert(result);

    // extract and clear any datacenter index from upper 8 bits
    //  (used for synthetic resname/dcname resources)
    const unsigned synth_dc = (resnum & DC_MASK) >> DC_SHIFT;
    const uint8_t synth_dclist[2] = { synth_dc, 0 };
    resnum &= RES_MASK;

    const resource_t* res = &resources[resnum];

    // save ttl across multiple lower-level wipe/recalls
    unsigned saved_ttl = result->ttl;

    unsigned scope_mask_out = 0;
    const uint8_t* dclist;
    if(synth_dc)
        dclist = synth_dclist;
    else
        dclist = map_get_dclist(res->map, cinfo, &scope_mask_out);

    bool rv = true;

    // empty dclist -> no results
    unsigned first_dc_num = *dclist;
    if(first_dc_num) {
        // iterate datacenters until we find a success or exhaust the list
        bool success = false;
        unsigned dcnum;
        while(!success && (dcnum = *dclist++)) {
            dmn_assert(dcnum <= res->num_dcs);
            memset(result, 0, sizeof(dynaddr_result_t));
            result->ttl = saved_ttl;
            const dc_t* dc = &res->dcs[dcnum];
            success = dc->plugin->resolve_dynaddr(threadnum, dc->res_num_dyna, cinfo, result);
        }

        // all datacenters failed, flag failure upstream (if any upstream) and use first dc
        if(!success) {
            memset(result, 0, sizeof(dynaddr_result_t));
            result->ttl = saved_ttl;
            const dc_t* dc = &res->dcs[first_dc_num];
            dc->plugin->resolve_dynaddr(threadnum, dc->res_num_dyna, cinfo, result);
            rv = false;
        }
    }

    // if both our map_get_dclist() and the subplugin tried to set a scope,
    //   we take the narrower of the two.  If either did not set a scope,
    //   their respective values will be zero, which also works out fine here.
    if(scope_mask_out > result->edns_scope_mask)
        result->edns_scope_mask = scope_mask_out;

    return rv;
}

#if DYNC_OK
F_NONNULL
void CB_RES_C(unsigned threadnum V_UNUSED, unsigned resnum, const uint8_t* origin, const client_info_t* cinfo, dyncname_result_t* result) {
    dmn_assert(origin); dmn_assert(cinfo); dmn_assert(result);

    // extract and clear any datacenter index from upper 8 bits
    //  (used for synthetic resname/dcname resources)
    const unsigned synth_dc = (resnum & DC_MASK) >> DC_SHIFT;
    const uint8_t synth_dclist[2] = { synth_dc, 0 };
    resnum &= RES_MASK;

    const resource_t* res = &resources[resnum];

    unsigned scope_mask_out = 0;
    const uint8_t* dclist;
    if(synth_dc)
        dclist = synth_dclist;
    else
        dclist = map_get_dclist(res->map, cinfo, &scope_mask_out);

    // For cnames, only the first datacenter matters
    const unsigned dcnum = dclist[0];
    dmn_assert(dcnum <= res->num_dcs);
    const dc_t* dc = &res->dcs[dcnum];
    if(dc->dname) {
        dname_copy(result->dname, dc->dname);
        if(dname_is_partial(result->dname))
            dname_cat(result->dname, origin);
    }
    else {
        dmn_assert(dc->plugin);
        dc->plugin->resolve_dyncname(threadnum, dc->res_num_dync, origin, cinfo, result);
    }
    dmn_assert(dname_status(result->dname) == DNAME_VALID);

    // if both our map_get_dclist() and the subplugin tried to set a scope,
    //   we take the narrower of the two.  If either did not set a scope,
    //   their respective values will be zero, which also works out fine here.
    if(scope_mask_out > result->edns_scope_mask)
        result->edns_scope_mask = scope_mask_out;
}
#endif

#ifndef NDEBUG
// only in debug cases, to make it easier to find leaks...
void CB_EXIT(void) {
    for(unsigned i = 0; i < num_res; i++)
        resource_destroy(&resources[i]);
    free(resources);
    maps_destroy();
}
#endif
