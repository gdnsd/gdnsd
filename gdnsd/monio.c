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

#include "monio.h"
#include "conf.h"
#include "gdnsd/plugapi-priv.h"
#include "gdnsd/log.h"

#include <string.h>
#include <unistd.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>

#define DEF_UP_THRESH 20
#define DEF_OK_THRESH 10
#define DEF_DOWN_THRESH 10
#define DEF_INTERVAL 10
#define DEF_TIMEOUT 3

struct _service_type_struct {
    const char* name;
    const plugin_t* plugin;
    unsigned up_thresh;   // Def: 20 Range: 1-uintmax
    unsigned ok_thresh;   // Def: 10 Range: 1-uintmax
    unsigned down_thresh; // Def: 10 Range: 1-uintmax
};

static int max_stats_len = 0;
static unsigned int num_mons = 0;
static mon_smgr_t** mons = NULL;

// Called once after all resources are monio_add()'d,
//  from main thread.  mon_loop happens to be the default
//  loop currently, and should be empty of events at
//  this point so that we can fall out after the initial
//  round of monitoring.
void monio_start(struct ev_loop* mon_loop) {
    dmn_assert(mon_loop);

    // Fall out quickly if nothing to monitor
    if(!num_mons) return;

    gdnsd_plugins_action_init_monitors(mon_loop);

    // Run the loop once until all events drain, which will
    // be one full monitoring cycle of each resource (without
    // any artificial delays).
    log_info("Starting initial round of monitoring ...");
    ev_run(mon_loop, 0);
    log_info("Initial round of monitoring complete");

    gdnsd_plugins_action_start_monitors(mon_loop);
}

// We only have to check the address, because the port
//  is determined by service type.
F_NONNULL
static bool addr_eq(const anysin_t* a, const anysin_t* b) {
    dmn_assert(a); dmn_assert(b);
    dmn_assert(a->sa.sa_family == AF_INET || a->sa.sa_family == AF_INET6);

    bool rv = false;
    if(a->sa.sa_family == b->sa.sa_family) {
        if(a->sa.sa_family == AF_INET)
            rv = (a->sin.sin_addr.s_addr == b->sin.sin_addr.s_addr);
        else
            rv = !memcmp(a->sin6.sin6_addr.s6_addr, b->sin6.sin6_addr.s6_addr, 16);
    }
    return rv;
}

static unsigned num_svc_types = 0;
static service_type_t* service_types;

// Called for plugins once per monitored service type+IP combination
//  immediately after their _load_config() phase (very important)
//  to request monitoring and initialize various data/state.
void monio_add_addr(const char* svctype_name, const char* desc, const char* addr, mon_state_t* mon_state_ptr) {

    stats_uint_t initial = MON_STATE_UNINIT;

    // The four special service types that do no real monitoring
    //   and stay stuck on a specific, forced initial state
    if(svctype_name) {
        if(!strcmp(svctype_name, "none"))
            initial = MON_STATE_UP;
        else if(!strcmp(svctype_name, "up"))
            initial = MON_STATE_UP;
        else if(!strcmp(svctype_name, "danger"))
            initial = MON_STATE_DANGER;
        else if(!strcmp(svctype_name, "down"))
            initial = MON_STATE_DOWN;
    }

    stats_own_set(mon_state_ptr, initial);

    // No actual setup for the forced states
    if(initial != MON_STATE_UNINIT)
        return;

    mon_smgr_t* this_smgr = calloc(1, sizeof(mon_smgr_t));

    // Set service type
    if(!svctype_name || !strcmp(svctype_name, "default")) {
        this_smgr->svc_type = &service_types[num_svc_types];
    }
    else {
        for(unsigned i = 0; i < num_svc_types; i++) {
            if(!strcmp(svctype_name, service_types[i].name)) {
                this_smgr->svc_type = &service_types[i];
                break;
            }
        }
        if(!this_smgr->svc_type)
            log_fatal("Invalid service type '%s' in monitoring request for '%s'", svctype_name, desc);
    }

    const int addr_err = gdnsd_anysin_getaddrinfo(addr, NULL, &this_smgr->addr);
    if(addr_err)
        log_fatal("Could not process monitoring address spec '%s': %s", addr, gai_strerror(addr_err));

    bool is_duplicate = false;

    // now check for uniqueness
    for(unsigned i = 0; i < num_mons; i++) {
        mon_smgr_t* that_smgr = mons[i];
        if(addr_eq(&this_smgr->addr, &that_smgr->addr) && this_smgr->svc_type == that_smgr->svc_type) {
            // We found a duplicate.  We'll keep this_smgr so that monitor stats output sees
            //   it normally, but also add it to the list of outputs for the original copy
            //   and (later) not directly add_monitor() the duplicate.  This de-duplicates
            //   the actual monitoring traffic and state-tracking, but not the listed outputs
            //   in e.g. the Web UI.  Note that we always scan for dupes in the same order,
            //   so all duplicates should get added to the first copy.
            that_smgr->mon_state_ptrs = realloc(
                that_smgr->mon_state_ptrs,
                (that_smgr->num_state_ptrs + 1) * sizeof(mon_state_t*)
            );
            that_smgr->mon_state_ptrs[that_smgr->num_state_ptrs++] = mon_state_ptr;
            is_duplicate = true;
            break;
        }
    }

    this_smgr->desc = strdup(desc);
    this_smgr->num_state_ptrs = 1;
    this_smgr->mon_state_ptrs = malloc(sizeof(mon_state_t*));
    this_smgr->mon_state_ptrs[0] = mon_state_ptr;
    this_smgr->n_failure = 0;
    this_smgr->n_success = 0;
    this_smgr->up_thresh = this_smgr->svc_type->up_thresh;
    this_smgr->ok_thresh = this_smgr->svc_type->ok_thresh;
    this_smgr->down_thresh = this_smgr->svc_type->down_thresh;

    if(gconfig.monitor_force_v6_up && this_smgr->addr.sa.sa_family == AF_INET6)
        stats_own_set(this_smgr->mon_state_ptrs[0], MON_STATE_UP);
    else if(!is_duplicate)
        this_smgr->svc_type->plugin->add_monitor(svctype_name, this_smgr);

    mons = realloc(mons, sizeof(mon_smgr_t*) * (num_mons + 1));
    mons[num_mons++] = this_smgr;
}

#define SVC_OPT_UINT(_hash, _typnam, _loc, _min, _max) \
    do { \
        const vscf_data_t* _data = vscf_hash_get_data_byconstkey(_hash, #_loc, true); \
        if(_data) { \
            unsigned long _val; \
            if(!vscf_is_simple(_data) \
            || !vscf_simple_get_as_ulong(_data, &_val)) \
                log_fatal("Service type '%s': option '%s': Value must be a positive integer", _typnam, #_loc); \
            if(_val < _min || _val > _max) \
                log_fatal("Service type '%s': option '%s': Value out of range (%lu, %lu)", _typnam, #_loc, _min, _max); \
            this_svc->_loc = (unsigned) _val; \
        } \
    } while(0)

#define SVC_OPT_D_UINT(_hash, _typnam, _loc, _min, _max) \
    do { \
        const vscf_data_t* _data = vscf_hash_get_data_byconstkey(_hash, #_loc, true); \
        if(_data) { \
            unsigned long _val; \
            if(!vscf_is_simple(_data) \
            || !vscf_simple_get_as_ulong(_data, &_val)) \
                log_fatal("Service type '%s': option '%s': Value must be a positive integer", _typnam, #_loc); \
            if(_val < _min || _val > _max) \
                log_fatal("Service type '%s': option '%s': Value out of range (%lu, %lu)", _typnam, #_loc, _min, _max); \
            _loc = (unsigned) _val; \
        } \
    } while(0)

#define SVC_OPT_STR(_hash, _typnam, _loc) \
    do { \
        const vscf_data_t* _data = vscf_hash_get_data_byconstkey(_hash, #_loc, true); \
        if(_data) { \
            if(!vscf_is_simple(_data)) \
                log_fatal("Service type '%s': option %s: Wrong type (should be string)", _typnam, #_loc); \
            this_svc->_loc = strdup(vscf_simple_get_data(_data)); \
        } \
    } while(0)

F_NONNULL
static bool bad_svc_opt(const char* key, unsigned klen V_UNUSED, const vscf_data_t* d V_UNUSED, void* data) {
    dmn_assert(key); dmn_assert(data);
    log_fatal("Service type '%s', bad option '%s'", (const char*)data, key);
}

void monio_add_servicetypes(const vscf_data_t* svctypes_cfg) {
    if(svctypes_cfg) {
        if(!vscf_is_hash(svctypes_cfg))
            log_fatal("service_types, if defined, must have a hash value");
        num_svc_types = vscf_hash_get_len(svctypes_cfg);
    }

    // The default entry is always the last of the array
    service_types = malloc((num_svc_types + 1) * sizeof(service_type_t));
    service_type_t* def_svc = &service_types[num_svc_types];

    def_svc->name = "default";
    const plugin_t* def_plugin = def_svc->plugin = gdnsd_plugin_find_or_load("http_status");
    dmn_assert(def_plugin->add_svctype && def_plugin->add_monitor);
    def_svc->up_thresh = DEF_UP_THRESH;
    def_svc->ok_thresh = DEF_OK_THRESH;
    def_svc->down_thresh = DEF_DOWN_THRESH;
    unsigned interval = DEF_INTERVAL;
    unsigned timeout = DEF_TIMEOUT;
    def_svc->plugin->add_svctype(def_svc->name, NULL, interval, timeout);

    // if this loop executes at all, svctypes_cfg is defined
    //   (see if() block at top of func, and definition of num_svc_types)
    dmn_assert(svctypes_cfg || !num_svc_types);
    for(unsigned i = 0; i < num_svc_types; i++) {
        service_type_t* this_svc = &service_types[i];
        this_svc->name = strdup(vscf_hash_get_key_byindex(svctypes_cfg, i, NULL));
        if(!strcmp(this_svc->name, "none")
           || !strcmp(this_svc->name, "up")
           || !strcmp(this_svc->name, "danger")
           || !strcmp(this_svc->name, "down")
           || !strcmp(this_svc->name, "default"))
            log_fatal("Explicit service type name '%s' not allowed", this_svc->name);
        const vscf_data_t* svctype_cfg = vscf_hash_get_data_byindex(svctypes_cfg, i);
        if(!vscf_is_hash(svctype_cfg))
            log_fatal("Definition of service type '%s' must be a hash", this_svc->name);

        const vscf_data_t* pname_cfg = vscf_hash_get_data_byconstkey(svctype_cfg, "plugin", true);
        if(pname_cfg) {
            if(!vscf_is_simple(pname_cfg) || !vscf_simple_get_len(pname_cfg))
                log_fatal("Service type '%s': 'plugin' must be a string", this_svc->name);
            const char* pname = vscf_simple_get_data(pname_cfg);
            this_svc->plugin = gdnsd_plugin_find_or_load(pname);
            if(!this_svc->plugin->add_svctype || !this_svc->plugin->add_monitor)
                log_fatal("Service type '%s' references plugin '%s', which does not support service monitoring (lacks required callbacks)", this_svc->name, pname);
        }
        else {
            this_svc->plugin = def_plugin;
        }

        this_svc->up_thresh = DEF_UP_THRESH;
        this_svc->ok_thresh = DEF_OK_THRESH;
        this_svc->down_thresh = DEF_DOWN_THRESH;
        interval = DEF_INTERVAL;
        timeout = DEF_TIMEOUT;
        SVC_OPT_UINT(svctype_cfg, this_svc->name, up_thresh, 1LU, 65535LU);
        SVC_OPT_UINT(svctype_cfg, this_svc->name, ok_thresh, 1LU, 65535LU);
        SVC_OPT_UINT(svctype_cfg, this_svc->name, down_thresh, 1LU, 65535LU);
        SVC_OPT_D_UINT(svctype_cfg, this_svc->name, interval, 1LU, 3600LU);
        SVC_OPT_D_UINT(svctype_cfg, this_svc->name, timeout, 1LU, 300LU);
        if((double)timeout > (double)interval * 0.9)
            log_fatal("Service type '%s': timeout must be less than 90%% of interval)", this_svc->name);
        this_svc->plugin->add_svctype(this_svc->name, svctype_cfg, interval, timeout);
        vscf_hash_iterate(svctype_cfg, true, bad_svc_opt, (void*)this_svc->name);
    }
}

static const char http_head[] = "<p><span class='bold big'>Monitored Service States:</span></p><table>\r\n"
    "<tr><th>Service</th><th>State</th></tr>\r\n";
static unsigned http_head_len = sizeof(http_head) - 1;

static const char http_tmpl[] = "<tr><td>%s</td><td class='%s'>%s</td></tr>\r\n";
static unsigned http_tmpl_len = sizeof(http_head) - 7;

static const char http_foot[] = "</table>\r\n";
static unsigned http_foot_len = sizeof(http_foot) - 1;

static const char csv_head[] = "Service,State\r\n";
static unsigned csv_head_len = sizeof(csv_head) - 1;

static const char csv_tmpl[] = "%s,%s\r\n";

static const char json_head[] = "\t\"services\": [\r\n";
static unsigned json_head_len = sizeof(json_head) - 1;
static const char json_tmpl[] = "\t\t{\r\n\t\t\t\"service\": \"%s\",\r\n\t\t\t\"state\": \"%s\"\r\n\t\t}";
static const char json_sep[] = ",\r\n";
static unsigned json_sep_len = sizeof(json_sep) - 1;
static const char json_nl[] = "\r\n";
static unsigned json_nl_len = sizeof(json_nl) - 1;
static const char json_foot[] = "\r\n\t]\r\n";
static unsigned json_foot_len = sizeof(json_foot) - 1;

static const char* state_txt[4] = {
    "UNINIT", // should be unused in practice due to startup ordering
    "DOWN",
    "DANGER",
    "UP",
};

// statio calls this at the appropriate time (long after all
//  basic setup is done, but before monio_start() time).
// monio's job here is to inform statio of the maximum possible
//  size of its stats output (csv or html, although html is probably
//  always the larger of the two).
unsigned monio_get_max_stats_len(void) {
    if(!num_mons) return max_stats_len = 0;

    unsigned retval = http_head_len + http_foot_len
           + (num_mons * (http_tmpl_len + (6*2))); // 6 is len(DANGER)
    for(unsigned i = 0; i < num_mons; i++)
        retval += strlen(mons[i]->desc);

    return max_stats_len = retval;
}

// Output our stats in html form to buf, returning
//  how many characters we added to the buf.
unsigned monio_stats_out_html(char* buf) {
    dmn_assert(buf);

    if(!num_mons) return 0;
    dmn_assert(max_stats_len);

    const char* const buf_start = buf;
    int avail = max_stats_len;

    memcpy(buf, http_head, http_head_len);
    buf += http_head_len;
    avail -= http_head_len;

    for(unsigned i = 0; i < num_mons; i++) {
        mon_state_uint_t st = stats_get(mons[i]->mon_state_ptrs[0]);
        int written = snprintf(buf, avail, http_tmpl, mons[i]->desc, state_txt[st], state_txt[st]);
        if(unlikely(written >= avail || avail < (int)http_foot_len))
            log_fatal("BUG: monio stats buf miscalculated");
        buf += written;
        avail -= written;
    }

    memcpy(buf, http_foot, http_foot_len);
    buf += http_foot_len;

    return (buf - buf_start);
}

// Output our stats in csv form to buf, returning
//  how many characters we added to the buf.
unsigned monio_stats_out_csv(char* buf) {
    dmn_assert(buf);

    if(!num_mons) return 0;
    dmn_assert(max_stats_len);

    const char* const buf_start = buf;
    int avail = max_stats_len;

    memcpy(buf, csv_head, csv_head_len);
    buf += csv_head_len;
    avail -= csv_head_len;

    for(unsigned i = 0; i < num_mons; i++) {
        mon_state_uint_t st = stats_get(mons[i]->mon_state_ptrs[0]);
        int written = snprintf(buf, avail, csv_tmpl, mons[i]->desc, state_txt[st]);
        if(unlikely(written >= avail))
            log_fatal("BUG: monio stats buf miscalculated");
        buf += written;
        avail -= written;
    }

    return (buf - buf_start);
}

unsigned monio_stats_out_json(char* buf) {
    dmn_assert(buf);

    const char* const buf_start = buf;

    if(num_mons == 0 ) {
        memcpy(buf, json_nl, json_nl_len);
        buf += json_nl_len;
        return (buf - buf_start);
    } else {
        memcpy(buf, json_sep, json_sep_len);
        buf += json_sep_len;
    }

    dmn_assert(max_stats_len);
    int avail = max_stats_len;

    memcpy(buf, json_head, json_head_len);
    buf += json_head_len;
    avail -= json_head_len;

    for(unsigned i = 0; i < num_mons; i++) {
        mon_state_uint_t st = stats_get(mons[i]->mon_state_ptrs[0]);
        int written = snprintf(buf, avail, json_tmpl, mons[i]->desc, state_txt[st]);
        if(unlikely(written >= avail || avail < (int)json_foot_len))
            log_fatal("BUG: monio stats buf miscalculated");
        buf += written;
        avail -= written;
        if( i < num_mons -1 ) {
            memcpy(buf, json_sep, json_sep_len);
            buf += json_sep_len;
        }
    }

    memcpy(buf, json_foot, json_foot_len);
    buf += json_foot_len;

    return (buf - buf_start);
}
