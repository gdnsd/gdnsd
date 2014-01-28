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

#include "config.h"

#include "gdnsd/mon.h"
#include "gdnsd/mon-priv.h"
#include "gdnsd/log.h"
#include "gdnsd/plugapi.h"
#include "gdnsd/plugapi-priv.h"
#include "gdnsd/prcu-priv.h"
#include "gdnsd/vscf.h"

#include <ev.h>

typedef struct {
    const char* name;
    const plugin_t* plugin;
    unsigned up_thresh;
    unsigned ok_thresh;
    unsigned down_thresh;
    unsigned interval;
    unsigned timeout;
} service_type_t;

// if type is NULL, there is no real monitoring,
//   it's only possible to administratively change
//   the state.  This happens in two cases:
// 1) "special" service types down/up/none
// 2) "virtual" resources (CNAMEs and aggregates)
typedef struct {
    const char* desc;
    service_type_t* type;
    anysin_t addr;
    unsigned n_failure;
    unsigned n_success;
    bool forced;
    gdnsd_sttl_t real_sttl;
} smgr_t;

static unsigned num_svc_types = 0;
static service_type_t* service_types = NULL;

static unsigned num_smgrs = 0;
static smgr_t* smgrs = NULL;

// There are two copies of the sttl table.
// The "consumer" copy is always ready for consumption
//   (via prcu deref) by other threads, and does not
//   get mutated directly.  The updates flow into
//   the non-consumer table and the tables are later
//   prcu swapped (with the old copy updated to new values)
static gdnsd_sttl_t* smgr_sttl = NULL;
static gdnsd_sttl_t* smgr_sttl_consumer = NULL;

static int max_stats_len = 0;

static bool initial_round = false;

static struct ev_loop* mon_loop = NULL;
static ev_timer* sttl_update_timer = NULL;

#define DEF_UP_THRESH 20
#define DEF_OK_THRESH 10
#define DEF_DOWN_THRESH 10
#define DEF_INTERVAL 10
#define DEF_TIMEOUT 3

static void sttl_table_update(struct ev_loop* loop V_UNUSED, ev_timer* w, int revents) {
    dmn_assert(loop); dmn_assert(w);
    dmn_assert(w == sttl_update_timer);
    dmn_assert(revents == EV_TIMER);

    gdnsd_sttl_t* saved_old_consumer = smgr_sttl_consumer;
    gdnsd_prcu_upd_lock();
    gdnsd_prcu_upd_assign(smgr_sttl_consumer, smgr_sttl);
    gdnsd_prcu_upd_unlock();
    smgr_sttl = saved_old_consumer;
    memcpy(smgr_sttl, smgr_sttl_consumer, sizeof(gdnsd_sttl_t) * num_smgrs);
}

// Called once after all servicetypes and monitored stuff
//  have been configured, from main thread.  mloop happens
//  to be the default loop currently, and should be empty of
//  events at this point so that we can fall out after the
//  initial round of monitoring.
void gdnsd_mon_start(struct ev_loop* mloop) {
    dmn_assert(mloop);

    // Fall out quickly if nothing to monitor
    if(!num_smgrs) return;

    // saved for timer usage later
    mon_loop = mloop;

    gdnsd_plugins_action_init_monitors(mloop);

    // Run the loop once until all events drain, which will
    // be one full monitoring cycle of each resource (without
    // any artificial delays).
    log_info("Starting initial round of monitoring ...");
    initial_round = true;
    ev_run(mloop, 0);
    initial_round = false;
    log_info("Initial round of monitoring complete");

    // set up the table-update coalescing timer
    sttl_update_timer = malloc(sizeof(ev_timer));
    ev_timer_init(sttl_update_timer, sttl_table_update, 1.0, 0.0);

    // trigger it once manually to invoke prcu stuff
    //   for the initial round results to ensure there's
    //   no confusion.
    sttl_table_update(mloop, sttl_update_timer, EV_TIMER);

    gdnsd_plugins_action_start_monitors(mloop);
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

// Called from plugins once per monitored service type+IP combination
//  to request monitoring and initialize various data/state.
unsigned gdnsd_mon_addr(const char* desc, const char* svctype_name, const anysin_t* addr) {
    dmn_assert(desc); dmn_assert(addr);

    // first, sort out what svctype_name actually means to us
    service_type_t* this_svc = NULL;

    if(!svctype_name)
        svctype_name = "default";

    const char* svctype_name_cmp = svctype_name;
    if(!strcmp(svctype_name_cmp, "none"))
        svctype_name_cmp = "up";
    for(unsigned i = 0; i < num_svc_types; i++) {
        if(!strcmp(svctype_name_cmp, service_types[i].name)) {
            this_svc = &service_types[i];
            break;
        }
    }
    if(!this_svc)
        log_fatal("Invalid service type '%s' in monitoring request for '%s'", svctype_name, desc);

    // from here, this_svc is only NULL if special down/up/none service_type

    // next, check if this is a duplicate of a request issued earlier
    //   by some other plugin/resource, in which case we can just give
    //   them the existing index
    for(unsigned i = 0; i < num_smgrs; i++) {
        smgr_t* that_smgr = &smgrs[i];
        if(addr_eq(addr, &that_smgr->addr) && this_svc == that_smgr->type)
            return i;
    }

    // allocate the new smgr/sttl
    const unsigned idx = num_smgrs++;
    smgrs = realloc(smgrs, sizeof(smgr_t) * num_smgrs);
    smgr_sttl = realloc(smgr_sttl, sizeof(gdnsd_sttl_t) * num_smgrs);
    smgr_sttl_consumer = realloc(smgr_sttl_consumer, sizeof(gdnsd_sttl_t) * num_smgrs);

    smgr_t* this_smgr = &smgrs[idx];
    memcpy(&this_smgr->addr, addr, sizeof(anysin_t));
    this_smgr->type = this_svc;
    this_smgr->desc = strdup(desc);
    this_smgr->n_failure = 0;
    this_smgr->n_success = 0;
    this_smgr->forced = false;
    this_smgr->real_sttl = GDNSD_STTL_TTL_MASK;

    // the "down" special gets a different default than the rest
    if(!strcmp(svctype_name, "down"))
        this_smgr->real_sttl |= GDNSD_STTL_DOWN;

    smgr_sttl_consumer[idx] = smgr_sttl[idx] = this_smgr->real_sttl;

    return idx;
}

// as above for CNAME/virtual resources that can only have a forced admin state
unsigned gdnsd_mon_admin(const char* desc) {
    dmn_assert(desc);

    const unsigned idx = num_smgrs++;
    smgrs = realloc(smgrs, sizeof(smgr_t) * num_smgrs);
    smgr_sttl = realloc(smgr_sttl, sizeof(gdnsd_sttl_t) * num_smgrs);
    smgr_sttl_consumer = realloc(smgr_sttl_consumer, sizeof(gdnsd_sttl_t) * num_smgrs);
    smgr_t* this_smgr = &smgrs[idx];
    memset(this_smgr, 0, sizeof(smgr_t));
    this_smgr->desc = strdup(desc);
    this_smgr->real_sttl = GDNSD_STTL_TTL_MASK;
    smgr_sttl_consumer[idx] = smgr_sttl[idx] = this_smgr->real_sttl;
    return idx;
}

const gdnsd_sttl_t* gdnsd_mon_get_sttl_table(void) {
    return gdnsd_prcu_rdr_deref(smgr_sttl_consumer);
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

F_NONNULL
static bool bad_svc_opt(const char* key, unsigned klen V_UNUSED, const vscf_data_t* d V_UNUSED, void* data) {
    dmn_assert(key); dmn_assert(data);
    log_fatal("Service type '%s', bad option '%s'", (const char*)data, key);
}

void gdnsd_mon_cfg_stypes_p1(const vscf_data_t* svctypes_cfg) {

    unsigned num_svc_types_cfg = 0;

    if(svctypes_cfg) {
        if(!vscf_is_hash(svctypes_cfg))
            log_fatal("service_types, if defined, must have a hash value");
        num_svc_types_cfg = vscf_hash_get_len(svctypes_cfg);
    }

    num_svc_types = num_svc_types_cfg + 3; // "default", "down", "up"

    // The default entry is always the last of the array
    service_types = malloc(num_svc_types * sizeof(service_type_t));
    service_types[0].name = "default";
    service_types[1].name = "down";
    service_types[2].name = "up";

    // if this loop executes at all, svctypes_cfg is defined
    //   (see if() block at top of func, and definition of num_svc_types)
    for(unsigned i = 0; i < num_svc_types_cfg; i++) {
        service_type_t* this_svc = &service_types[i + 3];
        this_svc->name = strdup(vscf_hash_get_key_byindex(svctypes_cfg, i, NULL));
        if(!strcmp(this_svc->name, "none")
           || !strcmp(this_svc->name, "up")
           || !strcmp(this_svc->name, "down")
           || !strcmp(this_svc->name, "default"))
            log_fatal("Explicit service type name '%s' not allowed", this_svc->name);
    }
}

void gdnsd_mon_cfg_stypes_p2(const vscf_data_t* svctypes_cfg, const bool force_v6_up) {

    // If no plugins actually used any plugin-monitored services, there's
    //   no point in setting up the remainder of this.  At the very least
    //   it lets us skip loading http_status.
    bool need_p2 = false;
    for(unsigned i = 0; i < num_smgrs; i++) {
        if(smgrs[i].type) {
            need_p2 = true;
            break;
        }
    }
    if(!need_p2)
        return;

    dmn_assert(num_svc_types >= 3); // for default, down, up

    const plugin_t* def_plugin = gdnsd_plugin_find_or_load("http_status");
    dmn_assert(def_plugin);
    dmn_assert(def_plugin->add_svctype && def_plugin->add_monitor);

    { // set up default
        service_type_t* def_svc = &service_types[0];
        def_svc->plugin = def_plugin;
        def_svc->up_thresh = DEF_UP_THRESH;
        def_svc->ok_thresh = DEF_OK_THRESH;
        def_svc->down_thresh = DEF_DOWN_THRESH;
        def_svc->interval = DEF_INTERVAL;
        def_svc->timeout = DEF_TIMEOUT;
        def_svc->plugin->add_svctype(def_svc->name, NULL, def_svc->interval, def_svc->timeout);
    }

    for(unsigned i = 1; i < 3; i++) { // set up down/up
        service_type_t* this_svc = &service_types[i];
        this_svc->plugin = NULL;
        this_svc->up_thresh = DEF_UP_THRESH;
        this_svc->ok_thresh = DEF_OK_THRESH;
        this_svc->down_thresh = DEF_DOWN_THRESH;
        this_svc->interval = DEF_INTERVAL;
        this_svc->timeout = DEF_TIMEOUT;
    }

    for(unsigned i = 3; i < num_svc_types; i++) {
        dmn_assert(svctypes_cfg);
        const unsigned cfg_i = i - 3;
        service_type_t* this_svc = &service_types[i];

        // assert same ordering as _p1
        dmn_assert(!strcmp(this_svc->name, vscf_hash_get_key_byindex(svctypes_cfg, cfg_i, NULL)));

        const vscf_data_t* svctype_cfg = vscf_hash_get_data_byindex(svctypes_cfg, cfg_i);
        if(!vscf_is_hash(svctype_cfg))
            log_fatal("Definition of service type '%s' must be a hash", this_svc->name);

        const vscf_data_t* pname_cfg = vscf_hash_get_data_byconstkey(svctype_cfg, "plugin", true);
        if(!pname_cfg) {
            this_svc->plugin = def_plugin;
        }
        else {
            if(!vscf_is_simple(pname_cfg) || !vscf_simple_get_len(pname_cfg))
                log_fatal("Service type '%s': 'plugin' must be a string", this_svc->name);
            const char* pname = vscf_simple_get_data(pname_cfg);
            this_svc->plugin = gdnsd_plugin_find_or_load(pname);
            if(!this_svc->plugin->add_svctype || !this_svc->plugin->add_monitor)
                log_fatal("Service type '%s' references plugin '%s', which does not support service monitoring (lacks required callbacks)", this_svc->name, pname);
        }

        this_svc->up_thresh = DEF_UP_THRESH;
        this_svc->ok_thresh = DEF_OK_THRESH;
        this_svc->down_thresh = DEF_DOWN_THRESH;
        this_svc->interval = DEF_INTERVAL;
        this_svc->timeout = DEF_TIMEOUT;
        SVC_OPT_UINT(svctype_cfg, this_svc->name, up_thresh, 1LU, 65535LU);
        SVC_OPT_UINT(svctype_cfg, this_svc->name, ok_thresh, 1LU, 65535LU);
        SVC_OPT_UINT(svctype_cfg, this_svc->name, down_thresh, 1LU, 65535LU);
        SVC_OPT_UINT(svctype_cfg, this_svc->name, interval, 1LU, 3600LU);
        SVC_OPT_UINT(svctype_cfg, this_svc->name, timeout, 1LU, 300LU);
        if((double)this_svc->timeout > (double)this_svc->interval * 0.9)
            log_fatal("Service type '%s': timeout must be less than 90%% of interval)", this_svc->name);
        this_svc->plugin->add_svctype(this_svc->name, svctype_cfg, this_svc->interval, this_svc->timeout);
        vscf_hash_iterate(svctype_cfg, true, bad_svc_opt, (void*)this_svc->name);
    }

    // now that we've solved the chicken-and-egg, finish processing
    //   the monitoring requests resolver plugins asked about earlier
    for(unsigned i = 0; i < num_smgrs; i++) {
        smgr_t* this_smgr = &smgrs[i];
        if(this_smgr->type) { // CNAME/virtual get no service_type at all
            if(this_smgr->type->plugin) { // down/up get no plugin
                dmn_assert(this_smgr->type->plugin->add_monitor);
                if(!(force_v6_up && this_smgr->addr.sa.sa_family == AF_INET6))
                    this_smgr->type->plugin->add_monitor(this_smgr->desc, this_smgr->type->name, &this_smgr->addr, i);
            }
        }
    }
}

void gdnsd_mon_state_updater(unsigned idx, const bool latest) {
    dmn_assert(idx < num_smgrs);
    smgr_t* smgr = &smgrs[idx];

    // a bit spammy to leave in all debug builds, but handy at times...
    //log_debug("'%s' new monitor result: %s", smgr->desc, latest ? "OK" : "FAIL");

    bool down;

    // XXX think up a better way to set TTL on initial monitoring round?
    //   may involve a whole new counting system, or at least
    //   a count of rounds_since_start until some period has passed?
    //  The idea would be to serve a shorter TTL until stability has
    //   been demonstrated.  For now, just going with pretending initial
    //   state is stable.
    if(initial_round) {
        dmn_assert(!smgr->n_failure);
        dmn_assert(!smgr->n_success);
        down = !latest;
    }
    else {
        // First handle basic up/down state and the counters
        down = smgr->real_sttl & GDNSD_STTL_DOWN;
        if(down) { // Currently DOWN
            if(latest) { // New Success
                if(++smgr->n_success == smgr->type->up_thresh) {
                    smgr->n_success = 0;
                    smgr->n_failure = 0;
                    down = false;
                }
            }
            else { // New failure when already down, reset for up_thresh
                smgr->n_success = 0;
            }
        }
        else { // Currently UP
            if(latest) { // New Success
                // Was UP with some intermittent failure history, but has cleared ok_thresh...
                if(smgr->n_failure && (++smgr->n_success == smgr->type->ok_thresh)) {
                    smgr->n_failure = 0;
                    smgr->n_success = 0;
                }
            }
            else { // New Failure
                smgr->n_success = 0;
                if(++smgr->n_failure == smgr->type->down_thresh) { // Fail threshold check on failure
                    smgr->n_failure = 0;
                    down = true;
                }
            }
        }
    }

    // calculate new TTL based on counters + interval
    const unsigned count_to_change = down
        ? smgr->type->up_thresh - smgr->n_success
        : smgr->type->down_thresh - smgr->n_failure;
    gdnsd_sttl_t new_sttl = smgr->type->interval * count_to_change;
    if(new_sttl > GDNSD_STTL_TTL_MASK)
        new_sttl = GDNSD_STTL_TTL_MASK;
    if(down)
        new_sttl |= GDNSD_STTL_DOWN;

    // propagate any change
    if(initial_round) {
        smgr_sttl[idx] = smgr->real_sttl = new_sttl;
        // table update taken care of in gdnsd_mon_start()
        //  after all initial monitors complete
    }
    else if(new_sttl != smgr->real_sttl) {
        smgr->real_sttl = new_sttl;
        if(!smgr->forced && new_sttl != smgr_sttl[idx]) {
            smgr_sttl[idx] = new_sttl;
            if(!ev_is_active(sttl_update_timer)) {
                ev_timer_set(sttl_update_timer, 1.0, 0.0);
                ev_timer_start(mon_loop, sttl_update_timer);
            }
        }
    }
}

//--------------------------------------------------
// stats code from here to the end
//--------------------------------------------------

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

static const char* state_txt[2] = {
    "DOWN",
    "UP",
};

// statio calls this at the appropriate time (long after all
//  basic setup is done, but before monio_start() time).
// monio's job here is to inform statio of the maximum possible
//  size of its stats output (csv or html, although html is probably
//  always the larger of the two).
unsigned gdnsd_mon_stats_get_max_len(void) {
    if(!num_smgrs) return max_stats_len = 0;

    unsigned retval = http_head_len + http_foot_len
           + (num_smgrs * (http_tmpl_len + (4*2))); // 6 is len(DOWN)
    for(unsigned i = 0; i < num_smgrs; i++)
        retval += strlen(smgrs[i].desc);

    return max_stats_len = retval;
}

// Output our stats in html form to buf, returning
//  how many characters we added to the buf.
unsigned gdnsd_mon_stats_out_html(char* buf) {
    dmn_assert(buf);

    if(!num_smgrs) return 0;
    dmn_assert(max_stats_len);

    const char* const buf_start = buf;
    int avail = max_stats_len;

    memcpy(buf, http_head, http_head_len);
    buf += http_head_len;
    avail -= http_head_len;

    for(unsigned i = 0; i < num_smgrs; i++) {
        bool st = !(smgr_sttl[i] & GDNSD_STTL_DOWN);
        int written = snprintf(buf, avail, http_tmpl, smgrs[i].desc, state_txt[st], state_txt[st]);
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
unsigned gdnsd_mon_stats_out_csv(char* buf) {
    dmn_assert(buf);

    if(!num_smgrs) return 0;
    dmn_assert(max_stats_len);

    const char* const buf_start = buf;
    int avail = max_stats_len;

    memcpy(buf, csv_head, csv_head_len);
    buf += csv_head_len;
    avail -= csv_head_len;

    for(unsigned i = 0; i < num_smgrs; i++) {
        bool st = !(smgr_sttl[i] & GDNSD_STTL_DOWN);
        int written = snprintf(buf, avail, csv_tmpl, smgrs[i].desc, state_txt[st]);
        if(unlikely(written >= avail))
            log_fatal("BUG: monio stats buf miscalculated");
        buf += written;
        avail -= written;
    }

    return (buf - buf_start);
}

unsigned gdnsd_mon_stats_out_json(char* buf) {
    dmn_assert(buf);

    const char* const buf_start = buf;

    if(num_smgrs == 0 ) {
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

    for(unsigned i = 0; i < num_smgrs; i++) {
        bool st = !(smgr_sttl[i] & GDNSD_STTL_DOWN);
        int written = snprintf(buf, avail, json_tmpl, smgrs[i].desc, state_txt[st]);
        if(unlikely(written >= avail || avail < (int)json_foot_len))
            log_fatal("BUG: monio stats buf miscalculated");
        buf += written;
        avail -= written;
        if( i < num_smgrs -1 ) {
            memcpy(buf, json_sep, json_sep_len);
            buf += json_sep_len;
        }
    }

    memcpy(buf, json_foot, json_foot_len);
    buf += json_foot_len;

    return (buf - buf_start);
}
