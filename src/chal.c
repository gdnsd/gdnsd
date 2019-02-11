/* Copyright © 2018 Brandon L Black <blblack@gmail.com>
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

#include <config.h>

#include "chal.h"
#include "main.h"
#include "dnswire.h"
#include "conf.h"

#include <gdnsd/compiler.h>
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/dname.h>

#include <ev.h>
#include <urcu-qsbr.h>

// General implementation notes:
// --
// A "challenge" (chal_t) is a singular challenge, i.e. one single response TXT
// value configured for one single domainname.
// --
// A "challenge set" (cset_t) is a set of up to 100 challenges that were sent
// to the daemon together in a single control socket transaction (single
// gdnsdctl invocation).
// --
// Expiration is tracked and processed in terms of whole challenge sets, and
// since the expiration TTL is a fixed configurable value for all csets, we can
// store all the active sets in a linked list in entry-time order and process
// in-order expiries off the oldest end of the list.  This linked list has
// "oldest" and "newest" as the ends of the linked list, and a "next_newer"
// pointer inside of each cset to link them up.
// --
// Separately from all of the above, there's a hashtable (chal_tbl, of type
// chal_tbl_t) which is used by runtime lookups returning DNS response data.  A
// fresh new hashtable is created every time a new cset is inserted or an old
// expires, and then it's RCU-swapped into place for runtime lookups (before
// deletion of old csets, in the case of expiry/flush).
// The hashtable is sized to the next power of two greater than or equal to
// double the count of all individual challenges configured, and hashes on the
// domainname the challenge is for.  It's legal and expected to configure
// multiple simultaneous challenges for a single domainname, and these all go
// into the same hashtable collision slot together, just like actual hash
// collisions of distinct names.  The lookup-time code iterates all colliding
// entries in the collision slot and outputs all exact matches.
// ---
// Because of the sizing and collision method here, we don't expect to have
// long collision lists except in the case of true multi-output duplicates
// (configuring many distinct responses for one actual domainname).
// The more multi-output duplicates there are in the total set, the more
// over-sized the hashtable becomes for the actual number of slots needed,
// which makes hash duplicates with differing domainnames sharing a collision
// slot even less-likely.
// ---
// Given the above, we define a sanity limit here of 200 entries per collision
// slot, which should only be realistically triggerable with many entries for
// an identical domainname.  At somewhere around 285 configured challenges for
// a single domainname we'd run out of room in our hardcoded maximum 16KB
// response sizes anyways.  When the sanity limit is reached by the addition of
// a new cset, the cset is rejected (and gdnsdctl fails).
// This is useful because it prevents scenarios where a runaway ACME automation
// tool or script might inadvertently spam thousands or millions of challenges
// into the daemon through the control socket in a short period of time, which
// could slow down main-thread processing in general, and maybe even cause
// slight performance impact to dnsio threads executing challenge queries.
#define CHAL_COLLIDE_SANITY_MAX 200

// Challenge payload TXT RR len, fully pre-encoded
// 2 bytes type, 2 bytes class, 4 bytes ttl,
// 2 bytes rdlen, 1 byte txt chunklen
// 43 bytes payload
#define CHAL_RR_FIELDS (2U + 2U + 4U + 2U + 1U)
#define CHAL_RR_PAYLOAD (43U)
#define CHAL_RR_LEN (CHAL_RR_FIELDS + CHAL_RR_PAYLOAD)

// When serializing, we add 5 bytes at the start:
// 2 bytes size, 2 bytes remaining TTL, 1 byte count
#define CHAL_MAX_SERIAL (CHAL_MAX_DLEN + 5U)

// Seconds of fudge-factor on expiries to avoid edge-cases with timers and
// communication delays, etc
#define TIME_FUDGE 3.2

// A single challenge
typedef struct {
    uint32_t dnhash; // faster table re-creations and collision checks
    uint8_t dname[256]; // full dname, without _acme-challenge prefix
    uint8_t txt[CHAL_RR_LEN];
} chal_t;

// A cset_t is a set of challenges added in a single control socket transaction
// which expire together.
struct cset_s_;
typedef struct cset_s_ cset_t;
struct cset_s_ {
    size_t count;
    ev_tstamp expiry;
    cset_t* next_newer;
    chal_t chals[0];
};

// The total list of all active cset_t is managed as a single-linked list as a
// time-ordered FIFO (since all expiry relative times are identical) with
// "oldest" and "newest" marking the current head and tail.  Insertion of new
// elements happens at the "newest" end, and expiry of old elements happens at
// the "oldest" end.  The "next_newer" pointer above points in the direction of
// "newest", and is NULL only for the object referenced by "newest"
static cset_t* oldest = NULL;
static cset_t* newest = NULL;

// Global expiration timer, ticking towards "oldest" expire-time, if any
// cset_t are active at all.
static ev_timer expire_timer;

// chal_collide_t is used to store all the chal_t* pointers in a single hash
// collision slot, and is realloc'd as it grows.  We can't do linked-list using
// a pointer within chal_t because it would break RCU guarantees during
// updates, and we expect to store duplicate keys and thus collisions
// commonly, and have to return the whole set of duplicates, so open addressing
// isn't a great idea either.
typedef struct {
    size_t count;
    const chal_t* chals[0];
} chal_collide_t;

// chal_tbl_t is a hashtable indexing into all the chal_t of all the current
// cset_t, used for runtime lookups.
typedef struct {
    uint32_t mask;
    chal_collide_t* tbl[0];
} chal_tbl_t;

// This is the table reference used for runtime lookups.  It's replaced by
// RCU-swap as cset_t are added (from controlsock) and removed (due to
// expiry).
static chal_tbl_t* chal_tbl = NULL;

F_NONNULL
static void chal_tbl_destruct(chal_tbl_t* destructme)
{
    for (size_t i = 0; i <= destructme->mask; i++)
        if (destructme->tbl[i])
            free(destructme->tbl[i]);
    free(destructme);
}

// Add a cset to a challenge hash table as its being constructed, fails with
// retval true if sanity-check size constraint fails, but only if check was true
F_NONNULL
static bool chal_tbl_hash_cset(chal_tbl_t* ctbl, const cset_t* cset, const bool check)
{
    for (size_t i = 0; i < cset->count; i++) {
        const chal_t* ch = &cset->chals[i];
        chal_collide_t** slotptr = &ctbl->tbl[ch->dnhash & ctbl->mask];
        size_t old_ct = 0;
        if (*slotptr) {
            old_ct = (*slotptr)->count;
            if (check && old_ct > CHAL_COLLIDE_SANITY_MAX)
                return true;
        }
        *slotptr = xrealloc(*slotptr, sizeof(**slotptr) + (sizeof((*slotptr)->chals[0]) * (old_ct + 1U)));
        (*slotptr)->chals[old_ct] = ch;
        (*slotptr)->count = old_ct + 1U;
    }

    return false;
}

// Create a new chal_tbl using whatever's currently in the linked list plus
// optionally one new cset we're attempting to add.  Will return NULL if cset
// is NULL and there were no existing ones (e.g. re-create after deleting
// last).
static chal_tbl_t* chal_tbl_create(const cset_t* oldest_set, const cset_t* adding)
{
    chal_tbl_t* new_chal_tbl = NULL;

    // Calculate the total challenge count between all existing csets and the
    // optional new one:
    unsigned total_count = adding ? adding->count : 0;
    const cset_t* iter_old = oldest_set;
    while (iter_old) {
        total_count += iter_old->count;
        iter_old = iter_old->next_newer;
    }

    if (total_count) { // We have things to hash
        const uint32_t mask = count2mask(total_count << 1U);
        new_chal_tbl = xcalloc(sizeof(*new_chal_tbl) + (sizeof(new_chal_tbl->tbl[0]) * (mask + 1U)));
        new_chal_tbl->mask = mask;
        iter_old = oldest_set;
        while (iter_old) {
            chal_tbl_hash_cset(new_chal_tbl, iter_old, false);
            iter_old = iter_old->next_newer;
        }
        // Ask the hasher to check size constraints when adding new csets, and
        // can fail here, which means we need to destruct our new table and
        // return NULL.
        if (adding && chal_tbl_hash_cset(new_chal_tbl, adding, true)) {
            chal_tbl_destruct(new_chal_tbl);
            new_chal_tbl = NULL;
        }
    }

    return new_chal_tbl;
}

// Can swap in NULL with this, e.g. for flush
static void chal_tbl_swap_and_free(chal_tbl_t* new_chal_tbl)
{
    chal_tbl_t* old_chal_tbl = chal_tbl;
    rcu_assign_pointer(chal_tbl, new_chal_tbl);
    synchronize_rcu();
    if (old_chal_tbl)
        chal_tbl_destruct(old_chal_tbl);
}

F_NONNULL
static void cset_expire(struct ev_loop* loop, ev_timer* t, const int revents V_UNUSED)
{
    gdnsd_assert(revents == EV_TIMER);

    const ev_tstamp cutoff = ev_now(loop) + TIME_FUDGE;

    // Skip past the to-be-expired without actually deleting them yet
    cset_t* iter_old = oldest;
    while (iter_old && iter_old->expiry <= cutoff)
        iter_old = iter_old->next_newer;

    // Create new hashtable, RCU-swap, delete old hashtable.  New may be NULL
    // and implicitly empty, if iter_old is NULL because the above loop wants
    // to expire everything.
    chal_tbl_t* new_chal_tbl = chal_tbl_create(iter_old, NULL);
    chal_tbl_swap_and_free(new_chal_tbl);

    // Delete expired csets now that RCU swap guaranteed no runtime references,
    // and actual move the global "oldest" as we go
    while (oldest && oldest->expiry <= cutoff) {
        cset_t* nn = oldest->next_newer;
        free(oldest);
        oldest = nn;
    }

    // If list items remain for future expiry, start a new timer event
    if (oldest) {
        ev_timer_set(t, oldest->expiry - ev_now(loop), 0);
        ev_timer_start(loop, t);
    } else {
        newest = NULL;
    }
}

void cset_flush(struct ev_loop* loop)
{
    // RCU-swap a NULL in and delete old hashtable
    chal_tbl_swap_and_free(NULL);

    // Delete all csets, as if they all expired, updating "oldest" as we go
    // until it becomes NULL
    while (oldest) {
        cset_t* nn = oldest->next_newer;
        free(oldest);
        oldest = nn;
    }
    newest = NULL;

    // Kill expire timer, nothing to expire
    if (loop) {
        ev_timer* t = &expire_timer;
        ev_timer_stop(loop, t);
    }

    log_debug("Flushed all ACME DNS-01 challenges");
}

// construct a whole TXT RR encoding the payload
static void mk_chal_rr(uint8_t* out, const uint8_t* payload)
{
    size_t idx = 0;
    gdnsd_put_una32(DNS_RRFIXED_TXT, &out[idx]);
    idx += 4;
    gdnsd_put_una32(htonl(gcfg->acme_challenge_ttl), &out[idx]);
    idx += 4;
    gdnsd_put_una16(htons(44), &out[idx]);
    idx += 2;
    out[idx++] = 43U;
    memcpy(&out[idx], payload, 43U);
    gdnsd_assert((idx + 43U) == CHAL_RR_LEN);
}

bool cset_create(struct ev_loop* loop, size_t ttl_remain, size_t count, size_t dlen, uint8_t* data)
{
    if (!count || !dlen || count > CHAL_MAX_COUNT || dlen > CHAL_MAX_DLEN) {
        log_err("Control socket send illegal ACME dns-01 challenge data");
        return true;
    }

    cset_t* cset = xmalloc(sizeof(*cset) + (sizeof(cset->chals[0]) * count));
    cset->count = count;
    if (!ttl_remain || ttl_remain > gcfg->acme_challenge_ttl)
        ttl_remain = gcfg->acme_challenge_ttl;
    cset->expiry = ev_now(loop) + ttl_remain;
    cset->next_newer = NULL;

    log_debug("Attempting to create ACME DNS-01 challenge set with %zu items:", count);

    size_t didx = 0;
    for (size_t i = 0; i < count; i++) {
        gdnsd_assert(didx <= dlen);
        if (dname_status_buflen(&data[didx], (dlen - didx)) == DNAME_INVALID) {
            log_err("Control socket sent invalid domainname in acme-dns-01 request");
            free(cset);
            return true;
        }
        chal_t* c = &cset->chals[i];
        dname_copy(c->dname, &data[didx]);
        dname_terminate(c->dname);
        didx += (data[didx] + 1U);
        c->dnhash = dname_hash(c->dname);

        gdnsd_assert(didx <= dlen);
        if ((dlen - didx) < 44U) {
            log_err("Control socket sent too little payload data in acme-dns-01 request");
            free(cset);
            return true;
        }
        data[didx + 43U] = '\0'; // should already be there, but enforce JIC
        mk_chal_rr(c->txt, &data[didx]);
        log_devdebug("ACME DNS-01 record created: dname '%s' payload '%s'", logf_dname(c->dname), &data[didx]);
        didx += 44U;
    }

    if (didx != dlen) {
        log_err("Control socket sent trailing junk data in acme-dns-01 request");
        free(cset);
        return true;
    }

    chal_tbl_t* new_chal_tbl = chal_tbl_create(oldest, cset);

    if (!new_chal_tbl) {
        log_err("Rejected acme-dns-01 challenge creation: collision sanity constraints exceeded, likely a runaway ACME automation script");
        free(cset);
        return true;
    }

    // Update linked list and deal with timer
    if (!oldest) {
        gdnsd_assert(!newest); // empty before this creation
        oldest = newest = cset;
        ev_timer* expire = &expire_timer;
        ev_timer_set(expire, gcfg->acme_challenge_ttl, 0);
        ev_timer_start(loop, expire);
    } else {
        gdnsd_assert(newest); // non-empty lists have both ends defined
        gdnsd_assert(!newest->next_newer);
        newest->next_newer = cset;
        newest = cset;
    }

    // Swap the new hashtable in for runtime lookups
    chal_tbl_swap_and_free(new_chal_tbl);

    return false;
}

// Serialize a cset_t back into controlsock wire format
F_NONNULL F_WUNUSED
static size_t cset_serialize(ev_tstamp now, cset_t* cset, uint8_t* dptr)
{
    gdnsd_assert(cset->count <= CHAL_MAX_COUNT);
    gdnsd_assert(cset->count);

    uint16_t ttl_remain = 0;
    gdnsd_assert(now < cset->expiry);
    gdnsd_assert(gcfg->acme_challenge_ttl <= UINT16_MAX);
    ev_tstamp remain_raw = cset->expiry - now;
    if (remain_raw > gcfg->acme_challenge_ttl)
        ttl_remain = gcfg->acme_challenge_ttl;
    else
        ttl_remain = (uint16_t)remain_raw;

    size_t offset = 2U; // save room for placing size at start
    gdnsd_put_una16(ttl_remain, &dptr[offset]);
    offset += 2U;
    dptr[offset++] = (uint8_t)cset->count;
    for (size_t i = 0; i < cset->count; i++) {
        const chal_t* c = &cset->chals[i];
        gdnsd_assert(dname_status(c->dname) == DNAME_VALID);
        dname_copy(&dptr[offset], c->dname);
        offset += c->dname[0] + 1U;
        memcpy(&dptr[offset], &c->txt[CHAL_RR_FIELDS], CHAL_RR_PAYLOAD);
        offset += CHAL_RR_PAYLOAD;
        dptr[offset++] = 0;
    }

    gdnsd_assert(offset > 5U);
    gdnsd_assert(offset <= CHAL_MAX_SERIAL);

    const size_t dlen = offset - 5U;
    gdnsd_assert(dlen <= UINT16_MAX);
    gdnsd_put_una16(dlen, dptr);

    return offset;
}

uint8_t* csets_serialize(struct ev_loop* loop, size_t* csets_count_p, size_t* csets_dlen_p)
{
    uint8_t* rv = NULL;
    size_t allocated = 0;
    size_t used = 0;
    size_t ct = 0;
    ev_tstamp now = ev_now(loop);

    cset_t* cur = oldest;
    while (cur) {
        if ((now + TIME_FUDGE) < cur->expiry) {
            if (used + CHAL_MAX_SERIAL > allocated) {
                if (unlikely(used + CHAL_MAX_SERIAL > UINT32_MAX)) {
                    log_err("Handing off partial ACME challenge data, total data length exceeds design limits");
                    break;
                }
                allocated += CHAL_MAX_SERIAL;
                rv = xrealloc(rv, allocated);
            }
            used += cset_serialize(now, cur, &rv[used]);
            if (unlikely(ct == 0xFFFFFFu)) {
                log_err("Handing off partial ACME challenge data, total count exceeds design limits");
                break;
            }
            ct++;
        }
        cur = cur->next_newer;
    }

    *csets_count_p = ct;
    *csets_dlen_p = used;
    return rv;
}

// runtime lookup called in dns i/o thread context from dnspacket.c from within
// an RCU read-side critical section.  Must be fast, non-blocking, no syscalls.
bool chal_respond(const unsigned qname_comp, const unsigned qtype, const uint8_t* qname, uint8_t* packet, unsigned* ancount_p, unsigned* offset_p, const unsigned this_max_response)
{
    bool matched = false;
    const bool qname_is_chal = dname_is_acme_chal(qname);
    const chal_tbl_t* t = rcu_dereference(chal_tbl);
    if (t) {
        uint8_t qn_stripped[256];
        if (qname_is_chal) {
            // Make a copy we can edit, skip over the first label and inject a
            // new overall length byte at offset 16, then set qname->that.
            dname_copy(qn_stripped, qname);
            qn_stripped[16] = qn_stripped[0] - 16U;
            qname = &qn_stripped[16];
        }
        const uint32_t qname_hash = dname_hash(qname);
        chal_collide_t* coll = t->tbl[qname_hash & t->mask];
        if (coll) {
            for (unsigned i = 0; i < coll->count; i++) {
                const chal_t* ch = coll->chals[i];
                if (ch->dnhash == qname_hash && likely(!dname_cmp(qname, ch->dname))) {
                    matched = true;
                    if (qname_is_chal && qtype == DNS_TYPE_TXT) {
                        if ((*offset_p + 2U + CHAL_RR_LEN) > this_max_response)
                            break; // do not run off the end of the buffer!
                        gdnsd_put_una16(htons(qname_comp | 0xC000), &packet[*offset_p]);
                        (*offset_p) += 2;
                        memcpy(&packet[*offset_p], ch->txt, CHAL_RR_LEN);
                        (*offset_p) += CHAL_RR_LEN;
                        (*ancount_p)++;
                    } else {
                        // no need for multi-match if not encoding responses
                        break;
                    }
                }
            }
        }
    }
    return matched;
}

static void chal_cleanup(void)
{
    cset_flush(NULL);
}

// called from main.c early in daemon life, before any other functions in this
// file could possibly be called
void chal_init(void)
{
    ev_timer* expire_ptr = &expire_timer;
    memset(expire_ptr, 0, sizeof(*expire_ptr));
    ev_timer_init(expire_ptr, cset_expire, 0., 0.);
    gdnsd_atexit(chal_cleanup);
}
