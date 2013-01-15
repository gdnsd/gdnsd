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

#include "zsrc_rfc1035.h"
#include "gdnsd/misc.h"
#include "gdnsd/log.h"
#include "gdnsd/paths.h"
#include "zscan_rfc1035.h"
#include "conf.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <time.h>

#include "ztree.h"

// IFF gconfig.zones_rfc1035_strict_startup is true,
//   this flag will be temporarily set to true during
//   the initial scan, then set back to false, making
//   zonefile parsing errors fatal for the initial scan.
static bool fail_fatally = false;

// quiesce time values.
// these are configurable via zones_rfc1035_min_quiesce
//   and zones_rfc1035_quiesce, respectively, but the first
//   may be adjusted upwards depending on compile-/run-
//   time detected OS/Filesystem constraints, and the latter
//   will always be adjusted (if necessary) to be >= the former.
static double min_quiesce = 1.02;
static double full_quiesce = 5.0;

#if USE_INOTIFY

#include <sys/inotify.h>

// this is set true once at startup if applicable
static bool using_inotify = false;

// size of our read(2) buffer for the inotify fd.
// must be able to handle sizeof(struct inotify_event)
//  + the max len of a filename in the zones directory
// read(2) will return EINVAL if this ends up being too small...
static const unsigned inotify_bufsize = 4096;

// The inotify mask for the zones dir watcher
#define INL_MASK ( IN_ONLYDIR | IN_DONT_FOLLOW \
     | IN_EXCL_UNLINK | IN_MODIFY | IN_ATTRIB \
     | IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM \
     | IN_CREATE | IN_DELETE | IN_MOVE_SELF | IN_DELETE_SELF)

// runtime inotify bits
typedef struct {
    int main_fd;
    int watch_desc;
    ev_io* io_watcher;
    ev_timer* fallback_watcher;
} inot_data;
static inot_data inot;

#else // not USE_INOTIFY
static const bool using_inotify = false;
#endif

char* rfc1035_dir = NULL;

// POSIX states that inode+dev uniquely identifies a file on
//   a given system.  Therefore those + mtime should uniquely
//   identify a set of file contents for a given pathname over
//   time through ops like create/destroy/modify/rename/remount/etc...
// The special value of all members being zero indicates a
//   non-existent (e.g. deleted) file.  The same value is used
//   to indicate an invalid zonefile (e.g. the pathname is
//   a subdirectory, a socket, a softlink, etc...)
typedef struct {
    uint64_t m; // see ztree.h
    ino_t i;    // st.st_inode
    dev_t d;    // st.st_dev
} statcmp_t;

static bool statcmp_eq(statcmp_t* a, statcmp_t* b) {
    return !((a->m ^ b->m) | (a->i ^ b->i) | (a->d ^ b->d));
}

// check for 0/0/0, indicating deleted or invalid (e.g. socket)
static bool statcmp_nx(statcmp_t* a) {
    return !(a->m | a->i | a->d);
}

// represents a zone file
// on initial load, update_pending is false, and thus "pending" is irrelevant
// when change detection sees a statcmp diff between "loaded" and the
//   filesystem, it's going to set "update_pending" and save the fs info
//   to "pending", while in many cases a quiescence timer waits for further
//   updates.
// when "pending" and the raw FS have stabilized, then the zone is actually
//   reloaded and "loaded" is set to "pending" values and the update_pending
//   flag is cleared.
typedef struct {
    unsigned hash;       // hash of "fn"
    unsigned generation; // generation counter for deletion checks
    char* full_fn;       // "etc/zones/example.com"
    const char* fn;      // ptr to "example.com" in above storage
    zone_t* zone;        // zone data
    ev_timer* pending_event; // pending quiescence timer, NULL if no pending change
    statcmp_t pending;   // lstat() info on pending update
    statcmp_t loaded;    // lstat() info on loaded data
} zfile_t;

// hash of all extant zonefiles
static zfile_t** zfhash = NULL;
static unsigned zfhash_count = 0;
static unsigned zfhash_alloc = 0;
static unsigned generation = 0; // deletion checks use this...

// ZFILE_DELETED is a deleted hash entry that can be reclaimed
static void* const ZFILE_DELETED = (void*)(uintptr_t)0x1;
// SLOT_REAL means not NULL and also not a reclaimable deleted entry
#define SLOT_REAL(x) ((uintptr_t)x & ~1UL)

F_NONNULL
static void zf_delete(zfile_t* zf) {
    dmn_assert(zf);
    if(zf->zone)
        zone_delete(zf->zone);
    if(zf->full_fn)
        free(zf->full_fn);
    if(zf->pending_event)
        free(zf->pending_event);
    free(zf);
}

static void statcmp_set(const char* full_fn, statcmp_t* out) {
    dmn_assert(full_fn); dmn_assert(out);

    struct stat st;
    int lstat_rv = lstat(full_fn, &st);
    if(likely(!lstat_rv && S_ISREG(st.st_mode))) {
        out->m = get_extended_mtime(&st);
        out->i = st.st_ino;
        out->d = st.st_dev;
    }
    else {
        out->m = 0;
        out->i = 0;
        out->d = 0;
    }
}

// grow hash by doubling, while also
//   clearing out deletion placeholders
F_NONNULL
static void zfhash_grow(void) {
    if(unlikely(!zfhash_alloc)) {
        // initial call on empty hash
        dmn_assert(!zfhash);
        dmn_assert(!zfhash_count);
        zfhash_alloc = 16;
        zfhash = calloc(16, sizeof(zfile_t*));
        return;
    }

    const unsigned new_alloc = zfhash_alloc << 1; // double
    const unsigned new_hash_mask = new_alloc - 1;
    zfile_t** new_hash = calloc(new_alloc, sizeof(zfile_t*));

    for(unsigned i = 0; i < zfhash_alloc; i++) {
        zfile_t* zf = zfhash[i];
        if(SLOT_REAL(zf)) {
            unsigned jmpby = 1;
            unsigned slot = zf->hash & new_hash_mask;
            while(new_hash[slot]) {
                slot += jmpby++;
                slot &= new_hash_mask;
            }
            new_hash[slot] = zf;
        }
    }

    free(zfhash);
    zfhash = new_hash;
    zfhash_alloc = new_alloc;
}

// assumes this filename does not exist in hash already,
// called must use zfhash_find() first!
F_NONNULL
static void zfhash_add(zfile_t* zf) {
    dmn_assert(zf);
    dmn_assert(zf->fn);
    dmn_assert(zf->full_fn);

    // Max 25% load
    if(unlikely(zfhash_count >= (zfhash_alloc >> 2)))
        zfhash_grow();

    const unsigned hash_mask = zfhash_alloc - 1;
    unsigned slot = zf->hash & hash_mask;
    unsigned jmpby = 1;
    while(SLOT_REAL(zfhash[slot])) {
        slot += jmpby++;
        slot &= hash_mask;
    }
    zfhash[slot] = zf;
    zfhash_count++;
}

F_NONNULL
static void zfhash_del(zfile_t* zf) {
    dmn_assert(zf);
    dmn_assert(zf->fn);
    dmn_assert(zf->full_fn);

    const unsigned hash_mask = zfhash_alloc - 1;
    unsigned slot = zf->hash & hash_mask;
    unsigned jmpby = 1;
    while(zfhash[slot] != zf) {
        slot += jmpby++;
        slot &= hash_mask;
    }

    zfhash[slot] = ZFILE_DELETED;
    zfhash_count--;

    zf_delete(zf);
}

F_NONNULL
static zfile_t* zfhash_find(const char* zfn) {
    dmn_assert(zfn);

    if(likely(zfhash_alloc)) {
        const unsigned zfn_hash = gdnsd_lookup2(zfn, strlen(zfn));
        const unsigned hash_mask = zfhash_alloc - 1;
        unsigned slot = zfn_hash & hash_mask;
        unsigned jmpby = 1;
        zfile_t* cand;
        while((cand = zfhash[slot])) {
            if(SLOT_REAL(cand) && cand->hash == zfn_hash && !strcmp(cand->fn, zfn))
                return cand;
            slot += jmpby++;
            slot &= hash_mask;
        }
    }

    return NULL;
}

F_NONNULL
static char* make_zone_name(const char* zf_name) {
    dmn_assert(zf_name);

    unsigned zf_name_len = strlen(zf_name);
    char* out = NULL;

    if(unlikely(zf_name_len > 1004)) {
        log_err("rfc1035: Zone file name '%s' is illegal", zf_name);
    }
    else {
        out = malloc(zf_name_len + 1);
        // check for root zone...
        if(unlikely(zf_name_len == 9 && !strncmp(zf_name, "ROOT_ZONE", 9))) {
            out[0] = '.';
            out[1] = 0;
        }
        else {
            // convert all '@' to '/' for RFC2137 reverse delegation zones
            for(unsigned i = 0; i <= zf_name_len; i++) {
                if(unlikely(zf_name[i] == '@'))
                    out[i] = '/';
                else
                    out[i] = zf_name[i];
            }
        }
    }

    return out;
}

F_NONNULL
static zone_t* zone_from_zf(zfile_t* zf) {
    dmn_assert(zf);

    char* name = make_zone_name(zf->fn);
    if(!name)
        return NULL;

    char* src = gdnsd_str_combine("rfc1035:", zf->fn, NULL);
    zone_t* z = zone_new(name, src);
    free(src);
    free(name);

    if(z) {
        if(zscan_rfc1035(z, zf->full_fn) || zone_finalize(z)) {
            zone_delete(z);
            z = NULL;
        }
    }

    return z;
}

F_NONNULL
static void quiesce_check(struct ev_loop* loop, ev_timer* timer, int revents V_UNUSED) {
    dmn_assert(loop);
    dmn_assert(timer);
    dmn_assert(revents = EV_TIMER);

    zfile_t* zf = (zfile_t*)timer->data;
    dmn_assert(zf->pending_event == timer);

    // check lstat() again for a new change during quiesce period
    statcmp_t newstat;
    statcmp_set(zf->full_fn, &newstat);

    // if it stayed stable...
    if(statcmp_eq(&newstat, &zf->pending)) {
        // stable delete
        if(statcmp_nx(&newstat)) {
            if(zf->zone) {
                log_debug("rfc1035: zonefile '%s' quiesce timer: acting on deletion, removing zone data from runtime...", zf->fn);
                dmn_assert(!statcmp_nx(&zf->loaded));
                ztree_update(zf->zone, NULL);
            }
            else {
                log_debug("rfc1035: zonefile '%s' quiesce timer: processing delete without runtime effects (add->remove before quiescence ended?)", zf->fn);
            }
            zfhash_del(zf);
        }
        // quiesced state isn't deleted, we need to load data
        else {
            zone_t* z = zone_from_zf(zf);
            // re-check that file didn't change while loading
            statcmp_t post_check;
            statcmp_set(zf->full_fn, &post_check);
            if(!statcmp_eq(&zf->pending, &post_check)) {
                log_debug("rfc1035: zonefile '%s' quiesce timer: lstat() changed during zonefile parsing, restarting timer for %.3g seconds...", zf->fn, full_quiesce);
                if(z)
                     zone_delete(z);
                ev_timer_set(timer, full_quiesce, 0.);
                ev_timer_start(loop, timer);
            }
            else {
                if(z) {
                    log_debug("rfc1035: zonefile '%s' quiesce timer: new zone data being added/updated for runtime...", zf->fn);
                    memcpy(&zf->loaded, &zf->pending, sizeof(statcmp_t));
                    z->mtime = zf->loaded.m;
                    ztree_update(zf->zone, z);
                    if(zf->zone)
                        zone_delete(zf->zone);
                    zf->zone = z;
                }
                else {
                    if(fail_fatally)
                        log_fatal("rfc1035: Cannot load zonefile '%s', failing", zf->fn);
                    log_debug("rfc1035: zonefile '%s' quiesce timer: zone parsing failed while lstat() info remained stable, dropping event, awaiting further fresh FS notification to try new syntax fixes...", zf->fn);
                }
                free(zf->pending_event);
                zf->pending_event = NULL;
            }
        }
    }
    else {
        log_debug("rfc1035: zonefile '%s' quiesce timer: lstat() changed again, restarting timer for %.3g seconds...", zf->fn, full_quiesce);
        ev_timer_set(timer, full_quiesce, 0.);
        ev_timer_start(loop, timer);
    }
}

F_NONNULL
static void process_zonefile(const char* zfn, struct ev_loop* loop, const double initial_quiesce_time) {
    dmn_assert(zfn);
    dmn_assert(loop);

    const char* fn;
    char* full_fn = gdnsd_str_combine(rfc1035_dir, zfn, &fn);

    statcmp_t newstat;
    statcmp_set(full_fn, &newstat);
    zfile_t* current_zft = zfhash_find(fn);

    if(!statcmp_nx(&newstat) && !current_zft) {
        // file was found, but previously unknown to the zfhash
        current_zft = calloc(1, sizeof(zfile_t));
        current_zft->full_fn = full_fn;
        current_zft->fn = fn;
        current_zft->hash = gdnsd_lookup2(fn, strlen(fn));
        zfhash_add(current_zft);
    }
    else {
        // else we don't need this new copy of the full fn,
        //   it's already there in the current_zft
        dmn_assert(!current_zft || !strcmp(current_zft->full_fn, full_fn));
        free(full_fn);
    }

    // the outer if-block here on the rest of this code means
    //   we take no action if both the file in question did
    //   not exist in the zfhash and also does not currently
    //   exist on-disk.
    if(current_zft) {
        // setting current_zft->generation for every file picked up
        //   by scandir() is what keeps check_missing() from thinking
        //   this zfile_t*'s target was deleted from the filesystem.
        current_zft->generation = generation;
        if(current_zft->pending_event) { // we already had a pending change
            if(!statcmp_eq(&newstat, &current_zft->pending)) { // but it changed again!
                log_debug("rfc1035: Change detected for already-pending zonefile '%s', delaying %.3g secs for further changes...", current_zft->fn, full_quiesce);
                memcpy(&current_zft->pending, &newstat, sizeof(statcmp_t));
                ev_timer_stop(loop, current_zft->pending_event);
                ev_timer_set(current_zft->pending_event, full_quiesce, 0.);
                ev_timer_start(loop, current_zft->pending_event);
            }
            // else (if pending state has not changed) let timer continue as it was...
            //   (spurious notification of already-detected change)
        }
        else if(!statcmp_eq(&newstat, &current_zft->loaded)) { // initial change detected
            if(statcmp_nx(&current_zft->loaded))
                log_debug("rfc1035: New zonefile '%s', delaying %.3g secs for further changes...", current_zft->fn, initial_quiesce_time);
            else
                log_debug("rfc1035: New change detected for stable zonefile '%s', delaying %.3g secs for further changes...", current_zft->fn, initial_quiesce_time);
            memcpy(&current_zft->pending, &newstat, sizeof(statcmp_t));
            current_zft->pending_event = malloc(sizeof(ev_timer));
            ev_timer_init(current_zft->pending_event, quiesce_check, initial_quiesce_time, 0.);
            current_zft->pending_event->data = current_zft;
            ev_timer_start(loop, current_zft->pending_event);
        }
    }
}

static void unload_zones(void) {
    for(unsigned i = 0; i < zfhash_alloc; i++) {
        zfile_t* zf = zfhash[i];
        if(SLOT_REAL(zf)) {
            if(zf->zone)
                ztree_update(zf->zone, NULL);
            zf_delete(zf);
        }
    }
}

static void scan_dir(struct ev_loop* loop, double initial_quiesce_time) {
    DIR* zdhandle = opendir(rfc1035_dir);
    if(!zdhandle) {
        log_err("rfc1035: Cannot open zones directory '%s': %s", rfc1035_dir, dmn_strerror(errno));
    }
    else {
        struct dirent* zfdi;
        while((zfdi = readdir(zdhandle)))
            if(likely(zfdi->d_name[0] != '.'))
                process_zonefile(zfdi->d_name, loop, initial_quiesce_time);
        if(closedir(zdhandle))
            log_err("rfc1035: closedir(%s) failed: %s", rfc1035_dir, dmn_strerror(errno));
    }
}

// This is the complement to the periodic scandir(), which
//  detects deletion events.  Its job is to run immediately
//  after the scandir loop and find zfhash entries that lack
//  the current "generation" counter value, indicating they
//  were not seen during scandir(), and feed them back into
//  process_zonefile() to be picked up as deletions.
F_NONNULL
static void check_missing(struct ev_loop* loop) {
    dmn_assert(loop);
    dmn_assert(generation);

    for(unsigned i = 0; i < zfhash_alloc; i++) {
        zfile_t* zf = zfhash[i];
        if(SLOT_REAL(zf)) {
            if(zf->generation != generation) {
                log_debug("rfc1035: check_missing() found deletion of zonefile '%s', triggering process_zonefile()", zf->fn);
                process_zonefile(zf->fn, loop, full_quiesce);
            }
        }
    }
}

F_NONNULL
static void do_scandir(struct ev_loop* loop) {
    dmn_assert(loop);
    generation++;
    scan_dir(loop, full_quiesce);
    check_missing(loop);
}

F_NONNULL
static void periodic_scan(struct ev_loop* loop, ev_timer* rtimer V_UNUSED, int revents V_UNUSED) {
    dmn_assert(loop);
    dmn_assert(rtimer);
    dmn_assert(revents == EV_TIMER);
    do_scandir(loop);
}

// ev stuff
static ev_timer* reload_timer = NULL;

#if USE_INOTIFY

static void set_inotify(void) {
    // Technically, it wouldn't be hard to support as low as 2.6.25 if
    //   we dropped IN_EXCL_UNLINK (merely an optimization) and didn't
    //   use inotify_init1(), but 2.6.36 seems a reasonably-old target
    //   for new code at this point in time, esp given we have a generic
    //   fallback with the scandir()-based model.
    if((using_inotify = gdnsd_linux_min_version(2, 6, 36)))
        log_info("rfc1035: will use inotify for zone change detection");
}

// This is for event debugging only
#define _maskcat(_x) \
    if(mask & _x) { \
        if(!optr[0]) \
            strcat(optr, #_x); \
        else \
            strcat(optr, "|" #_x); \
    }
static const char* logf_inmask(uint32_t mask) {
    char* output = dmn_fmtbuf_alloc(256);
    char* optr = output;
    optr[0] = 0;

    _maskcat(IN_ISDIR);
    _maskcat(IN_IGNORED);
    _maskcat(IN_Q_OVERFLOW);
    _maskcat(IN_UNMOUNT);
    _maskcat(IN_ACCESS);
    _maskcat(IN_ATTRIB);
    _maskcat(IN_CLOSE_WRITE);
    _maskcat(IN_CLOSE_NOWRITE);
    _maskcat(IN_CREATE);
    _maskcat(IN_DELETE);
    _maskcat(IN_DELETE_SELF);
    _maskcat(IN_MODIFY);
    _maskcat(IN_MOVE_SELF);
    _maskcat(IN_MOVED_FROM);
    _maskcat(IN_MOVED_TO);
    _maskcat(IN_OPEN);

    return output;
}

F_NONNULL
static void inot_reader(struct ev_loop* loop, ev_io* w, int revents);

static bool inotify_setup(void) {
    bool rv = false;

    inot.main_fd = inotify_init1(IN_NONBLOCK);
    if(inot.main_fd < 0) {
        log_err("rfc1035: inotify_init1(IN_NONBLOCK) failed: %s", logf_errno());
        rv = true;
    }
    else {
        inot.watch_desc = inotify_add_watch(inot.main_fd, rfc1035_dir, INL_MASK);
        if(inot.watch_desc < 0) {
            log_err("rfc1035: inotify_add_watch(%s) failed: %s", logf_pathname(rfc1035_dir), logf_errno());
            close(inot.main_fd);
            rv = true;
        }
        else {
            ev_io_init(inot.io_watcher, inot_reader, inot.main_fd, EV_READ);
        }
    }

    return rv;
}

static bool inotify_initial_failure = true;

static void inotify_initial_setup(void) {
    // Set up the actual inotify bits...
    memset(&inot, 0, sizeof(inot_data));
    inot.io_watcher = malloc(sizeof(ev_io));
    inot.fallback_watcher = malloc(sizeof(ev_timer));
    inotify_initial_failure = inotify_setup();
}

static void inotify_run(struct ev_loop* loop) {
    ev_io_start(loop, inot.io_watcher);
}

F_NONNULL
static void inotify_fallback_scan(struct ev_loop* loop, ev_timer* rtimer, int revents);

static void inotify_initial_run(struct ev_loop* loop) {
    ev_io_start(loop, inot.io_watcher);
    if(!inotify_initial_failure) {
        inotify_run(loop);
    }
    else {
        log_warn("rfc1035: Initial inotify() setup failed, using fallback scandir() method until recovery");
        ev_timer_init(inot.fallback_watcher, inotify_fallback_scan, gconfig.zones_rfc1035_auto_interval, gconfig.zones_rfc1035_auto_interval);
        ev_timer_start(loop, inot.fallback_watcher);
    }
}

static void inotify_fallback_scan(struct ev_loop* loop, ev_timer* rtimer, int revents) {
    dmn_assert(loop);
    dmn_assert(rtimer);
    dmn_assert(revents == EV_TIMER);

    bool setup_failure = inotify_setup();
    periodic_scan(loop, rtimer, revents);
    if(!setup_failure) {
        log_warn("rfc1035: inotify() recovered");
        ev_timer_stop(loop, rtimer);
        inotify_run(loop);
    }
}

F_NONNULL
static void handle_inotify_failure(struct ev_loop* loop) {
    dmn_assert(loop);

    log_warn("rfc1035: inotify() failed, using fallback scandir() method until recovery");

    // clean up old watcher setup
    ev_io_stop(loop, inot.io_watcher);
    inotify_rm_watch(inot.main_fd, inot.watch_desc);
    close(inot.main_fd);

    // insert periodic timer for fallback/retry scanning
    ev_timer_init(inot.fallback_watcher, inotify_fallback_scan, gconfig.zones_rfc1035_auto_interval, gconfig.zones_rfc1035_auto_interval);
    ev_timer_start(loop, inot.fallback_watcher);
}

// retval: true -> halt inotify loop
// This will not perform correctly in all cases.  This code can easily
//   be tricked into attempting to load partially-written zonefiles if
//   the zonefile management tools do silly things like overwriting
//   zonefiles in place and/or moving open files around while they're
//   being written to.
// The code makes a certain amount of effort to handle this sort of thing
//   which will mostly Just Work assuming there aren't huge delays between
//   the in-place writes, but there's no gaurantees unless the zonefile
//   updating tools strictly adhere to using atomic (i.e. rename(2)/mv(1))
//   moves to update the zones.
static bool inot_process_event(const char* fname, struct ev_loop* loop, uint32_t emask) {

    bool rv = false;

    if(!fname) { // directory-level event
        log_debug("rfc1035: inotified for directory event: %s", logf_inmask(emask));
        if(unlikely(emask & (IN_Q_OVERFLOW|IN_IGNORED|IN_UNMOUNT|IN_DELETE_SELF|IN_MOVE_SELF))) {
            log_err("rfc1035: inotify watcher stopping due to directory-level event %s", logf_inmask(emask));
            handle_inotify_failure(loop);
            rv = true;
        }
        // Other directory-level events (e.g. IN_MODIFY) are ignored.
        // We'll see their fallout as e.g. IN_MOVED_X operations on the contained filenames.
    }
    else if(fname[0] != '.') { // skip dotfiles
        log_debug("rfc1035: inotified for zonefile: %s event: %s", fname, logf_inmask(emask));
        // IN_MOVED_TO, IN_MOVED_FROM, and IN_DELETE are expected to commonly
        //   leave the zonefile in a consistent, user-desired state, so they cause a short
        //   initial quiesence timer if they're the first event seen recently on a file.
        // IN_CREATE, IN_MODIFY, and IN_CLOSE_WRITE will virtually always mean the file is
        //   being overwritten in-place (bad practice).  IN_ATTRIB is sort of an unknown
        //   depending on what's going on.  We make a best-effort to support these by using an
        //   initial quiesce period that's long like the default scandir() stuff.
        // Note that in any case, any time a quiesce period gets overlapped by a double-change
        //   to a single pathname, the second change *will* fall back to the longer, configured
        //   quiesce period, even if the final event was one of the "fast quiesce" ones above.
        double delay = min_quiesce; // fast reload on "normal" events
        if(emask & (IN_CREATE|IN_MODIFY|IN_CLOSE_WRITE|IN_ATTRIB))
            delay = full_quiesce;
        process_zonefile(fname, loop, delay);
    }

    return rv;
}

static void inot_reader(struct ev_loop* loop, ev_io* w, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w); dmn_assert(revents == EV_READ);

    uint8_t evtbuf[inotify_bufsize];

    while(1) {
        int bytes = read(w->fd, evtbuf, inotify_bufsize);
        if(bytes < 1) {
            if(!bytes || errno != EAGAIN) {
                if(bytes)
                    log_err("rfc1035: read() of inotify file descriptor failed: %s", logf_errno());
                else
                    log_err("rfc1035: Got EOF on inotify file descriptor!");
                handle_inotify_failure(loop);
            }
            return;
        }

        unsigned offset = 0;
        while(offset < (unsigned)bytes) {
            dmn_assert((bytes - offset) >= sizeof(struct inotify_event));
            struct inotify_event* evt = (void*)&evtbuf[offset];
            offset += sizeof(struct inotify_event);
            offset += evt->len;
            if(inot_process_event((evt->len > 0 ? evt->name : NULL), loop, evt->mask))
                return;
        }
    }
}

#else // no compile-time support for inotify

static void set_inotify(void) { }

static void inotify_initial_setup(void) {
    dmn_assert(false);
    log_fatal("rfc1035: inotify code called in non-inotify build???");
}

static void inotify_initial_run(struct ev_loop* loop V_UNUSED) {
    dmn_assert(false);
    log_fatal("rfc1035: inotify code called in non-inotify build???");
}

#endif // not-inotify

#ifndef O_SYNC
#define O_SYNC 0
#endif

F_UNUSED F_NONNULL
static uint64_t try_zone_mtime(const char* testfn) {
    uint64_t rv = UINT64_MAX;

    do {
        int fd = open(testfn, O_CREAT|O_TRUNC|O_SYNC|O_RDWR, 0644);

        if(fd < 0) {
            log_warn("rfc1035: failed to open %s for writing: %s", testfn, logf_errno());
            break;
        }

        if(9 != write(fd, "testmtime", 9)) {
            log_warn("rfc1035: failed to write 9 bytes to %s: %s", testfn, logf_errno());
            close(fd);
            unlink(testfn);
            break;
        }

        if(close(fd)) {
            log_warn("rfc1035: failed to close %s: %s", testfn, logf_errno());
            unlink(testfn);
            break;
        }

        struct stat st;

        if(lstat(testfn, &st)) {
            log_warn("rfc1035: failed to lstat %s: %s", testfn, logf_errno());
            unlink(testfn);
            break;
        }

        if(unlink(testfn)) {
            log_warn("rfc1035: failed to unlink %s: %s", testfn, logf_errno());
            break;
        }

        rv = get_extended_mtime(&st);
    } while(0);

    return rv;
}

static void set_quiesce(void) {
    double sys_min_quiesce = 1.02; // portable default

#if has_mtimens // ztree.h, no point trying if no nanoseconds in stat
    // The idea here is to touch a file and grab the high-res
    //   mtime 5 times in a row (with a small sleep between each),
    //   attempts to see whether the <10ms numbers are consistently zero.
    char* testfn = gdnsd_str_combine(rfc1035_dir, ".mtime_test", NULL);
    const struct timespec nsdelay = { 0, 2765432 }; // ~2.7ms
    unsigned attempts = 5;
    while(attempts--) {
        const uint64_t mt = try_zone_mtime(testfn);
        if(mt == UINT64_MAX)
            break; // can't do .mtime_test at all
        if(mt % 10000000) { // apparent precision better than 10ms
            sys_min_quiesce = 0.01; // set to 10ms
            break;
        }
        nanosleep(&nsdelay, NULL);
    }
    free(testfn);
#endif // has_mtimens

    min_quiesce = (sys_min_quiesce > gconfig.zones_rfc1035_min_quiesce)
        ? sys_min_quiesce
        : gconfig.zones_rfc1035_min_quiesce;
    full_quiesce = (min_quiesce > gconfig.zones_rfc1035_quiesce)
        ? min_quiesce
        : gconfig.zones_rfc1035_quiesce;
    log_info("rfc1035: quiescence times are %.3g min, %.3g full", min_quiesce, full_quiesce);

    // undocumented env var to speed startup for the testsuite on slow filesystems,
    //   which is ok if we don't plan to test dynamic changes to the zonefiles
    if(getenv("GDNSD_TESTSUITE_NO_ZONEFILE_MODS")) {
        log_warn("rfc1035: fast testsuite mode activited via env var!");
        full_quiesce = min_quiesce = 0.0;
    }
}

/*************************/
/*** Public interfaces ***/
/*************************/

void zsrc_rfc1035_load_zones(void) {
    dmn_assert(!rfc1035_dir);

    rfc1035_dir = gdnsd_resolve_path_cfg("zones/", NULL);
    set_quiesce();
    if(gconfig.zones_rfc1035_auto) {
        set_inotify();
        if(using_inotify)
            inotify_initial_setup();
    }
    if(gconfig.zones_rfc1035_strict_startup)
        fail_fatally = true;
    struct ev_loop* temp_load_loop = ev_loop_new(EVFLAG_AUTO);
    scan_dir(temp_load_loop, min_quiesce);
    ev_run(temp_load_loop, 0);
    ev_loop_destroy(temp_load_loop);
    free(reload_timer);
    fail_fatally = false;
    if(dmn_get_debug() && atexit(unload_zones))
        log_fatal("rfc1035: atexit(unload_zones) failed: %s", logf_errno());
}

// we track the loop here for the async sighup request
static struct ev_loop* zones_loop = NULL;
static ev_async* sighup_waker = NULL;

// called within our thread/loop to take sighup action
F_NONNULL
static void sighup_cb(struct ev_loop* loop, ev_async* w V_UNUSED, int revents V_UNUSED) {
    dmn_assert(loop); dmn_assert(w);
    log_info("rfc1035: received SIGHUP notification, scanning for changes...");
    do_scandir(loop);
}

// called from main thread to feed ev_async
void zsrc_rfc1035_sighup(void) {
    dmn_assert(zones_loop); dmn_assert(sighup_waker);
    ev_async_send(zones_loop, sighup_waker);
}

void zsrc_rfc1035_runtime_init(struct ev_loop* loop) {
    dmn_assert(loop);

    zones_loop = loop;
    sighup_waker = malloc(sizeof(ev_async));
    ev_async_init(sighup_waker, sighup_cb);
    ev_async_start(loop, sighup_waker);

    if(gconfig.zones_rfc1035_auto) {
        if(using_inotify) {
            inotify_initial_run(loop);
        }
        else {
            reload_timer = calloc(1, sizeof(ev_timer));
            ev_timer_init(reload_timer, periodic_scan, gconfig.zones_rfc1035_auto_interval, gconfig.zones_rfc1035_auto_interval);
            ev_timer_start(loop, reload_timer);
        }
    }
}
