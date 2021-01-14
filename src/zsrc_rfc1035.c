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

#include <config.h>
#include "zsrc_rfc1035.h"

#include "zscan_rfc1035.h"
#include "conf.h"
#include "ltree.h"
#include "main.h"

#include <gdnsd/alloc.h>
#include <gdnsd/misc.h>
#include <gdnsd/log.h>
#include <gdnsd/paths.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

static char* rfc1035_dir = NULL;

F_NONNULL
static char* make_zone_name(const char* zf_name)
{
    unsigned zf_name_len = strlen(zf_name);
    char* out = NULL;

    if (zf_name_len > 1004) {
        log_err("rfc1035: Zone file name '%s' is illegal", zf_name);
    } else {
        // check for root zone...
        if (unlikely(zf_name_len == 9 && !strncmp(zf_name, "ROOT_ZONE", 9))) {
            out = xmalloc(2);
            out[0] = '.';
            out[1] = 0;
        } else {
            // convert all '@' to '/' for RFC2317 reverse delegation zones
            out = xmalloc(zf_name_len + 1);
            for (unsigned i = 0; i <= zf_name_len; i++) {
                if (unlikely(zf_name[i] == '@'))
                    out[i] = '/';
                else
                    out[i] = zf_name[i];
            }
        }
    }

    return out;
}

// Threaded parallel processing of zonefiles:

struct zf_list {
    char* full_fn; // worker input
    const char* fn; // (aliases into above, needs no free)
    struct ltree_node_zroot* zroot; // worker output
    struct zf_list* next; // next in list
};

F_NONNULL
static void zf_list_early_destroy(struct zf_list* zfl)
{
    if (zfl->next)
        zf_list_early_destroy(zfl->next);
    gdnsd_assert(!zfl->zroot);
    free(zfl->full_fn);
    free(zfl);
}

struct zf_threads {
    size_t threads;
    size_t next_thread;
    size_t total_count;
    struct zf_list** lists;
    pthread_t* threadids;
};

static struct zf_threads* zf_threads_new(const size_t threads)
{
    gdnsd_assume(threads);
    struct zf_threads* zft = xcalloc(sizeof(*zft));
    zft->threads = threads;
    zft->threadids = xcalloc_n(threads, sizeof(*zft->threadids));
    zft->lists = xcalloc_n(threads, sizeof(*zft->lists));
    return zft;
}

F_NONNULL
static void zf_threads_add_zone(struct zf_threads* zft, char* full_fn, const char* fn)
{
    struct zf_list* zfl = xcalloc(sizeof(*zfl));
    zfl->full_fn = full_fn;
    zfl->fn = fn;
    gdnsd_assume(zft->next_thread < zft->threads);
    struct zf_list** slot = &zft->lists[zft->next_thread];
    while (*slot)
        slot = &(*slot)->next;
    *slot = zfl;
    zft->next_thread++;
    zft->next_thread %= zft->threads;
    zft->total_count++;
}

// If something fails while adding zones, but before invoking load_zones below
// (e.g. readdir() failure), call this to clean up the structure built so far.
F_NONNULL
static void zf_threads_early_destroy(struct zf_threads* zft)
{
    for (size_t i = 0; i < zft->threads; i++)
        if (zft->lists[i])
            zf_list_early_destroy(zft->lists[i]);
    free(zft->lists);
    free(zft->threadids);
    free(zft);
}

F_NONNULL
static void* zones_worker(void* list_asvoid)
{
    gdnsd_thread_setname("rfc1035-worker");
    struct zf_list* zfl = list_asvoid;
    while (zfl) {
        char* name = make_zone_name(zfl->fn);
        if (!name)
            return (void*)1;
        struct ltree_node_zroot* zroot = ltree_new_zone(name);
        free(name);
        if (!zroot)
            return (void*)1;
        zfl->zroot = zroot;
        if (zscan_rfc1035(zroot, zfl->full_fn) || ltree_postproc_zone(zroot))
            return (void*)1;
        zfl = zfl->next;
    }

    return NULL;
}

F_NONNULL
static bool harvest_zone_worker(pthread_t threadid, struct zf_list* zfl, union ltree_node** root_of_dns_p, bool failed)
{
    void* raw_exit_status = (void*)1;
    int pthread_err = pthread_join(threadid, &raw_exit_status);
    if (pthread_err)
        log_err("pthread_join() of rfc1035 worker thread failed: %s", logf_strerror(pthread_err));
    if (raw_exit_status != NULL)
        failed = true;

    do {
        free(zfl->full_fn);
        if (!failed) {
            gdnsd_assume(zfl->zroot);
            failed = ltree_merge_zone(root_of_dns_p, zfl->zroot);
        }
        if (failed && zfl->zroot)
            ltree_destroy((union ltree_node*)zfl->zroot);
        zfl->zroot = NULL;
        struct zf_list* next = zfl->next;
        free(zfl);
        zfl = next;
    } while (zfl);

    return failed;
}

// This is done once after all _add_zone above.  It spawns the worker threads,
// collects their output zone data, and merges it into the global root ltree
// that's being constructed for this global load/reload operation.  It also
// logs the final success count (if successful!) and always deallocates all
// struct zf_threads/struct zf_list resources by the time it returns, even if things fail
// partially or wholly.
F_NONNULL
static union ltree_node* zf_threads_load_zones(struct zf_threads* zft, union ltree_node* root_of_dns)
{
    sigset_t sigmask_all;
    sigfillset(&sigmask_all);
    sigset_t sigmask_prev;
    sigemptyset(&sigmask_prev);
    if (pthread_sigmask(SIG_SETMASK, &sigmask_all, &sigmask_prev))
        log_fatal("pthread_sigmask() failed");

    pthread_attr_t attribs;
    pthread_attr_init(&attribs);
    pthread_attr_setdetachstate(&attribs, PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&attribs, PTHREAD_SCOPE_SYSTEM);

    size_t useful_threads = zft->total_count < zft->threads ? zft->total_count : zft->threads;

    for (size_t i = 0; i < useful_threads; i++) {
        int pthread_err = pthread_create(&zft->threadids[i], &attribs, &zones_worker, zft->lists[i]);
        if (pthread_err)
            log_fatal("pthread_create() of zone data thread failed: %s", logf_strerror(pthread_err));
    }

    if (pthread_sigmask(SIG_SETMASK, &sigmask_prev, NULL))
        log_fatal("pthread_sigmask() failed");
    pthread_attr_destroy(&attribs);

    bool failed = false;
    for (size_t i = 0; i < useful_threads; i++)
        failed = harvest_zone_worker(zft->threadids[i], zft->lists[i], &root_of_dns, failed);

    if (!failed)
        log_info("rfc1035: Loaded %zu zonefiles from '%s'", zft->total_count, rfc1035_dir);

    free(zft->lists);
    free(zft->threadids);
    free(zft);

    if (failed) {
        ltree_destroy(root_of_dns);
        root_of_dns = NULL;
    }

    return root_of_dns;
}

/*************************/
/*** Public interfaces ***/
/*************************/

union ltree_node* zsrc_rfc1035_load_zones(void)
{
    union ltree_node* root_of_dns = xcalloc(sizeof(*root_of_dns));
    root_of_dns->c.dname = xmalloc(2U);
    root_of_dns->c.dname[0] = '\1';
    root_of_dns->c.dname[1] = '\0';

    gdnsd_assume(rfc1035_dir);
    DIR* zdhandle = opendir(rfc1035_dir);
    if (!zdhandle) {
        if (errno == ENOENT) {
            log_debug("rfc1035: Zones directory '%s' does not exist", rfc1035_dir);
            return root_of_dns;
        }
        log_err("rfc1035: Cannot open zones directory '%s': %s", rfc1035_dir, logf_errno());
        return NULL;
    }

    struct zf_threads* zft = zf_threads_new(gcfg->zones_rfc1035_threads);

    bool failed = false;
    const struct dirent* result = NULL;
    do {
        errno = 0;
        result = readdir(zdhandle);
        if (likely(result)) {
            if (result->d_name[0] != '.') {
                struct stat st;
                const char* fn;
                char* full_fn = gdnsd_str_combine(rfc1035_dir, result->d_name, &fn);
                if (stat(full_fn, &st)) {
                    log_err("rfc1035: stat(%s) failed: %s", full_fn, logf_errno());
                    free(full_fn);
                    failed = true;
                } else if (S_ISREG(st.st_mode)) {
                    zf_threads_add_zone(zft, full_fn, fn);
                } else {
                    free(full_fn);
                }
            }
        } else if (errno) {
            log_err("rfc1035: readdir(%s) failed: %s", rfc1035_dir, logf_errno());
            failed = true;
        }
    } while (!failed && result);

    if (closedir(zdhandle)) {
        log_err("rfc1035: closedir(%s) failed: %s", rfc1035_dir, logf_errno());
        failed = true;
    }

    if (failed) {
        ltree_destroy(root_of_dns);
        zf_threads_early_destroy(zft);
        return NULL;
    }

    return zf_threads_load_zones(zft, root_of_dns);
}

void zsrc_rfc1035_init(void)
{
    rfc1035_dir = gdnsd_resolve_path_cfg("zones/", NULL);
}
