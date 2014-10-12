/* Copyright © 2012-2013 Timo Teräs <timo.teras@iki.fi>
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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <setjmp.h>

#include "conf.h"
#include "ztree.h"
#include "zscan_djb.h"
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/misc.h>

#define TTL_NS 259200
#define TTL_POSITIVE 86400
#define TTL_NEGATIVE 2560

#define parse_abort() \
    siglongjmp(z->jbuf, 1)

#define parse_warn(_fmt, ...) \
    log_warn("djb: %s: parse error at line %u: " _fmt,z->fn,z->lcount,__VA_ARGS__);\

#define parse_error_noargs(_fmt) \
    do {\
        log_err("djb: %s: parse error at line %u: " _fmt,z->fn,z->lcount);\
        parse_abort();\
    } while(0)

#define parse_error(_fmt, ...) \
    do {\
        log_err("djb: %s: parse error at line %u: " _fmt,z->fn,z->lcount,__VA_ARGS__);\
        parse_abort();\
    } while(0)

typedef struct {
    char* ptr;
    unsigned len;
} field_t;

typedef struct {
    /* variables preserved across files */
    uint64_t mtime;
    zscan_djb_zonedata_t* zonedata;
    const char* path;
    uint8_t** texts;
    char* line;
    size_t allocated;
    int num_texts;
    int skipped;

    /* file specific data */
    int lcount;
    char* full_fn;
    const char* fn;
    FILE* file;

    sigjmp_buf jbuf;
} zscan_t;

static const uint8_t dname_root[] = {1,0};
static const uint8_t dname_ns[]   = {4,2,'n','s',255};
static const uint8_t dname_mx[]   = {4,2,'m','x',255};
static const uint8_t dname_srv[]  = {5,3,'s','r','v',255};

void zscan_djbzone_add(zscan_djb_zonedata_t** zd, zone_t *zone) {
    zscan_djb_zonedata_t* nzd = xmalloc(sizeof(zscan_djb_zonedata_t));
    nzd->zone = zone;
    nzd->marked = 0;
    nzd->next = *zd;
    *zd = nzd;
}

F_PURE
zscan_djb_zonedata_t* zscan_djbzone_get(zscan_djb_zonedata_t* zd, const uint8_t* dname, int exact) {
    zscan_djb_zonedata_t* best = NULL;

    for (; zd; zd = zd->next) {
        if (exact) {
            if (dname_cmp(zd->zone->dname, dname) == 0)
                return zd;
        } else {
            if (!dname_isinzone(zd->zone->dname, dname))
                continue;
            if (best == NULL || zd->zone->dname[0] > best->zone->dname[0]) {
                best = zd;
                if (best->zone->dname[0] == dname[0])
                    return best;
            }
        }
    }
    return best;
}

void zscan_djbzone_free(zscan_djb_zonedata_t** zd) {
    zscan_djb_zonedata_t* cur = *zd;
    zscan_djb_zonedata_t* next;

    while (cur) {
        next = cur->next;
        free(cur);
        cur = next;
    }
    *zd = NULL;
}


F_NONNULL
static uint8_t *parse_dname(zscan_t *z, uint8_t *dname, field_t *f) {
    dname_status_t status = dname_from_string(dname, f->ptr, f->len);

    switch(status) {
        case DNAME_INVALID:
            parse_error("'%.*s' is not a domain name", f->len, f->ptr);
            break;
        case DNAME_VALID:
            break;
        case DNAME_PARTIAL:
            if(dname_cat(dname, dname_root) == DNAME_INVALID)
                parse_error("'%.*s' is not a valid name", f->len, f->ptr);
            break;
    }
    return dname;
}

F_NONNULL
static uint8_t *make_dname_relative(uint8_t* dname, const uint8_t* parent_dname) {
    *dname -= *parent_dname - 1;
    dname[*dname] = 0;
    dmn_assert(dname_status(dname) == DNAME_VALID);
    return dname;
}

F_NONNULL
static uint8_t *expand_dname(zscan_t *z, uint8_t *dname, field_t *f, const uint8_t *subzone, const uint8_t *zone) {
    /* fully qualified name in the primary field? */
    if (strchr(f->ptr, '.') != NULL)
        return parse_dname(z, dname, f);

    /* construct dname of form <fieldname>.<subzone>.<zone>
     * e.g. ns1.ns.example.com */
    dname_from_string(dname, f->ptr, f->len);
    dname_cat(dname, subzone);
    switch (dname_cat(dname, zone)) {
        case DNAME_VALID:
            break;
        case DNAME_PARTIAL:
            if(dname_cat(dname, dname_root) != DNAME_INVALID)
                break;
            /* fallthrough */
        case DNAME_INVALID:
            parse_error("unable to expand '%.*s' as to valid domain name", f->len, f->ptr);
            break;
    }

    return dname;
}

F_NONNULL
static uint32_t parse_ipv4(zscan_t *z, field_t *f) {
    struct in_addr addr;

    if(inet_pton(AF_INET, f->ptr, &addr) <= 0)
        parse_error("IPv4 address '%s' invalid", f->ptr);

    return addr.s_addr;
}

F_NONNULL
static unsigned parse_ttl(zscan_t *z, field_t *f, unsigned defttl) {
    char *end;
    if (f->len == 0)
        return defttl;
    unsigned ttl = strtol(f->ptr, &end, 10);
    if (end != f->ptr + f->len)
        parse_error("Invalid TTL '%.*s'", f->len, f->ptr);
    return ttl;
}

F_NONNULL
static unsigned parse_int(zscan_t *z, field_t *f) {
    char *end;
    unsigned ttl = strtol(f->ptr, &end, 10);
    if (end != f->ptr + f->len)
        parse_error("Invalid integer value '%.*s'", f->len, f->ptr);
    return ttl;
}

F_NONNULL
static void parse_txt(field_t *f) {
    unsigned i;
    unsigned j;

    if (f->len < 2)
      return;

    j = 0;
    i = 0;
    while (i < f->len) {
        char ch = f->ptr[i++];
        if (ch == '\\') {
            if (i >= f->len) break;
            ch = f->ptr[i++];
            if ((ch >= '0') && (ch <= '7')) {
                ch -= '0';
                if ((i < f->len) && (f->ptr[i] >= '0') && (f->ptr[i] <= '7')) {
                    ch <<= 3;
                    ch += f->ptr[i++] - '0';
                    if ((i < f->len) && (f->ptr[i] >= '0') && (f->ptr[i] <= '7')) {
                        ch <<= 3;
                        ch += f->ptr[i++] - '0';
                    }
                }
            }
        }
        f->ptr[j++] = ch;
    }
    f->len = j;
    f->ptr[j] = 0;
}

static void create_zones(zscan_t *z, char record_type, field_t *field) {
    uint8_t dname[256];

    if (record_type != 'Z')
        return;

    parse_dname(z, dname, &field[0]);
    if (zscan_djbzone_get(z->zonedata, dname, 1))
        return;

    char* src = gdnsd_str_combine("djb:", z->fn, NULL);
    zscan_djbzone_add(&z->zonedata, zone_new(logf_dname(dname), src));
    dmn_fmtbuf_reset();
    free(src);
}

#define TTDCHECK(fno) if (field[fno].len) { z->skipped++; return; }
#define LOCCHECK(fno) if (field[fno].len) { z->skipped++; return; }

static void load_zones(zscan_t *z, char record_type, field_t *field) {
    uint8_t dname[256], dname2[256], email[256];
    unsigned i, ttl;

    parse_dname(z, dname, &field[0]);
    zscan_djb_zonedata_t* zd = zscan_djbzone_get(z->zonedata, dname, 0);
    if (!zd)
       return;

    //log_info("djb: processing '%s'", logf_dname(dname));

    zone_t* zone = zd->zone;
    make_dname_relative(dname, zone->dname);

    //log_info("djb: record %c name '%s' in zone '%s'", record_type, logf_dname(dname), logf_dname(zone->dname));

    switch (record_type) {
    case 'Z': /* SOA */
        TTDCHECK(9);
        LOCCHECK(10);
        zone->serial = parse_int(z, &field[3]);
        zone->mtime = z->mtime;
        if (ltree_add_rec_soa(zone, dname,
                              parse_dname(z, dname2, &field[1]),
                              parse_dname(z, email, &field[2]),
                              parse_ttl(z, &field[8], TTL_NEGATIVE),
                              zone->serial ?: z->mtime, /* serial */
                              parse_int(z, &field[4]) ?:    16384, /* refresh */
                              parse_int(z, &field[5]) ?:     2048, /* retry */
                              parse_int(z, &field[6]) ?:  1048576, /* expire */
                              parse_int(z, &field[7]) ?:     2560  /* cache */))
            parse_abort();
        break;
    case '.': /* NS + SOA (+ A) */
    case '&': /* NS (+ A) */
        TTDCHECK(4);
        LOCCHECK(5);
        expand_dname(z, dname2, &field[2], dname_ns, dname);
        ttl = parse_ttl(z, &field[3], TTL_NS);
        if (ltree_add_rec_ns(zone, dname, dname2, ttl))
            parse_abort();
        if (field[1].len) {
            zd = zscan_djbzone_get(z->zonedata, dname2, 0);
            if (zd) {
                make_dname_relative(dname2, zd->zone->dname);
                log_info("djb: NS+A name '%s' in zone '%s'", logf_dname(dname2), logf_dname(zd->zone->dname));
                if (ltree_add_rec_a(zone, dname2, parse_ipv4(z, &field[1]), ttl, 0, NULL))
                    parse_abort();
            }
        }
        break;
    case '@': /* MX (+ A) */
        TTDCHECK(5);
        LOCCHECK(6);
        expand_dname(z, dname2, &field[2], dname_mx, dname);
        ttl = parse_ttl(z, &field[4], TTL_POSITIVE);
        if (ltree_add_rec_mx(zone, dname, dname2, ttl, parse_int(z, &field[3])))
            parse_abort();
        if (field[1].len) {
            zd = zscan_djbzone_get(z->zonedata, dname2, 0);
            if (zd) {
                make_dname_relative(dname2, zd->zone->dname);
                log_info("djb: MX+A name '%s' in zone '%s'", logf_dname(dname2), logf_dname(zd->zone->dname));
                if (ltree_add_rec_a(zone, dname2, parse_ipv4(z, &field[1]), ttl, 0, NULL))
                    parse_abort();
            }
        }
        break;
    case '+': /* A */
    case '=': /* A + PTR */
        TTDCHECK(3);
        ttl = parse_ttl(z, &field[2], TTL_POSITIVE);
        if (field[4].len == 2 && memcmp(field[4].ptr, "~~", 2) == 0) {
            /* FIXME: check ooz is right */
            /* FIXME: new arg ttl_min set to half of ttl, could use explicit param in data file */
            if (ltree_add_rec_dynaddr(zone, dname, field[1].ptr, ttl, ttl >> 1, 0, 0, 0))
                parse_abort();
        } else {
            LOCCHECK(4);
            if (ltree_add_rec_a(zone, dname, parse_ipv4(z, &field[1]), ttl, 0, NULL))
                parse_abort();
#if 0
            /* FIXME: autogen PTR record */
            if (line[0] == '=') {
                ltree_add_rec_ptr();
            }
#endif
        }
        break;
    case 'C': /* CNAME */
        TTDCHECK(3);
        ttl = parse_ttl(z, &field[2], TTL_POSITIVE);
        if (field[4].len == 2 && memcmp(field[4].ptr, "~~", 2) == 0) {
            /* FIXME: ttl_min as above */
            if (ltree_add_rec_dync(zone, dname, field[1].ptr, dname_root, ttl, ttl >> 1, 0, 0))
                parse_abort();
        } else {
            LOCCHECK(4);
            if (ltree_add_rec_cname(zone, dname, parse_dname(z, dname2, &field[1]), ttl))
                parse_abort();
        }
        break;
    case '\'': /* TXT */
        TTDCHECK(3);
        LOCCHECK(4);

        parse_txt(&field[1]);

        unsigned bytes = field[1].len;
        const char* src = field[1].ptr;
        unsigned chunks = (bytes + 254) / 255;

        if(bytes > 255 && gconfig.disable_text_autosplit)
            parse_error_noargs("Text chunk too long (>255 unescaped)");
        if(bytes > 65500)
            parse_error_noargs("Text chunk too long (>65500 unescaped)");

        z->texts = xrealloc(z->texts, sizeof(uint8_t *) * (chunks + 1));
        for (i = 0; i < chunks; i++) {
            int s = (bytes > 255 ? 255 : bytes);
            z->texts[i] = xmalloc(s + 1);
            z->texts[i][0] = s;
            memcpy(&z->texts[i][1], src, s);
            bytes -= s;
            src += s;
        }
        z->texts[i] = NULL;
        if (ltree_add_rec_txt(zone, dname, chunks, z->texts, parse_ttl(z,&field[2], TTL_POSITIVE))) {
            for (i = 0; i < chunks; i++)
                free(z->texts[i]);
            parse_abort();
        }
        break;
    case 'S': /* SRV (+ A) */
        TTDCHECK(7);
        LOCCHECK(8);
        expand_dname(z, dname2, &field[2], dname_srv, dname);
        ttl = parse_ttl(z, &field[6], TTL_POSITIVE);
        if (ltree_add_rec_srv(zone, dname, dname2, ttl, parse_int(z, &field[4]), parse_int(z, &field[5]), parse_int(z, &field[3])))
            parse_abort();
        if (field[1].len) {
            zd = zscan_djbzone_get(z->zonedata, dname2, 0);
            if (zd) {
                make_dname_relative(dname2, zd->zone->dname);
                log_info("djb: SRV+A name '%s' in zone '%s'", logf_dname(dname2), logf_dname(zd->zone->dname));
                if (ltree_add_rec_a(zone, dname2, parse_ipv4(z, &field[1]), ttl, 0, NULL))
                    parse_abort();
            }
        }
        break;
    case 'N': /* NAPTR */
        TTDCHECK(8);
        LOCCHECK(9);
        parse_txt(&field[3]);
        parse_txt(&field[4]);
        parse_txt(&field[5]);
        if (field[3].len > 255 || field[4].len > 255 || field[5].len > 255)
            parse_error_noargs("NAPTR label cannot exceed 255 chars");

        z->texts = xrealloc(z->texts, 4 * sizeof(uint8_t *));
        for (i = 0; i < 3; i++) {
            z->texts[i] = xmalloc(field[3+i].len + 1);
            z->texts[i][0] = field[3+i].len;
            memcpy(&z->texts[i][1], field[3+i].ptr, field[3+i].len);
        }
        z->texts[i] = NULL;
        if (ltree_add_rec_naptr(zone, dname, parse_dname(z, dname2, &field[6]), parse_ttl(z, &field[7], TTL_POSITIVE), parse_int(z, &field[1]), parse_int(z, &field[2]), 3, z->texts)) {
            for (i = 0; i < 3; i++)
                free(z->texts[i]);
            parse_abort();
        }
        break;
#if 0
    case '3': /* AAAA */
    case '6': /* AAAA + PTR */
    case '^': /* PTR */
    case ':': /* raw */
#endif
    default:
        parse_warn("Unsupported djb record type '%c'", record_type);
    }
}

typedef void (*djb_recordcb_t)(zscan_t *z, char record_type, field_t *fields);

static void zscan_foreach_file_record(zscan_t *z, djb_recordcb_t cb) {
    field_t field[15];
    ssize_t len;
    size_t i;
    char *c;

    z->lcount = 0;
    log_debug("Scanning djbzone file '%s'", z->fn);

    z->file = fopen(z->full_fn, "rt");
    if(z->file == NULL)
        parse_error("Cannot open zone file '%s' for reading: %s", z->full_fn, dmn_logf_errno());

    while ((len = getline(&z->line, &z->allocated, z->file)) != -1) {
        z->lcount++;

        /* Skip empty lines and comments */
        if (len == 0 || z->line[0] == '#' || z->line[0] == '-')
            continue;
        if (z->line[len-1] == '\n') {
            z->line[len-1] = 0;
            len--;
        }
        /* Skip empty lines and location records */
        if (len == 0 || z->line[0] == '%')
            continue;

        for (i = 0, c = z->line + 1; i < sizeof(field)/sizeof(field[0]); i++) {
            field[i].ptr = c ?: (char*) "";
            field[i].len = 0;
            if (c) {
                char *n = strchr(c, ':');
                if (n) {
                    field[i].len = n - c;
                    *n = 0;
                    c = n + 1;
                } else {
                    field[i].len = strlen(c);
                    c = NULL;
                }
            }
        }

        cb(z, z->line[0], field);
    }
}

static bool zscan_foreach_record(zscan_t *z, djb_recordcb_t cb) {
    DIR *dir;
    bool failed = false;

    dir = opendir(z->path);
    if (dir == NULL) {
        if(errno == ENOENT)
            log_debug("djb: directory '%s' does not exist", z->path);
        else
            log_err("djb: cannot open directory '%s': %s", z->path, dmn_logf_errno());
        return true;
    }

    const size_t bufsz = gdnsd_dirent_bufsize(dir, z->path);
    struct dirent* buf = xmalloc(bufsz);

    while(1) {
        struct dirent* e = NULL;
        if(unlikely(readdir_r(dir, buf, &e)))
            log_fatal("djb: readdir_r(%s) failed: %s", z->path, dmn_logf_errno());
        if(!e)
            break;
        if(e->d_name[0] == '.')
            continue;

        struct stat st;
        z->full_fn = gdnsd_str_combine(z->path, e->d_name, &z->fn);
        if (stat(z->full_fn, &st)) {
            log_err("djb: cannot stat file '%s': %s", z->full_fn, dmn_logf_errno());
            parse_abort();
        }
        if((st.st_mode & S_IFMT) != S_IFREG) {
            free(z->full_fn);
            z->fn = z->full_fn = NULL;
            continue;
        }
        uint64_t emtime = get_extended_mtime(&st);
        if (emtime > z->mtime)
            z->mtime = emtime;
        failed = true;
        if(!sigsetjmp(z->jbuf, 0)) {
            zscan_foreach_file_record(z, cb);
            failed = false;
        }
        if (z->file) {
            fclose(z->file);
            z->file = NULL;
        }
        free(z->full_fn);
        z->fn = z->full_fn = NULL;

        if (failed)
            break;
    }

    free(buf);
    closedir(dir);

    return failed;
}

F_WUNUSED F_NONNULL
bool zscan_djb(const char* djb_path, zscan_djb_zonedata_t** zonedata)
{
    dmn_assert(djb_path);

    zscan_t _z, *z = &_z;
    memset(z, 0, sizeof(*z));
    z->path = djb_path;

    if (zscan_foreach_record(z, create_zones) || zscan_foreach_record(z, load_zones))
        goto error;

    for (zscan_djb_zonedata_t *zd = z->zonedata; zd; zd = zd->next)
        if (zone_finalize(zd->zone))
            goto error;

    if (z->skipped)
        log_warn("djb: skipped %d records with TTD or location", z->skipped);

    *zonedata = z->zonedata;
    free(z->line);
    return false;

error:
    zscan_djbzone_free(&z->zonedata);
    free(z->line);
    return true;
}
