/* Copyright © 2012 Brandon L Black <blblack@gmail.com> and Jay Reitz <jreitz@gmail.com>
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
#include "zscan_rfc1035.h"

#include "conf.h"
#include "ltree.h"
#include "ltarena.h"

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/misc.h>
#include <gdnsd/file.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <setjmp.h>
#include <errno.h>

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#define parse_error(_fmt, ...) \
    do {\
        log_err("rfc1035: Zone %s: Zonefile parse error at file %s line %u: " _fmt, logf_dname(z->zone->dname), z->curfn, z->lcount, __VA_ARGS__);\
        siglongjmp(z->jbuf, 1);\
    } while (0)

#define parse_error_noargs(_fmt) \
    do {\
        log_err("rfc1035: Zone %s: Zonefile parse error at file %s line %u: " _fmt, logf_dname(z->zone->dname), z->curfn, z->lcount);\
        siglongjmp(z->jbuf, 1);\
    } while (0)

typedef struct {
    uint8_t  ipv6[16];
    uint32_t ipv4;
    bool     zn_err_detect;
    bool     lhs_is_ooz;
    unsigned lcount;
    unsigned text_len;
    unsigned def_ttl;
    unsigned uval;
    unsigned ttl;
    unsigned ttl_min;
    unsigned uv_1;
    unsigned uv_2;
    unsigned uv_3;
    unsigned uv_4;
    unsigned uv_5;
    unsigned rfc3597_data_len;
    unsigned rfc3597_data_written;
    uint8_t* rfc3597_data;
    zone_t* zone;
    const char* tstart;
    const char* curfn;
    char* include_filename;
    uint8_t  origin[256];
    uint8_t  file_origin[256];
    uint8_t  lhs_dname[256];
    uint8_t  rhs_dname[256];
    union {
        uint8_t eml_dname[256];
        char    rhs_dyn[256];
        char    caa_prop[256];
    };
    uint8_t* text;
    sigjmp_buf jbuf;
} zscan_t;

F_NONNULL
static void scanner(zscan_t* z, char* buf, const size_t bufsize);

/******** IP Addresses ********/

F_NONNULL
static void set_ipv4(zscan_t* z, const char* end)
{
    char txt[16];
    unsigned len = end - z->tstart;
    memcpy(txt, z->tstart, len);
    txt[len] = 0;
    z->tstart = NULL;
    struct in_addr addr;
    int status = inet_pton(AF_INET, txt, &addr);
    if (status > 0)
        z->ipv4 = addr.s_addr;
    else
        parse_error("IPv4 address '%s' invalid", txt);
}

F_NONNULL
static void set_ipv6(zscan_t* z, const char* end)
{
    char txt[INET6_ADDRSTRLEN + 1];
    unsigned len = end - z->tstart;
    memcpy(txt, z->tstart, len);
    txt[len] = 0;
    z->tstart = NULL;
    struct in6_addr v6a;
    int status = inet_pton(AF_INET6, txt, &v6a);
    if (status > 0)
        memcpy(z->ipv6, v6a.s6_addr, 16);
    else
        parse_error("IPv6 address '%s' invalid", txt);
}

F_NONNULL
static void set_uval(zscan_t* z)
{
    errno = 0;
    z->uval = strtoul(z->tstart, NULL, 10);
    z->tstart = NULL;
    if (errno)
        parse_error("Integer conversion error: %s", logf_errno());
}

F_NONNULL
static void validate_origin_in_zone(zscan_t* z, const uint8_t* origin)
{
    gdnsd_assert(z->zone->dname);
    if (!dname_isinzone(z->zone->dname, origin))
        parse_error("Origin '%s' is not within this zonefile's zone (%s)", logf_dname(origin), logf_dname(z->zone->dname));
}

F_NONNULL
static void validate_lhs_not_ooz(zscan_t* z)
{
    if (z->lhs_is_ooz)
        parse_error("Domainname '%s' is not within this zonefile's zone (%s)", logf_dname(z->lhs_dname), logf_dname(z->zone->dname));
}

F_NONNULL F_PURE
static unsigned dn_find_final_label_offset(const uint8_t* dname)
{
    gdnsd_assert(dname_status(dname) == DNAME_PARTIAL);

    // Since we assert DNAME_PARTIAL, we just have to search forward until the
    // next potential label len is the partial terminator 0xff.
    const uint8_t* dnptr = dname + 1;
    unsigned next_llen_pos = *dnptr + 1U;
    while (dnptr[next_llen_pos] != 0xff) {
        dnptr += next_llen_pos;
        next_llen_pos = *dnptr + 1U;
    }

    return (unsigned)(dnptr - dname);
}

// This converts an unqualified name to a qualified one.  Normal behavior is to
// append the current $ORIGIN, but we also plug in support for '@' here (as a
// lone character meaning $ORIGIN) and also these extensions:
//--
// * If the final label is "@Z", we replace that with the original zone-level
// origin (the name of the actual zone) rather than the current $ORIGIN
// * If the final label is "@F", we replace that with the original file-level
// origin (the origin when a zonefile or includefile was first loaded, before
// any $ORIGIN statement within it) rather than the current $ORIGIN
//--
// @Z and @F are equivalent when not processing an included file.
// @Z and @F can also, like @, be the first (only) label; there doesn't have to
// be any prefix label before them.

F_NONNULL
static dname_status_t dn_qualify(uint8_t* dname, const uint8_t* origin, uint8_t* const file_origin, const uint8_t* zone_origin)
{
    gdnsd_assert(dname_status(dname) == DNAME_PARTIAL);

    // Lone "@" case:
    if (dname[0] == 3U && dname[2] == '@') {
        gdnsd_assert(dname[1] == 1U && dname[3] == 0xff);
        dname_copy(dname, origin);
        return DNAME_VALID;
    }

    // @Z/@F handling (note @X for any other char is illegal for now):
    const unsigned final_label_offset = dn_find_final_label_offset(dname);
    const unsigned final_label_len = dname[final_label_offset];
    gdnsd_assert(final_label_len != 0);

    if (final_label_len == 2U && dname[final_label_offset + 1] == '@') {
        const uint8_t which = dname[final_label_offset + 2];
        // adjust dname to strip the final @X label off
        dname[final_label_offset] = 0xff;
        *dname -= 3U;
        // note lowercase z/f here, because earlier dname processing
        // normalizes all alpha chars to lowercase
        if (which == 'z')
            return dname_cat(dname, zone_origin);
        else if (which == 'f')
            return dname_cat(dname, file_origin);
        else
            return DNAME_INVALID;
    }

    // default qualification with no @ involvement
    return dname_cat(dname, origin);
}

F_NONNULL
static void dname_set(zscan_t* z, uint8_t* dname, unsigned len, bool lhs)
{
    gdnsd_assert(z->zone->dname);
    dname_status_t catstat;
    dname_status_t status;

    if (len) {
        status = dname_from_string(dname, z->tstart, len);
    } else {
        gdnsd_assert(lhs);
        dname_copy(dname, z->origin);
        status = DNAME_VALID;
    }

    switch (status) {
    case DNAME_INVALID:
        parse_error_noargs("unparseable domainname");
        break;
    case DNAME_VALID:
        if (lhs) {
            const bool inzone = dname_isinzone(z->zone->dname, dname);
            z->lhs_is_ooz = !inzone;
            // in-zone LHS dnames are made relative to zroot
            if (inzone)
                gdnsd_dname_drop_zone(dname, z->zone->dname);
        }
        break;
    case DNAME_PARTIAL:
        // even though in the lhs case we commonly trim
        //   back most or all of z->origin from dname, we
        //   still have to construct it just for validity checks
        catstat = dn_qualify(dname, z->origin, z->file_origin, z->zone->dname);
        if (catstat == DNAME_INVALID)
            parse_error_noargs("illegal domainname");
        gdnsd_assert(catstat == DNAME_VALID);
        if (lhs) {
            z->lhs_is_ooz = false;
            gdnsd_dname_drop_zone(dname, z->zone->dname);
        }
        break;
    default:
        gdnsd_assert(0);
    }
}

// This is broken out into a separate function (called via
//   function pointer to eliminate the possibility of
//   inlining on non-gcc compilers, I hope) to avoid issues with
//   setjmp and all of the local auto variables in zscan_rfc1035() below.
typedef bool (*sij_func_t)(zscan_t*, char*, const unsigned);
F_NONNULL F_NOINLINE
static bool _scan_isolate_jmp(zscan_t* z, char* buf, const unsigned bufsize)
{
    if (!sigsetjmp(z->jbuf, 0)) {
        scanner(z, buf, bufsize);
        return false;
    }
    return true;
}

F_NONNULL
static bool zscan_do(zone_t* zone, const uint8_t* origin, const char* fn, const unsigned def_ttl_arg)
{
    log_debug("rfc1035: Scanning file '%s' for zone '%s'", fn, logf_dname(zone->dname));

    bool failed = false;

    gdnsd_fmap_t* fmap = gdnsd_fmap_new(fn, true, true);
    if (!fmap) {
        failed = true;
        return failed;
    }

    const size_t bufsize = gdnsd_fmap_get_len(fmap);
    char* buf = gdnsd_fmap_get_buf(fmap);

    zscan_t* z = xcalloc(sizeof(*z));
    z->lcount = 1;
    z->def_ttl = def_ttl_arg;
    z->zone = zone;
    z->curfn = fn;
    dname_copy(z->origin, origin);
    dname_copy(z->file_origin, origin);
    z->lhs_dname[0] = 1; // set lhs to relative origin initially

    sij_func_t sij = &_scan_isolate_jmp;
    if (sij(z, buf, bufsize))
        failed = true;

    if (gdnsd_fmap_delete(fmap))
        failed = true;

    if (z->text)
        free(z->text);
    if (z->rfc3597_data)
        free(z->rfc3597_data);
    if (z->include_filename)
        free(z->include_filename);
    free(z);

    return failed;
}

/********** TXT ******************/

F_NONNULL
static void text_start(zscan_t* z)
{
    gdnsd_assert(z->text == NULL);
    gdnsd_assert(z->text_len == 0);
}

F_NONNULL
static void text_add_tok(zscan_t* z, const unsigned len, const bool big_ok)
{
    char* text_temp = xmalloc(len ? len : 1);
    unsigned newlen = len;
    if (len) {
        newlen = dns_unescape(text_temp, z->tstart, len);
        if (!newlen)
            parse_error_noargs("Text chunk has bad escape sequence");
        gdnsd_assert(newlen <= len);
    }

    if (newlen > 255U) {
        if (!big_ok || gcfg->disable_text_autosplit) {
            free(text_temp);
            parse_error_noargs("Text chunk too long (>255 unescaped)");
        }
        if (newlen > 16000U) {
            free(text_temp);
            parse_error_noargs("Text chunk too long (>16000 unescaped)");
        }
        const unsigned remainder = newlen % 255;
        const unsigned num_whole_chunks = (newlen - remainder) / 255;
        unsigned new_alloc = newlen + num_whole_chunks + (remainder ? 1 : 0);
        if (new_alloc + z->text_len > 16000U)
            parse_error_noargs("Text record too long (>16000 in rdata form)");

        z->text = xrealloc(z->text, z->text_len + new_alloc);
        unsigned write_offset = z->text_len;
        z->text_len += new_alloc;
        const char* readptr = text_temp;
        for (unsigned i = 0; i < num_whole_chunks; i++) {
            z->text[write_offset++] = 255;
            memcpy(&z->text[write_offset], readptr, 255);
            write_offset += 255;
            readptr += 255;
        }
        if (remainder) {
            z->text[write_offset++] = remainder;
            memcpy(&z->text[write_offset], readptr, remainder);
        }
        gdnsd_assert(write_offset + remainder == z->text_len);
    } else { // 0-255 bytes, one chunk
        const unsigned new_alloc = newlen + 1;
        if (new_alloc + z->text_len > 16000U) {
            free(text_temp);
            parse_error_noargs("Text record too long (>16000 in rdata form)");
        }
        z->text = xrealloc(z->text, z->text_len + new_alloc);
        unsigned write_offset = z->text_len;
        z->text_len += new_alloc;
        z->text[write_offset++] = newlen;
        memcpy(&z->text[write_offset], text_temp, newlen);
    }

    free(text_temp);
    z->tstart = NULL;
}

F_NONNULL
static void text_add_tok_huge(zscan_t* z, const unsigned len)
{
    char* storage = xmalloc(len ? len : 1);
    unsigned newlen = len;
    if (len) {
        newlen = dns_unescape(storage, z->tstart, len);
        if (!newlen)
            parse_error_noargs("Text chunk has bad escape sequence");
        gdnsd_assert(newlen <= len);
    }

    if (newlen > 16000U) {
        free(storage);
        parse_error_noargs("Text chunk too long (>16000 unescaped)");
    }

    // _huge is only used alone, not in a set
    gdnsd_assert(!z->text_len);
    gdnsd_assert(!z->text);

    z->text = (uint8_t*)storage;
    z->text_len = newlen;
    z->tstart = NULL;
}

F_NONNULL
static void set_filename(zscan_t* z, const unsigned len)
{
    char* fn = xmalloc(len + 1);
    const unsigned newlen = dns_unescape(fn, z->tstart, len);
    if (!newlen)
        parse_error_noargs("Filename has bad escape sequence");
    gdnsd_assert(newlen <= len);
    z->include_filename = fn = xrealloc(fn, newlen + 1);
    fn[newlen] = 0;
    z->tstart = NULL;
}

F_NONNULL
static char* _make_zfn(const char* curfn, const char* include_fn)
{
    if (include_fn[0] == '/')
        return xstrdup(include_fn);

    const char* slashpos = strrchr(curfn, '/');
    const unsigned cur_copy = (slashpos - curfn) + 1;
    const unsigned include_len = strlen(include_fn);
    char* rv = xmalloc(cur_copy + include_len + 1);
    memcpy(rv, curfn, cur_copy);
    memcpy(rv + cur_copy, include_fn, include_len);
    rv[cur_copy + include_len] = 0;

    return rv;
}

F_NONNULL
static void process_include(zscan_t* z)
{
    gdnsd_assert(z->include_filename);

    validate_origin_in_zone(z, z->rhs_dname);
    char* zfn = _make_zfn(z->curfn, z->include_filename);
    free(z->include_filename);
    z->include_filename = NULL;
    bool subfailed = zscan_do(z->zone, z->rhs_dname, zfn, z->def_ttl);
    free(zfn);
    if (subfailed)
        siglongjmp(z->jbuf, 1);
}

// Input must have two bytes of text constrained to [0-9A-Fa-f]
F_NONNULL
static unsigned hexbyte(const char* intxt)
{
    gdnsd_assert(
        (intxt[0] >= '0' && intxt[0] <= '9')
        || (intxt[0] >= 'A' && intxt[0] <= 'F')
        || (intxt[0] >= 'a' && intxt[0] <= 'f')
    );
    gdnsd_assert(
        (intxt[1] >= '0' && intxt[1] <= '9')
        || (intxt[1] >= 'A' && intxt[1] <= 'F')
        || (intxt[1] >= 'a' && intxt[1] <= 'f')
    );

    int out;

    if (intxt[0] <= '9')
        out = (intxt[0] - '0') << 4;
    else
        out = ((intxt[0] | 0x20) - ('a' - 10)) << 4;

    if (intxt[1] <= '9')
        out |= (intxt[1] - '0');
    else
        out |= ((intxt[1] | 0x20) - ('a' - 10));

    gdnsd_assert(out >= 0 && out < 256);
    return (unsigned)out;
}

F_NONNULL
static void mult_uval(zscan_t* z, int fc)
{
    fc |= 0x20;
    switch (fc) {
    case 'm':
        z->uval *= 60;
        break;
    case 'h':
        z->uval *= 3600;
        break;
    case 'd':
        z->uval *= 86400;
        break;
    case 'w':
        z->uval *= 604800;
        break;
    default:
        gdnsd_assert(0);
    }
}

F_NONNULL
static void set_dyna(zscan_t* z, const char* fpc)
{
    unsigned dlen = fpc - z->tstart;
    if (dlen > 255)
        parse_error_noargs("DYNA/DYNC plugin!resource string cannot exceed 255 chars");
    memcpy(z->rhs_dyn, z->tstart, dlen);
    z->rhs_dyn[dlen] = 0;
    z->tstart = NULL;
}

F_NONNULL
static void set_caa_prop(zscan_t* z, const char* fpc)
{
    unsigned dlen = fpc - z->tstart;
    if (dlen > 255)
        parse_error_noargs("CAA property string cannot exceed 255 chars");
    memcpy(z->caa_prop, z->tstart, dlen);
    z->caa_prop[dlen] = 0;
    z->tstart = NULL;
}

F_NONNULL
static void rec_soa(zscan_t* z)
{
    validate_lhs_not_ooz(z);
    if (z->lhs_dname[0] != 1)
        parse_error_noargs("SOA record can only be defined for the root of the zone");
    if (ltree_add_rec_soa(z->zone, z->lhs_dname, z->rhs_dname, z->eml_dname, z->ttl, z->uv_1, z->uv_2, z->uv_3, z->uv_4, z->uv_5))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void rec_a(zscan_t* z)
{
    if (ltree_add_rec_a(z->zone, z->lhs_dname, z->ipv4, z->ttl, z->lhs_is_ooz))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void rec_aaaa(zscan_t* z)
{
    if (ltree_add_rec_aaaa(z->zone, z->lhs_dname, z->ipv6, z->ttl, z->lhs_is_ooz))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void rec_ns(zscan_t* z)
{
    validate_lhs_not_ooz(z);
    if (ltree_add_rec_ns(z->zone, z->lhs_dname, z->rhs_dname, z->ttl))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void rec_cname(zscan_t* z)
{
    validate_lhs_not_ooz(z);
    if (ltree_add_rec_cname(z->zone, z->lhs_dname, z->rhs_dname, z->ttl))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void rec_ptr(zscan_t* z)
{
    validate_lhs_not_ooz(z);
    if (ltree_add_rec_ptr(z->zone, z->lhs_dname, z->rhs_dname, z->ttl))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void rec_mx(zscan_t* z)
{
    validate_lhs_not_ooz(z);
    if (ltree_add_rec_mx(z->zone, z->lhs_dname, z->rhs_dname, z->ttl, z->uval))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void rec_srv(zscan_t* z)
{
    validate_lhs_not_ooz(z);
    if (ltree_add_rec_srv(z->zone, z->lhs_dname, z->rhs_dname, z->ttl, z->uv_1, z->uv_2, z->uv_3))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void text_cleanup(zscan_t* z)
{
    if (z->text)
        free(z->text);
    z->text = NULL;
    z->text_len = 0;
}

F_NONNULL
static void rec_naptr(zscan_t* z)
{
    validate_lhs_not_ooz(z);
    if (ltree_add_rec_naptr(z->zone, z->lhs_dname, z->rhs_dname, z->ttl, z->uv_1, z->uv_2, z->text_len, z->text))
        siglongjmp(z->jbuf, 1);
    z->text = NULL; // storage handed off to ltree
    text_cleanup(z);
}

F_NONNULL
static void rec_txt(zscan_t* z)
{
    validate_lhs_not_ooz(z);
    if (ltree_add_rec_txt(z->zone, z->lhs_dname, z->text_len, z->text, z->ttl))
        siglongjmp(z->jbuf, 1);
    z->text = NULL; // storage handed off to ltree
    text_cleanup(z);
}

F_NONNULL
static void rec_dyna(zscan_t* z)
{
    validate_lhs_not_ooz(z);
    if (ltree_add_rec_dynaddr(z->zone, z->lhs_dname, z->rhs_dyn, z->ttl, z->ttl_min))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void rec_dync(zscan_t* z)
{
    validate_lhs_not_ooz(z);
    if (ltree_add_rec_dync(z->zone, z->lhs_dname, z->rhs_dyn, z->ttl, z->ttl_min))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void rec_rfc3597(zscan_t* z)
{
    if (z->rfc3597_data_written < z->rfc3597_data_len)
        parse_error("RFC3597 generic RR claimed rdata length of %u, but only %u bytes of data present", z->rfc3597_data_len, z->rfc3597_data_written);
    validate_lhs_not_ooz(z);
    if (ltree_add_rec_rfc3597(z->zone, z->lhs_dname, z->uv_1, z->ttl, z->rfc3597_data_len, z->rfc3597_data))
        siglongjmp(z->jbuf, 1);
    z->rfc3597_data = NULL;
}

F_NONNULL
static void rec_caa(zscan_t* z)
{
    if (z->uval > 255)
        parse_error("CAA flags byte value %u is >255", z->uval);

    validate_lhs_not_ooz(z);

    const unsigned prop_len = strlen(z->caa_prop);
    gdnsd_assert(prop_len < 256); // parser-enforced
    const unsigned value_len = z->text_len;
    const unsigned total_len = 2 + prop_len + value_len;

    uint8_t* caa_rdata = xmalloc(total_len);
    uint8_t* caa_write = caa_rdata;
    *caa_write++ = z->uval;
    *caa_write++ = prop_len;
    memcpy(caa_write, z->caa_prop, prop_len);
    caa_write += prop_len;
    memcpy(caa_write, z->text, value_len);

    if (ltree_add_rec_rfc3597(z->zone, z->lhs_dname, 257, z->ttl, total_len, caa_rdata))
        siglongjmp(z->jbuf, 1);
    text_cleanup(z);
}

F_NONNULL
static void rfc3597_data_setup(zscan_t* z)
{
    z->rfc3597_data_len = z->uval;
    z->rfc3597_data_written = 0;
    z->rfc3597_data = xmalloc(z->uval);
}

F_NONNULL
static void rfc3597_octet(zscan_t* z)
{
    if (z->rfc3597_data_written == z->rfc3597_data_len)
        parse_error_noargs("RFC3597 generic RR: more rdata is present than the indicated length");
    z->rfc3597_data[z->rfc3597_data_written++] = hexbyte(z->tstart);
}

// The external entrypoint to the parser
bool zscan_rfc1035(zone_t* zone, const char* fn)
{
    gdnsd_assert(zone->dname);
    log_debug("rfc1035: Scanning zonefile '%s'", logf_dname(zone->dname));
    return zscan_do(zone, zone->dname, fn, gcfg->zones_default_ttl);
}

// This pre-processor does two important things that vastly simplify the real
// ragel parser:
// 1) Gets rid of all comments, replacing their characters with spaces so that
//    they're just seen as excessive whitespace.  Technically we only needed
//    to strip comments for the () case below, which is the complicated one
//    for ragel, but since we're doing it anyways it seemed simpler to do
//    universally and take comment-handling out of ragel as well.
// 2) Gets rid of all awful rfc1035 () line continuation, replacing the
//    parentheses themselves with spaces, and replacing any embedded newlines
//    with the formfeed character \f (which the ragel parser treats as
//    whitespace, but also knows to increment linecount on these so that error
//    reporting still shows the correct line number).

#define preproc_err(_msg) \
    do {\
        log_err("rfc1035: Zone %s: Zonefile preprocessing error at file %s line %lu: " _msg, logf_dname(z->zone->dname), z->curfn, line_num);\
        siglongjmp(z->jbuf, 1);\
    } while (0)

F_NONNULL
static void preprocess_buf(zscan_t* z, char* buf, const size_t buflen)
{
    // This is validated with a user-facing error before calling this function!
    gdnsd_assert(buf[buflen - 1] == '\n');

    bool in_quotes = false;
    bool in_parens = false;
    size_t line_num = 1;
    for (size_t i = 0; i < buflen; i++) {
        switch (buf[i]) {
        case '\n':
            line_num++;
            // In parens, replace \n with \f.  The ragel parser treats \f as
            // whitespace but knows to increment the line count so that error
            // reports are sane, while true unescaped \n terminates records.
            if (in_parens && !in_quotes)
                buf[i] = '\f';
            break;
        case ';':
            if (!in_quotes) {
                // Note we don't check i < buflen while advancing here, because
                // there's a check that the final character of the buffer must
                // be '\n' before the preprocessor is even invoked, which is
                // re-asserted at the top of this function.
                do {
                    buf[i++] = ' ';
                } while (buf[i] != '\n');
                line_num++;
                if (in_parens)
                    buf[i] = '\f';
            }
            break;
        case '"':
            in_quotes = !in_quotes;
            break;
        case '(':
            if (!in_quotes) {
                if (in_parens)
                    preproc_err("Parentheses double-opened");
                in_parens = true;
                buf[i] = ' ';
            }
            break;
        case ')':
            if (!in_quotes) {
                if (!in_parens)
                    preproc_err("Parentheses double-closed");
                in_parens = false;
                buf[i] = ' ';
            }
            break;
        case '\\':
            // Skip one escaped char.  Note 3-digit escapes exist as well, but
            // we're only concerned here with escaping of metachars, so it
            // turns out we don't have to track for the 3-digit escapes here.
            // We do have to keep the line count accurate in the case of an
            // escaped newline, though.
            if (buf[++i] == '\n')
                line_num++;
            break;
        case '\f':
            // Because \f is a special metachar for our ()-handling
            if (!in_quotes)
                preproc_err("Literal formfeed character not allowed in unquoted text: please escape it!");
            break;
        default:
            break;
        }
    }

    if (in_quotes)
        preproc_err("Unterminated open double-quote at EOF");
    if (in_parens)
        preproc_err("Unterminated open parentheses at EOF");
}

// *INDENT-OFF*
// start-sonar-exclude
%%{
    machine zone;

    action token_start { z->tstart = fpc; }

    # special case for LHS: dname_set w/ len of zero -> use origin and trim zone root
    action set_lhs_dname { dname_set(z, z->lhs_dname, fpc - z->tstart, true); }
    action set_lhs_qword { z->tstart++; dname_set(z, z->lhs_dname, fpc - z->tstart - 1, true); }
    action set_rhs_dname { dname_set(z, z->rhs_dname, fpc - z->tstart, false); }
    action set_rhs_qword { z->tstart++; dname_set(z, z->rhs_dname, fpc - z->tstart - 1, false); }
    action set_eml_dname { dname_set(z, z->eml_dname, fpc - z->tstart, false); }
    action set_eml_qword { z->tstart++; dname_set(z, z->eml_dname, fpc - z->tstart - 1, false); }
    # re-sets default for $INCLUDE without explicit origin
    action reset_rhs_origin { dname_copy(z->rhs_dname, z->origin); }

    action reset_origin {
        validate_origin_in_zone(z, z->rhs_dname);
        dname_copy(z->origin, z->rhs_dname);
    }

    action set_filename { set_filename(z, fpc - z->tstart); }
    action set_filename_q { z->tstart++; set_filename(z, fpc - z->tstart - 1); }
    action process_include { process_include(z); }

    action start_txt { text_start(z); }
    action push_txt_rdata { text_add_tok(z, fpc - z->tstart, true); }
    action push_txt_rdata_q { z->tstart++; text_add_tok(z, fpc - z->tstart - 1, true); }
    action push_txt_rdata_255 { text_add_tok(z, fpc - z->tstart, false); }
    action push_txt_rdata_255_q { z->tstart++; text_add_tok(z, fpc - z->tstart - 1, false); }
    action push_txt_rdata_huge { text_add_tok_huge(z, fpc - z->tstart); }
    action push_txt_rdata_huge_q { z->tstart++; text_add_tok_huge(z, fpc - z->tstart - 1); }

    action set_ipv4 { set_ipv4(z, fpc); }
    action set_ipv6 { set_ipv6(z, fpc); }
    action set_uval { set_uval(z); }
    action mult_uval { mult_uval(z, fc); }

    action set_ttl     { z->ttl  = z->uval; }
    action set_ttl_dyn { z->ttl  = z->uv_1; z->ttl_min = z->uv_2 ? z->uv_2 : z->uv_1 >> 1; }
    action set_def_ttl { z->def_ttl = z->uval; }
    action use_def_ttl { z->ttl  = z->def_ttl; }
    action use_def_ttl_dyn { z->ttl  = z->def_ttl; z->ttl_min = z->def_ttl >> 1; z->uv_2 = 0; }
    action set_uv_1    { z->uv_1 = z->uval; }
    action set_uv_2    { z->uv_2 = z->uval; }
    action set_uv_3    { z->uv_3 = z->uval; }
    action set_uv_4    { z->uv_4 = z->uval; }
    action set_uv_5    { z->uv_5 = z->uval; }

    action set_dyna { set_dyna(z, fpc); }
    action set_caa_prop { set_caa_prop(z, fpc); }

    action rec_soa { rec_soa(z); }
    action rec_a { rec_a(z); }
    action rec_aaaa { rec_aaaa(z); }
    action rec_ns { rec_ns(z); }
    action rec_cname { rec_cname(z); }
    action rec_ptr { rec_ptr(z); }
    action rec_mx { rec_mx(z); }
    action rec_srv { rec_srv(z); }
    action rec_naptr { rec_naptr(z); }
    action rec_txt { rec_txt(z); }
    action rec_dyna { rec_dyna(z); }
    action rec_dync { rec_dync(z); }
    action rec_rfc3597 { rec_rfc3597(z); }
    action rec_caa { rec_caa(z); }

    action rfc3597_data_setup { rfc3597_data_setup(z); }
    action rfc3597_octet { rfc3597_octet(z); }

    # newlines, count them
    nl  = '\n' %{ z->lcount++; };

    # Whitespace: note we use the special metachar \f as a linecount-bumping
    # whitespace, to coordinate with the preprocessor's removal of true
    # newlines within parentheses.
    ws = ( [ \t] | ('\f' %{ z->lcount++; } ))+;

    # Escape sequences in general for any character-string
    #  (domainname or TXT record rdata, etc)
    escapes    = '\\' ( [^0-9\n] | [0-9]{3} | nl);

    # Quoted character string
    qword     = '"' ([^"\n\\]|escapes|nl)* '"';

    # The base set of literal characters allowed in unquoted character
    #  strings (again, labels or txt rdata chunks)
    lit_chr   = [^; \t\f"\n\\)(];

    # plugin / resource names for DYNA
    plugres   = ((lit_chr - [!]) | escapes)+;

    # unquoted TXT case
    tword     = (lit_chr | escapes)+ $1 %0;

    # unquoted dname case, disallow unescaped [$] at the front
    dname     = ((lit_chr - [$]) | escapes ) (lit_chr | escapes)*;

    # A whole domainname in various contexts
    dname_lhs     = (dname %set_lhs_dname | qword %set_lhs_qword) >token_start;
    dname_rhs     = (dname %set_rhs_dname | qword %set_rhs_qword) >token_start;
    dname_eml     = (dname %set_eml_dname | qword %set_eml_qword) >token_start;

    # One chunk of TXT rdata
    txt_item  = (tword %push_txt_rdata | qword %push_txt_rdata_q) >token_start;

    # One chunk of TXT rdata, limited to 255 explicitly
    txt_item_255  = (tword %push_txt_rdata_255 | qword %push_txt_rdata_255_q) >token_start;

    # One chunk of TXT rdata, limited to 16000 explicitly
    txt_item_huge  = (tword %push_txt_rdata_huge | qword %push_txt_rdata_huge_q) >token_start;

    # A whole set of TXT rdata
    txt_rdata = (ws | txt_item)+ $1 %0 >start_txt;

    # filenames for $INCLUDE
    filename  = (tword %set_filename | qword %set_filename_q) >token_start;

    # plugin!resource for DYN[AC] records
    dyna_rdata = (plugres ('!' plugres)?) >token_start %set_dyna;

    # Unsigned integer values, with "ttl" being a special
    #  case with an optional multiplier suffix
    uval      = digit+ >token_start %set_uval;
    uval_mult = [MHDWmhdw] @mult_uval;
    ttl       = (uval uval_mult?);
    ttl_dyn   = (uval uval_mult? %set_uv_1) ('/' uval uval_mult? %set_uv_2)?;

    # IPv[46] Addresses.  Note that while they are not very
    #  very precise, anything bad that gets past them will still
    #  trigger graceful failure when passed to inet_pton().
    ipv4      = [0-9.]+ >token_start %set_ipv4;
    ipv6      = [a-fA-F0-9:.]+ >token_start %set_ipv6;

    # NAPTR's text strings
    naptr_txt = (txt_item_255 ws txt_item_255 ws txt_item_255) $1 %0 >start_txt;

    # NAPTR's rdata as a whole
    naptr_rdata = uval %set_uv_1 ws uval %set_uv_2 ws naptr_txt ws dname_rhs;

    rfc3597_octet = ([0-9A-Fa-f]{2}) >token_start %rfc3597_octet;
    rfc3597_rdata = uval %set_uv_1 ws '\\' '#' ws uval %rfc3597_data_setup ws
        (rfc3597_octet+ ws?)**;

    caa_prop = [0-9A-Za-z]+ >token_start %set_caa_prop;
    caa_rdata = uval ws caa_prop ws txt_item_huge >start_txt;

    # The left half of a resource record, which for our purposes here
    #  is the optional domainname and/or the optional ttl and/or the
    #  optional 'IN' class, with the order of the latter two being
    #  interchangeable.
    rr_lhs = dname_lhs? ws %use_def_ttl (
          (ttl %set_ttl ws ('IN'i ws)?)
        | ('IN'i ws (ttl %set_ttl ws)?)
    )?;

    # Separate version for DYN[AC] to support TTLs of the form max[/min]
    rr_lhs_dyn = dname_lhs? ws %use_def_ttl_dyn (
          (ttl_dyn %set_ttl_dyn ws ('IN'i ws)?)
        | ('IN'i ws (ttl_dyn %set_ttl_dyn ws)?)
    )?;

    # The rest of a resource record: RR-type and RR-type-specific RDATA.
    # The final actions of each match here invoke ltree code to insert
    #  data into the runtime data structures.
    rr_rhs = (
          ('A'i     ws ipv4) %rec_a
        | ('AAAA'i  ws ipv6) %rec_aaaa
        | ('NS'i    ws dname_rhs) %rec_ns
        | ('CNAME'i ws dname_rhs) %rec_cname
        | ('PTR'i   ws dname_rhs) %rec_ptr
        | ('MX'i    ws uval ws dname_rhs) %rec_mx
        | ('TXT'i   ws txt_rdata) %rec_txt
        | ('SRV'i   ws uval %set_uv_1 ws uval %set_uv_2
                    ws uval %set_uv_3 ws dname_rhs) %rec_srv
        | ('NAPTR'i ws naptr_rdata) %rec_naptr
        | ('SOA'i   ws dname_rhs ws dname_eml ws ttl %set_uv_1
                    ws ttl %set_uv_2 ws ttl %set_uv_3 ws ttl %set_uv_4
                    ws ttl %set_uv_5) %rec_soa
        | ('TYPE'i  rfc3597_rdata) %rec_rfc3597
        # From here down, these are parser-only RR-types, which look
        # identical to RFC3597 to the rest of the core code
        | ('CAA'i   ws caa_rdata) %rec_caa
    );

    # Again, separate copy for the DYN[AC] TTL stuff
    rr_rhs_dyn = (
          ('DYNA'i  ws dyna_rdata) %rec_dyna
        | ('DYNC'i  ws dyna_rdata) %rec_dync
    );

    # A complete resource record, static or dynamic
    rr = (rr_lhs rr_rhs) | (rr_lhs_dyn rr_rhs_dyn);

    # A "command", the $foo directives in zonefiles
    cmd = '$' (
          ('TTL'i ws ttl %set_def_ttl)
        | ('ORIGIN'i ws dname_rhs %reset_origin)
        | ('INCLUDE'i %reset_rhs_origin ws filename (ws dname_rhs)?) $1 %0 %process_include
    );

    # A zonefile is composed of many resource records
    #  and commands and comments and such...
    statement = rr | cmd;
    main := (statement? ws? nl)*;

    write data;
}%%
// end-sonar-exclude

F_NONNULL
static void scanner(zscan_t* z, char* buf, const size_t bufsize)
{
    gdnsd_assert(bufsize);

    // This avoids the unfortunately common case of files with final lines
    //   that are unterminated by bailing out early.  This also incidentally
    //   but importantly protects from set_uval()'s strtoul running off the
    //   end of the buffer if we were parsing an integer at that point.
    if (buf[bufsize - 1] != '\n') {
        parse_error_noargs("No newline at end of file");
        return;
    }

    // Undo parentheses braindamage before real parsing
    preprocess_buf(z, buf, bufsize);

    (void)zone_en_main; // silence unused var warning from generated code

    int cs = zone_start;

    GDNSD_DIAG_PUSH_IGNORED("-Wswitch-default")
    GDNSD_DIAG_PUSH_IGNORED("-Wimplicit-fallthrough")
// start-sonar-exclude
#ifndef __clang_analyzer__
    // ^ ... because the ragel-generated code for the zonefile parser is
    //   so huge that it makes analyzer runs take forever.
    const char* p = buf;
    const char* pe = buf + bufsize;
    const char* eof = pe;
    %% write exec;
#endif // __clang_analyzer__
// end-sonar-exclude
    GDNSD_DIAG_POP
    GDNSD_DIAG_POP

    if (cs == zone_error)
        parse_error_noargs("General parse error");
    else if (cs < zone_first_final)
        parse_error_noargs("Trailing incomplete or unparseable record at end of file");
}
