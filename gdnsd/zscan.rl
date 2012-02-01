/* Copyright © 2011 Brandon L Black <blblack@gmail.com> and Jay Reitz <jreitz@gmail.com>
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

#include "zscan.h"

#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "conf.h"
#include "ltree.h"
#include "ltarena.h"
#include "gdnsd-misc.h"

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#define parse_error(_fmt, ...) \
    log_fatal("Zonefile parse error at line %u of %s: " _fmt,z->lcount,z->curfn,__VA_ARGS__)

#define parse_error_noargs(_fmt) \
    log_fatal("Zonefile parse error at line %u of %s: " _fmt,z->lcount,z->curfn)

typedef struct {
    uint8_t  ipv6[16];
    uint32_t ipv4;
    bool     in_paren;
    bool     zn_err_detect;
    bool     lhs_is_ooz;
    unsigned n_subzones;
    unsigned lcount;
    unsigned num_texts;
    unsigned def_ttl;
    unsigned uval;
    unsigned ttl;
    unsigned uv_1;
    unsigned uv_2;
    unsigned uv_3;
    unsigned uv_4;
    unsigned uv_5;
    unsigned rfc3597_data_len;
    unsigned rfc3597_data_written;
    unsigned limit_v4;
    unsigned limit_v6;
    uint8_t* rfc3597_data;
    const uint8_t** subzones;
    const char* zones_dir;
    const char* curfn;
    const char* tstart;
    uint8_t* include_filename;
    uint8_t  zroot[256];
    uint8_t  origin[256];
    uint8_t  lhs_dname[256];
    uint8_t  rhs_dname[256];
    uint8_t  eml_dname[256];
    uint8_t** texts;
} zscan_t;

F_NONNULL
static void scanner(zscan_t* z, int fd);

/******** IP Addresses ********/

F_NONNULL
static void set_ipv4(zscan_t* z, const char* end) {
    dmn_assert(z); dmn_assert(end);
    char txt[16];
    unsigned len = end - z->tstart;
    memcpy(txt, z->tstart, len);
    txt[len] = 0;
    z->tstart = NULL;
    struct in_addr addr;
    int status = inet_pton(AF_INET, txt, &addr);
    if(status > 0)
        z->ipv4 = addr.s_addr;
    else
        parse_error("IPv4 address '%s' invalid", txt);
}

F_NONNULL
static void set_ipv6(zscan_t* z, const char* end) {
    dmn_assert(z);
    dmn_assert(end);
    char txt[INET6_ADDRSTRLEN + 1];
    unsigned len = end - z->tstart;
    memcpy(txt, z->tstart, len);
    txt[len] = 0;
    z->tstart = NULL;
    struct in6_addr* v6a = malloc(sizeof(struct in6_addr));
    int status = inet_pton(AF_INET6, txt, v6a);
    if(status > 0)
        memcpy(z->ipv6, v6a->s6_addr, 16);
    else
        parse_error("IPv6 address '%s' invalid", txt);

    free(v6a);
}

F_NONNULL
static void validate_dname_in_zone(const zscan_t* z, const uint8_t* dname) {
    dmn_assert(z); dmn_assert(z->zroot); dmn_assert(dname);
    if(!dname_isinzone(z->zroot, dname))
        parse_error("domainname %s is not within this zonefile's zone (%s)", logf_dname(dname), logf_dname(z->zroot));
}

F_NONNULL
static void validate_lhs_not_ooz(const zscan_t* z) {
    dmn_assert(z);
    if(z->lhs_is_ooz)
        parse_error("domainname %s is not within this zonefile's zone (%s)", logf_dname(z->lhs_dname), logf_dname(z->zroot));
}

F_NONNULL
static void dname_set(zscan_t* z, uint8_t* dname, unsigned len, bool lhs) {
    dmn_assert(z); dmn_assert(dname); dmn_assert(z->zroot); dmn_assert(z->origin);
    dname_status_t catstat;
    dname_status_t status = dname_from_string(dname, (const uint8_t*)z->tstart, len);
    switch(status) {
        case DNAME_INVALID:
            parse_error_noargs("unparseable domainname");
            break;
        case DNAME_VALID:
            if(lhs) z->lhs_is_ooz = !dname_isinzone(z->zroot, dname);
            break;
        case DNAME_PARTIAL:
            if(lhs) z->lhs_is_ooz = false;
            catstat = dname_cat(dname, z->origin);
            if(catstat == DNAME_INVALID)
                parse_error_noargs("illegal domainname");
            break;
    }
}

F_NONNULL
static zscan_t* zscan_init(zscan_t* z, const char* zones_dir, const uint8_t* zname, const uint8_t* origin, const char* fn, const unsigned def_ttl_arg, const unsigned limit_v4, const unsigned limit_v6, const unsigned n_subzones, const uint8_t** subzones) {
    dmn_assert(z); dmn_assert(zname); dmn_assert(origin); dmn_assert(fn);
    memset(z, 0, sizeof(zscan_t));
    z->lcount = 1;
    z->def_ttl = def_ttl_arg;
    z->curfn = fn;
    z->n_subzones = n_subzones;
    z->subzones = subzones;
    z->zones_dir = zones_dir;
    z->limit_v4 = limit_v4;
    z->limit_v6 = limit_v6;
    dname_copy(z->zroot, zname);
    dname_copy(z->origin, origin);

    return z;
}

/********** TXT/SPF ******************/

F_NONNULL
static void text_start(zscan_t* z) {
    dmn_assert(z);
    z->num_texts = 0;
    z->texts = NULL;
}

// Only if we didn't add_rec, as normally
//  add_rec consumes the allocation.
F_NONNULL
static void texts_free(zscan_t* z) {
    for(unsigned i = 0; i < z->num_texts; i++)
        free(z->texts[i]);
}

F_NONNULL
static void text_add_tok(zscan_t* z, const unsigned len, const bool big_ok) {
    dmn_assert(z);

    uint8_t text_temp[len + 1];

    const unsigned newlen = dns_unescape(text_temp, (const uint8_t*)z->tstart, len);
    dmn_assert(newlen <= len);

    if(newlen > 255) {
        if(!big_ok || gconfig.disable_text_autosplit)
            parse_error_noargs("Text chunk too long (>255 unescaped)");
        if(newlen > 65500) parse_error_noargs("Text chunk too long (>65500 unescaped)");
        unsigned remainder = newlen % 255;
        unsigned num_whole_chunks = (newlen - remainder) / 255;
        const uint8_t* zptr = text_temp;
        const unsigned new_alloc = 1 + z->num_texts + num_whole_chunks + (remainder ? 1 : 0);
        z->texts = realloc(z->texts, new_alloc * sizeof(uint8_t*));
        for(unsigned i = 0; i < num_whole_chunks; i++) {
            uint8_t* chunk = z->texts[z->num_texts++] = lta_malloc_1(256);
            *chunk++ = 255;
            memcpy(chunk, zptr, 255);
            zptr += 255;
        }
        if(remainder) {
            uint8_t* chunk = z->texts[z->num_texts++] = lta_malloc_1(remainder + 1);
            *chunk++ = remainder;
            memcpy(chunk, zptr, remainder);
        }
        z->texts[z->num_texts] = NULL;
    }
    else {
        z->texts = realloc(z->texts, (z->num_texts + 2) * sizeof(uint8_t*));
        uint8_t* chunk = z->texts[z->num_texts++] = lta_malloc_1(newlen + 1);
        *chunk++ = newlen;
        memcpy(chunk, text_temp, newlen);
        z->texts[z->num_texts] = NULL;
    }

    z->tstart = NULL;
}

F_NONNULL
static void set_filename(zscan_t* z, const unsigned len) {
    dmn_assert(z);
    uint8_t* fn = malloc(len + 1);
    const unsigned newlen = dns_unescape(fn, (const uint8_t*)z->tstart, len);
    dmn_assert(newlen <= len);
    z->include_filename = fn = realloc(fn, newlen + 1);
    fn[newlen] = 0;
    z->tstart = NULL;
}

// Input must have two bytes of text constrained to [0-9A-Fa-f]
F_NONNULL
static unsigned hexbyte(const char* intxt) {
    dmn_assert(intxt);
    dmn_assert(
        (intxt[0] >= '0' && intxt[0] <= '9')
        || (intxt[0] >= 'A' && intxt[0] <= 'F')
        || (intxt[0] >= 'a' && intxt[0] <= 'f')
    );
    dmn_assert(
        (intxt[1] >= '0' && intxt[1] <= '9')
        || (intxt[1] >= 'A' && intxt[1] <= 'F')
        || (intxt[1] >= 'a' && intxt[1] <= 'f')
    );

    unsigned out;

    if(intxt[0] <= '9')
        out = (intxt[0] - '0') << 4;
    else
        out = ((intxt[0] | 0x20) - ('a' - 10)) << 4;

    if(intxt[1] <= '9')
        out |= (intxt[1] - '0');
    else
        out |= ((intxt[1] | 0x20) - ('a' - 10));

    return out;
}

F_NONNULL
static bool lhs_subzones_ok(zscan_t* z) {
    for(unsigned i = 0; i < z->n_subzones; i++) {
        if(dname_isinzone(z->subzones[i], z->lhs_dname)) {
            log_warn("Ignoring RRs for name '%s' in zone '%s' because they overlap subzone '%s'",
                logf_dname(z->lhs_dname), logf_dname(z->zroot), logf_dname(z->subzones[i]));
            return false;
        }
    }

    return true;
}

F_NONNULL
static void process_include(zscan_t* z) {
    dmn_assert(z);
    dmn_assert(z->include_filename);
    char* zfn = gdnsd_make_abs_fn(z->zones_dir, (char*)z->include_filename);
    free(z->include_filename);
    z->include_filename = NULL;
    validate_dname_in_zone(z, z->rhs_dname);
    zscan_t* znew = malloc(sizeof(zscan_t));
    zscan_init(znew, z->zones_dir, z->zroot, z->rhs_dname, zfn, z->def_ttl, z->limit_v4, z->limit_v6, z->n_subzones, z->subzones);
    int newfd = open(zfn, O_RDONLY);
    if(newfd < 0)
        parse_error("Cannot open $INCLUDE file '%s' for reading: %s", zfn, logf_errno());
    scanner(znew, newfd);
    if(close(newfd))
        parse_error("Cannot close $INCLUDE file '%s': %s", zfn, logf_errno());
    free(zfn);
    free(znew);
}

F_NONNULL
static void mult_uval(zscan_t* z, int fc) {
    dmn_assert(z);
    fc |= 0x20;
    switch(fc) {
        case 'm': z->uval *= 60; break;
        case 'h': z->uval *= 3600; break;
        case 'd': z->uval *= 86400; break;
        case 'w': z->uval *= 604800; break;
    }
}

F_NONNULL
static void set_dyna(zscan_t* z, const char* fpc) {
    dmn_assert(z);
    unsigned dlen = fpc - z->tstart;
    if(dlen > 255)
        parse_error_noargs("DYNA/DYNC plugin!resource string cannot exceed 255 chars");
    memcpy(z->eml_dname, z->tstart, dlen);
    z->eml_dname[dlen] = 0;
    z->tstart = NULL;
}

F_NONNULL
static void rec_soa(zscan_t* z) {
    dmn_assert(z);
    if(dname_cmp(z->lhs_dname, z->zroot))
        parse_error_noargs("SOA record can only be defined for the root of the zone");
    ltree_add_rec_soa(z->lhs_dname, z->rhs_dname, z->eml_dname, z->ttl, z->uv_1, z->uv_2, z->uv_3, z->uv_4, z->uv_5);
}

F_NONNULL
static void rec_a(zscan_t* z) {
    dmn_assert(z);
    if(lhs_subzones_ok(z))
        ltree_add_rec_a(z->lhs_dname, z->ipv4, z->ttl, z->limit_v4, z->lhs_is_ooz ? z->zroot : NULL);
}

F_NONNULL
static void rec_aaaa(zscan_t* z) {
    dmn_assert(z);
    if(!z->lhs_is_ooz)
        ltree_add_rec_aaaa(z->lhs_dname, z->ipv6, z->ttl, z->limit_v6, z->lhs_is_ooz ? z->zroot : NULL);
}

F_NONNULL
static void rec_ns(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(lhs_subzones_ok(z))
        ltree_add_rec_ns(z->lhs_dname, z->rhs_dname, z->ttl);
}

F_NONNULL
static void rec_cname(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(lhs_subzones_ok(z))
        ltree_add_rec_cname(z->lhs_dname, z->rhs_dname, z->ttl);
}

F_NONNULL
static void rec_ptr(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(lhs_subzones_ok(z))
        ltree_add_rec_ptr(z->lhs_dname, z->rhs_dname, z->ttl);
}

F_NONNULL
static void rec_mx(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(lhs_subzones_ok(z))
        ltree_add_rec_mx(z->lhs_dname, z->rhs_dname, z->ttl, z->uv_1);
}

F_NONNULL
static void rec_srv(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(lhs_subzones_ok(z))
        ltree_add_rec_srv(z->lhs_dname, z->rhs_dname, z->ttl, z->uv_1, z->uv_2, z->uv_3);
}

F_NONNULL
static void rec_naptr(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(lhs_subzones_ok(z))
        ltree_add_rec_naptr(z->lhs_dname, z->rhs_dname, z->ttl, z->uv_1, z->uv_2, z->num_texts, z->texts);
    else
        texts_free(z);
    free(z->texts);
}

F_NONNULL
static void rec_txt(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(lhs_subzones_ok(z))
        ltree_add_rec_txt(z->lhs_dname, z->num_texts, z->texts, z->ttl);
    else
        texts_free(z);
    free(z->texts);
}

F_NONNULL
static void rec_spf(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(lhs_subzones_ok(z))
        ltree_add_rec_spf(z->lhs_dname, z->num_texts, z->texts, z->ttl);
    else
        texts_free(z);
    free(z->texts);
}

F_NONNULL
static void rec_spftxt(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(lhs_subzones_ok(z))
        ltree_add_rec_spftxt(z->lhs_dname, z->num_texts, z->texts, z->ttl);
    else
        texts_free(z);
    free(z->texts);
}

F_NONNULL
static void rec_dyna(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(lhs_subzones_ok(z))
        ltree_add_rec_dynaddr(z->lhs_dname, z->eml_dname, z->ttl, z->limit_v4, z->limit_v6);
}

F_NONNULL
static void rec_dyncname(zscan_t* z) {
    dmn_assert(z);

    validate_lhs_not_ooz(z);
    if(lhs_subzones_ok(z)) {
        ltree_add_rec_dyncname(z->lhs_dname, z->eml_dname, z->origin, z->ttl);
    }
}

F_NONNULL
static void rec_rfc3597(zscan_t* z) {
    dmn_assert(z);
    if(z->rfc3597_data_written < z->rfc3597_data_len)
        parse_error("RFC3597 generic RR claimed rdata length of %u, but only %u bytes of data present", z->rfc3597_data_len, z->rfc3597_data_written);
    validate_lhs_not_ooz(z);
    if(lhs_subzones_ok(z))
        ltree_add_rec_rfc3597(z->lhs_dname, z->uv_1, z->ttl, z->rfc3597_data_len, z->rfc3597_data);
    else
        free(z->rfc3597_data);
}

%%{
    machine zone;

    action token_start { z->tstart = fpc; }

    action set_lhs_origin { dname_copy(z->lhs_dname, z->origin); }
    action set_lhs_dname { dname_set(z, z->lhs_dname, fpc - z->tstart, true); }
    action set_lhs_qword { z->tstart++; dname_set(z, z->lhs_dname, fpc - z->tstart - 1, true); }
    action set_rhs_origin { dname_copy(z->rhs_dname, z->origin); }
    action set_rhs_dname { dname_set(z, z->rhs_dname, fpc - z->tstart, false); }
    action set_rhs_qword { z->tstart++; dname_set(z, z->rhs_dname, fpc - z->tstart - 1, false); }
    action set_eml_dname { dname_set(z, z->eml_dname, fpc - z->tstart, false); }
    action set_eml_qword { z->tstart++; dname_set(z, z->eml_dname, fpc - z->tstart - 1, false); }

    action reset_origin {
        validate_dname_in_zone(z, z->rhs_dname);
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

    action set_ipv4 { set_ipv4(z, fpc); }
    action set_ipv6 { set_ipv6(z, fpc); }
    action set_uval { z->uval = atoi(z->tstart); z->tstart = NULL; }
    action mult_uval { mult_uval(z, fc); }

    action set_ttl     { z->ttl  = z->uval; }
    action set_def_ttl { z->def_ttl = z->uval; }
    action use_def_ttl { z->ttl  = z->def_ttl; }
    action set_uv_1    { z->uv_1 = z->uval; }
    action set_uv_2    { z->uv_2 = z->uval; }
    action set_uv_3    { z->uv_3 = z->uval; }
    action set_uv_4    { z->uv_4 = z->uval; }
    action set_uv_5    { z->uv_5 = z->uval; }

    action set_limit_v4 {
        if(z->uval > 65535)
            parse_error("$ADDR_LIMIT_V4 value %u out of range (0-65535)", z->uval);
        z->limit_v4 = z->uval;
    }

    action set_limit_v6 {
        if(z->uval > 65535)
            parse_error("$ADDR_LIMIT_V6 value %u out of range (0-65535)", z->uval);
        z->limit_v6 = z->uval;
    }

    # We re-use eml_dname to store dyna strings
    action set_dyna { set_dyna(z, fpc); }

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
    action rec_spf { rec_spf(z); }
    action rec_spftxt { rec_spftxt(z); }
    action rec_dyna { rec_dyna(z); }
    action rec_dync { rec_dyncname(z); }
    action rec_rfc3597 { rec_rfc3597(z); }

    action rfc3597_data_setup { z->rfc3597_data_len = z->uval; z->rfc3597_data_written = 0; z->rfc3597_data = malloc(z->uval); }


    action open_paren { if(z->in_paren) parse_error_noargs("Parenthetical error: double-open"); z->in_paren = true; }
    action close_paren { if(!z->in_paren) parse_error_noargs("Parenthetical error: unneccesary close"); z->in_paren = false; }
    action in_paren { z->in_paren }

    # newlines, count them
    nl  = [\n]+ ${z->lcount++;};

    # Single Line Comment, e.g. ; dns comment
    slc = ';' [^\n]*;

    # Whitespace, with special handling for braindead () multi-line records
    ws = (
        [ \t]+
        | '(' $open_paren
        | ')' $close_paren
        | (slc? nl)+ when in_paren
    )+;

    # Escape sequences in general for any character-string
    #  (domainname or TXT record rdata, etc)
    escape_int = 25[0-5] | ( 2[0-4] | [01][0-9] ) [0-9] ;
    escapes    = ('\\' [^0-9\n]) | ('\\' escape_int) | ('\\\n' %{z->lcount++;});

    # Quoted character string 
    qword     = '"' ([^"\n\\]|escapes|nl)* '"';

    # The base set of literal characters allowed in unquoted character
    #  strings (again, labels or txt rdata chunks)
    lit_chr   = [^; \t"\n\\)(];

    # plugin / resource names for DYNA
    plugres   = ((lit_chr - [!]) | escapes)+;

    # unquoted TXT case
    tword     = (lit_chr | escapes)+ $1 %0;

    # unquoted dname case, disallow unescaped [@$] at the front
    dname     = ((lit_chr - [@$]) | escapes ) (lit_chr | escapes)*;

    # A whole domainname (or @ as $ORIGIN shorthand) in various contexts
    dname_lhs     = (
          '@'   %set_lhs_origin
        | dname %set_lhs_dname
        | qword %set_lhs_qword
    ) >token_start;

    dname_rhs     = (
          '@'   %set_rhs_origin
        | dname %set_rhs_dname
        | qword %set_rhs_qword
    ) >token_start;

    dname_eml     = (
          dname %set_eml_dname
        | qword %set_eml_qword
    ) >token_start;

    # One chunk of TXT rdata
    txt_item  = (tword %push_txt_rdata | qword %push_txt_rdata_q) >token_start;

    # One chunk of TXT rdata, limited to 255 explicitly
    txt_item_255  = (tword %push_txt_rdata_255 | qword %push_txt_rdata_255_q) >token_start;

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

    # IPv[46] Addresses.  Note that while they are not very
    #  very precise, anything bad that gets past them will still
    #  trigger graceful failure when passed to inet_pton().
    ipoct     = digit{1,3};
    _ipv4     = ipoct ('.' ipoct){3};
    ipv4      = _ipv4 >token_start %set_ipv4;
    ipv6      = ([a-fA-F0-9:]+ ( ':' _ipv4 )?) >token_start %set_ipv6;

    # NAPTR's text strings
    naptr_txt = (txt_item_255 ws txt_item_255 ws txt_item_255) $1 %0 >start_txt;

    # NAPTR's rdata as a whole
    naptr_rdata = uval %set_uv_1 ws uval %set_uv_2 ws naptr_txt ws dname_rhs;

    rfc3597_octet = ([0-9A-Fa-f]{2}) >token_start %{
        if(z->rfc3597_data_written == z->rfc3597_data_len)
           parse_error_noargs("RFC3597 generic RR: more rdata is present than the indicated length");
        z->rfc3597_data[z->rfc3597_data_written++] = hexbyte(z->tstart);
    };
    rfc3597_rdata = uval %set_uv_1 ws '\\' '#' ws uval %rfc3597_data_setup
        (ws rfc3597_octet+ $1 %0)* $1 %0;

    # The left half of a resource record, which for our purposes here
    #  is the optional domainname and/or the optional ttl and/or the
    #  optional 'IN' class, with the order of the latter two being
    #  interchangeable.
    rr_lhs = dname_lhs? ws %use_def_ttl (
          (ttl %set_ttl ws ('IN'i ws)?)
        | ('IN'i ws (ttl %set_ttl ws)?)
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
        | ('MX'i    ws uval %set_uv_1 ws dname_rhs) %rec_mx
        | ('TXT'i   ws txt_rdata) %rec_txt
        | ('SPF'i   ws txt_rdata) %rec_spf
        | ('SPF+'i  ws txt_rdata) %rec_spftxt
        | ('SRV'i   ws uval %set_uv_1 ws uval %set_uv_2
                    ws uval %set_uv_3 ws dname_rhs) %rec_srv
        | ('NAPTR'i ws naptr_rdata) %rec_naptr
        | ('DYNA'i  ws dyna_rdata) %rec_dyna
        | ('DYNC'i  ws dyna_rdata) %rec_dync
        | ('SOA'i   ws dname_rhs ws dname_eml ws ttl %set_uv_1
                    ws ttl %set_uv_2 ws ttl %set_uv_3 ws ttl %set_uv_4
                    ws ttl %set_uv_5) %rec_soa
        | ('TYPE'i  rfc3597_rdata) %rec_rfc3597
    );

    # A complete resource record
    rr = rr_lhs rr_rhs;

    # A "command", the $foo directives in zonefiles
    cmd = '$' (
          ('TTL'i ws ttl %set_def_ttl)
        | ('ORIGIN'i ws dname_rhs %reset_origin)
        | ('INCLUDE'i ws filename (ws dname_rhs)?) $1 %0 %process_include
        | ('ADDR_LIMIT_V4'i ws uval %set_limit_v4)
        | ('ADDR_LIMIT_V6'i ws uval %set_limit_v6)
    );

    # A zonefile is composed of many resource records
    #  and commands and comments and such...
    statement = rr | cmd;
    main := (statement? ws? ((slc? nl) when !in_paren))*;

    write data nofinal;
}%%

/*
 * The longest possible tstart-based token is a maximum-length
 *  quoted TXT string, which given autosplit, can be up to
 *  roughly 64K, which means buffer size has to be that big
 *  to accomodate that.  There probably wouldn't be any bugs
 *  going down to something reasonable like 4K, but it would
 *  cause parse errors if anyone tried to use longer TXT strings.
 * Another important thing: for integers, we use atoi() directly
 *  on the buffer itself.  In the normal case this works because
 *  there is always some non-integer after it in the buffer, which
 *  halts atoi().  The corner case is if the last digit of an
 *  integer happened to be the last byte of the buffer.  This
 *  is why we allocate one extra buffer byte and set it to zero.
 */
#define BUFSIZE 65536

F_NONNULL
static void scanner(zscan_t* z, int fd) {
    dmn_assert(z);

#ifdef HAVE_POSIX_FADVISE
    {
        struct stat fdstat;
        if(fstat(fd, &fdstat))
            log_fatal("fstat() of '%s' failed: %s", z->curfn, logf_errno());
        posix_fadvise(fd, 0, fdstat.st_size, POSIX_FADV_SEQUENTIAL);
    }
#endif

    char* buf = malloc(BUFSIZE + 1);
    char* read_at;
    buf[BUFSIZE] = 0;

    const char* pe = NULL;
    const char* eof = NULL;
    int cs = zone_start;

    while(!eof) {
        unsigned have = 0;
        if(z->tstart != NULL) {
            dmn_assert(pe);
            dmn_assert(z->tstart < pe);
            dmn_assert(z->tstart != buf);
            have = pe - z->tstart;
            memmove(buf, z->tstart, have);
            z->tstart = buf;
        }

        const int space = BUFSIZE - have;
        const char* p = read_at = buf + have;

        const int len = read(fd, read_at, space);
        if(len < 0)
            parse_error("read() failed: %s", logf_errno());

        pe = p + len;

        if(len < space)
            eof = pe;

        %%{
            write exec;
        }%%

        if(cs == zone_error)
            parse_error_noargs("unparseable");
    }

    free(buf);
}

void scan_zone(const zoneinfo_t* zone) {
    dmn_assert(zone);

    log_debug("Scanning zone '%s'", logf_dname(zone->dname));

    zscan_t* z = malloc(sizeof(zscan_t));
    zscan_init(z, zone->zones_dir, zone->dname, zone->dname, zone->file, zone->def_ttl, 0, 0, zone->n_subzones, zone->subzones);
    int fd = open(zone->file, O_RDONLY);
    if(fd < 0)
        log_fatal("Cannot open zone file '%s' for reading: %s", zone->file, logf_errno());
    scanner(z, fd);
    if(close(fd))
        log_fatal("Cannot close zone file '%s': %s", zone->file, logf_errno());
    free(z);
}
