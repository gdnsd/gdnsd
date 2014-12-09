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
        log_err("rfc1035: Zone %s: Zonefile parse error at line %u: " _fmt,logf_dname(z->zone->dname),z->lcount,__VA_ARGS__);\
        siglongjmp(z->jbuf, 1);\
    } while(0)

#define parse_error_noargs(_fmt) \
    do {\
        log_err("rfc1035: Zone %s: Zonefile parse error at line %u: " _fmt,logf_dname(z->zone->dname),z->lcount);\
        siglongjmp(z->jbuf, 1);\
    } while(0)

typedef struct {
    uint8_t  ipv6[16];
    uint32_t ipv4;
    bool     in_paren;
    bool     zn_err_detect;
    bool     lhs_is_ooz;
    unsigned lcount;
    unsigned num_texts;
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
    unsigned limit_v4;
    unsigned limit_v6;
    uint8_t* rfc3597_data;
    zone_t* zone;
    const char* tstart;
    uint8_t  origin[256];
    uint8_t  lhs_dname[256];
    uint8_t  rhs_dname[256];
    union {
        uint8_t eml_dname[256];
        char    rhs_dyn[256];
    };
    uint8_t** texts;
    sigjmp_buf jbuf;
} zscan_t;

F_NONNULL
static void scanner(zscan_t* z, const char* buf, const size_t bufsize);

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
    struct in6_addr v6a;
    int status = inet_pton(AF_INET6, txt, &v6a);
    if(status > 0)
        memcpy(z->ipv6, v6a.s6_addr, 16);
    else
        parse_error("IPv6 address '%s' invalid", txt);
}

F_NONNULL
static void set_uval(zscan_t* z) {
    errno = 0;
    z->uval = strtoul(z->tstart, NULL, 10);
    z->tstart = NULL;
    if(errno)
        parse_error("Integer conversion error: %s", dmn_logf_errno());
}

F_NONNULL
static void validate_origin_in_zone(zscan_t* z, const uint8_t* origin) {
    dmn_assert(z); dmn_assert(z->zone->dname); dmn_assert(origin);
    if(!dname_isinzone(z->zone->dname, origin))
        parse_error("Origin '%s' is not within this zonefile's zone (%s)", logf_dname(origin), logf_dname(z->zone->dname));
}

F_NONNULL
static void validate_lhs_not_ooz(zscan_t* z) {
    dmn_assert(z);
    if(z->lhs_is_ooz)
        parse_error("Domainname '%s' is not within this zonefile's zone (%s)", logf_dname(z->lhs_dname), logf_dname(z->zone->dname));
}

F_NONNULL
static void dname_set(zscan_t* z, uint8_t* dname, unsigned len, bool lhs) {
    dmn_assert(z); dmn_assert(dname); dmn_assert(z->zone->dname);
    dname_status_t catstat;
    dname_status_t status;

    if(len) {
        status = dname_from_string(dname, z->tstart, len);
    }
    else {
        dmn_assert(lhs);
        dname_copy(dname, z->origin);
        status = DNAME_VALID;
    }

    switch(status) {
        case DNAME_INVALID:
            parse_error_noargs("unparseable domainname");
            break;
        case DNAME_VALID:
            if(lhs) {
                const bool inzone = dname_isinzone(z->zone->dname, dname);
                z->lhs_is_ooz = !inzone;
                // in-zone LHS dnames are made relative to zroot
                if(inzone)
                    gdnsd_dname_drop_zone(dname, z->zone->dname);
            }
            break;
        case DNAME_PARTIAL:
            // even though in the lhs case we commonly trim
            //   back most or all of z->origin from dname, we
            //   still have to construct it just for validity checks
            catstat = dname_cat(dname, z->origin);
            if(catstat == DNAME_INVALID)
                parse_error_noargs("illegal domainname");
            dmn_assert(catstat == DNAME_VALID);
            if(lhs) {
                z->lhs_is_ooz = false;
                gdnsd_dname_drop_zone(dname, z->zone->dname);
            }
            break;
        default: dmn_assert(0);
    }
}

/********** TXT ******************/

F_NONNULL
static void text_start(zscan_t* z) {
    dmn_assert(z);
    z->num_texts = 0;
    z->texts = NULL;
}

F_NONNULL
static void text_add_tok(zscan_t* z, const unsigned len, const bool big_ok) {
    dmn_assert(z);

    char text_temp[len + 1];
    text_temp[0] = 0;
    unsigned newlen = len;
    if(len)
        newlen = dns_unescape(text_temp, z->tstart, len);

    dmn_assert(newlen <= len);

    if(newlen > 255) {
        if(!big_ok || gcfg->disable_text_autosplit)
            parse_error_noargs("Text chunk too long (>255 unescaped)");
        if(newlen > 65500) parse_error_noargs("Text chunk too long (>65500 unescaped)");
        unsigned remainder = newlen % 255;
        unsigned num_whole_chunks = (newlen - remainder) / 255;
        const char* zptr = text_temp;
        const unsigned new_alloc = 1 + z->num_texts + num_whole_chunks + (remainder ? 1 : 0);
        z->texts = xrealloc(z->texts, new_alloc * sizeof(uint8_t*));
        for(unsigned i = 0; i < num_whole_chunks; i++) {
            uint8_t* chunk = z->texts[z->num_texts++] = xmalloc(256);
            *chunk++ = 255;
            memcpy(chunk, zptr, 255);
            zptr += 255;
        }
        if(remainder) {
            uint8_t* chunk = z->texts[z->num_texts++] = xmalloc(remainder + 1);
            *chunk++ = remainder;
            memcpy(chunk, zptr, remainder);
        }
        z->texts[z->num_texts] = NULL;
    }
    else {
        z->texts = xrealloc(z->texts, (z->num_texts + 2) * sizeof(uint8_t*));
        uint8_t* chunk = z->texts[z->num_texts++] = xmalloc(newlen + 1);
        *chunk++ = newlen;
        memcpy(chunk, text_temp, newlen);
        z->texts[z->num_texts] = NULL;
    }

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

    int out;

    if(intxt[0] <= '9')
        out = (intxt[0] - '0') << 4;
    else
        out = ((intxt[0] | 0x20) - ('a' - 10)) << 4;

    if(intxt[1] <= '9')
        out |= (intxt[1] - '0');
    else
        out |= ((intxt[1] | 0x20) - ('a' - 10));

    dmn_assert(out >= 0 && out < 256);
    return (unsigned)out;
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
        default: dmn_assert(0);
    }
}

F_NONNULL
static void set_dyna(zscan_t* z, const char* fpc) {
    dmn_assert(z);
    unsigned dlen = fpc - z->tstart;
    if(dlen > 255)
        parse_error_noargs("DYNA/DYNC plugin!resource string cannot exceed 255 chars");
    memcpy(z->rhs_dyn, z->tstart, dlen);
    z->rhs_dyn[dlen] = 0;
    z->tstart = NULL;
}

F_NONNULL
static void rec_soa(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(z->lhs_dname[0] != 1)
        parse_error_noargs("SOA record can only be defined for the root of the zone");
    if(ltree_add_rec_soa(z->zone, z->lhs_dname, z->rhs_dname, z->eml_dname, z->ttl, z->uv_1, z->uv_2, z->uv_3, z->uv_4, z->uv_5))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void rec_a(zscan_t* z) {
    dmn_assert(z);
    if(ltree_add_rec_a(z->zone, z->lhs_dname, z->ipv4, z->ttl, z->limit_v4, z->lhs_is_ooz))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void rec_aaaa(zscan_t* z) {
    dmn_assert(z);
    if(ltree_add_rec_aaaa(z->zone, z->lhs_dname, z->ipv6, z->ttl, z->limit_v6, z->lhs_is_ooz))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void rec_ns(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(ltree_add_rec_ns(z->zone, z->lhs_dname, z->rhs_dname, z->ttl))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void rec_cname(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(ltree_add_rec_cname(z->zone, z->lhs_dname, z->rhs_dname, z->ttl))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void rec_ptr(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(ltree_add_rec_ptr(z->zone, z->lhs_dname, z->rhs_dname, z->ttl))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void rec_mx(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(ltree_add_rec_mx(z->zone, z->lhs_dname, z->rhs_dname, z->ttl, z->uv_1))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void rec_srv(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(ltree_add_rec_srv(z->zone, z->lhs_dname, z->rhs_dname, z->ttl, z->uv_1, z->uv_2, z->uv_3))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void texts_cleanup(zscan_t* z) {
    dmn_assert(z);
    free(z->texts);
    z->texts = NULL;
    z->num_texts = 0;
}

F_NONNULL
static void rec_naptr(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(ltree_add_rec_naptr(z->zone, z->lhs_dname, z->rhs_dname, z->ttl, z->uv_1, z->uv_2, z->num_texts, z->texts))
        siglongjmp(z->jbuf, 1);
    texts_cleanup(z);
}

F_NONNULL
static void rec_txt(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(ltree_add_rec_txt(z->zone, z->lhs_dname, z->num_texts, z->texts, z->ttl))
        siglongjmp(z->jbuf, 1);
    texts_cleanup(z);
}

F_NONNULL
static void rec_dyna(zscan_t* z) {
    dmn_assert(z);
    if(ltree_add_rec_dynaddr(z->zone, z->lhs_dname, z->rhs_dyn, z->ttl, z->ttl_min, z->limit_v4, z->limit_v6, z->lhs_is_ooz))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void rec_dync(zscan_t* z) {
    dmn_assert(z);
    validate_lhs_not_ooz(z);
    if(ltree_add_rec_dync(z->zone, z->lhs_dname, z->rhs_dyn, z->origin, z->ttl, z->ttl_min, z->limit_v4, z->limit_v6))
        siglongjmp(z->jbuf, 1);
}

F_NONNULL
static void rec_rfc3597(zscan_t* z) {
    dmn_assert(z);
    if(z->rfc3597_data_written < z->rfc3597_data_len)
        parse_error("RFC3597 generic RR claimed rdata length of %u, but only %u bytes of data present", z->rfc3597_data_len, z->rfc3597_data_written);
    validate_lhs_not_ooz(z);
    if(ltree_add_rec_rfc3597(z->zone, z->lhs_dname, z->uv_1, z->ttl, z->rfc3597_data_len, z->rfc3597_data))
        siglongjmp(z->jbuf, 1);
    z->rfc3597_data = NULL;
}

F_NONNULL
static void rfc3597_data_setup(zscan_t* z) {
    dmn_assert(z);
    z->rfc3597_data_len = z->uval;
    z->rfc3597_data_written = 0;
    z->rfc3597_data = xmalloc(z->uval);
}

F_NONNULL
static void rfc3597_octet(zscan_t* z) {
    dmn_assert(z);
    if(z->rfc3597_data_written == z->rfc3597_data_len)
       parse_error_noargs("RFC3597 generic RR: more rdata is present than the indicated length");
    z->rfc3597_data[z->rfc3597_data_written++] = hexbyte(z->tstart);
}

F_NONNULL
static void set_limit_v4(zscan_t* z) {
    dmn_assert(z);
    if(z->uval > 65535)
        parse_error("$ADDR_LIMIT_V4 value %u out of range (0-65535)", z->uval);
    z->limit_v4 = z->uval;
}

F_NONNULL
static void set_limit_v6(zscan_t* z) {
    dmn_assert(z);
    if(z->uval > 65535)
        parse_error("$ADDR_LIMIT_V6 value %u out of range (0-65535)", z->uval);
    z->limit_v6 = z->uval;
}

F_NONNULL
static void open_paren(zscan_t* z) {
    dmn_assert(z);
    if(z->in_paren)
        parse_error_noargs("Parenthetical error: double-open");
    z->in_paren = true;
}

F_NONNULL
static void close_paren(zscan_t* z) {
    dmn_assert(z);
    if(!z->in_paren)
        parse_error_noargs("Parenthetical error: unnecessary close");
    z->in_paren = false;
}

%%{
    machine zone;

    action token_start { z->tstart = fpc; }

    # special case for LHS: dname_set w/ len of zero -> use origin and trim zone root
    action set_lhs_origin { dname_set(z, z->lhs_dname, 0, true); }
    action set_lhs_dname { dname_set(z, z->lhs_dname, fpc - z->tstart, true); }
    action set_lhs_qword { z->tstart++; dname_set(z, z->lhs_dname, fpc - z->tstart - 1, true); }
    action set_rhs_origin { dname_copy(z->rhs_dname, z->origin); }
    action set_rhs_dname { dname_set(z, z->rhs_dname, fpc - z->tstart, false); }
    action set_rhs_qword { z->tstart++; dname_set(z, z->rhs_dname, fpc - z->tstart - 1, false); }
    action set_eml_dname { dname_set(z, z->eml_dname, fpc - z->tstart, false); }
    action set_eml_qword { z->tstart++; dname_set(z, z->eml_dname, fpc - z->tstart - 1, false); }

    action reset_origin {
        validate_origin_in_zone(z, z->rhs_dname);
        dname_copy(z->origin, z->rhs_dname);
    }

    action start_txt { text_start(z); }
    action push_txt_rdata { text_add_tok(z, fpc - z->tstart, true); }
    action push_txt_rdata_q { z->tstart++; text_add_tok(z, fpc - z->tstart - 1, true); }
    action push_txt_rdata_255 { text_add_tok(z, fpc - z->tstart, false); }
    action push_txt_rdata_255_q { z->tstart++; text_add_tok(z, fpc - z->tstart - 1, false); }

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

    action set_limit_v4 { set_limit_v4(z); }
    action set_limit_v6 { set_limit_v6(z); }

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
    action rec_dyna { rec_dyna(z); }
    action rec_dync { rec_dync(z); }
    action rec_rfc3597 { rec_rfc3597(z); }

    action rfc3597_data_setup { rfc3597_data_setup(z); }
    action rfc3597_octet { rfc3597_octet(z); }
    action open_paren { open_paren(z); }
    action close_paren { close_paren(z); }
    action in_paren { z->in_paren }

    # newlines, count them
    nl  = '\r'? '\n' %{ z->lcount++; };

    # Single Line Comment, e.g. ; dns comment
    slc = ';' [^\r\n]*;

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
    escapes    = ('\\' [^0-9\r\n]) | ('\\' escape_int) | ('\\' nl);

    # Quoted character string
    qword     = '"' ([^"\r\n\\]|escapes|nl)* '"';

    # The base set of literal characters allowed in unquoted character
    #  strings (again, labels or txt rdata chunks)
    lit_chr   = [^; \t"\r\n\\)(];

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
    ipoct     = digit{1,3};
    _ipv4     = ipoct ('.' ipoct){3};
    ipv4      = _ipv4 >token_start %set_ipv4;
    ipv6      = ([a-fA-F0-9:]+ ( ':' _ipv4 )?) >token_start %set_ipv6;

    # NAPTR's text strings
    naptr_txt = (txt_item_255 ws txt_item_255 ws txt_item_255) $1 %0 >start_txt;

    # NAPTR's rdata as a whole
    naptr_rdata = uval %set_uv_1 ws uval %set_uv_2 ws naptr_txt ws dname_rhs;

    rfc3597_octet = ([0-9A-Fa-f]{2}) >token_start %rfc3597_octet;
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
        | ('MX'i    ws uval %set_uv_1 ws dname_rhs) %rec_mx
        | ('TXT'i   ws txt_rdata) %rec_txt
        | ('SRV'i   ws uval %set_uv_1 ws uval %set_uv_2
                    ws uval %set_uv_3 ws dname_rhs) %rec_srv
        | ('NAPTR'i ws naptr_rdata) %rec_naptr
        | ('SOA'i   ws dname_rhs ws dname_eml ws ttl %set_uv_1
                    ws ttl %set_uv_2 ws ttl %set_uv_3 ws ttl %set_uv_4
                    ws ttl %set_uv_5) %rec_soa
        | ('TYPE'i  rfc3597_rdata) %rec_rfc3597
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
        | ('ADDR_LIMIT_V4'i ws uval %set_limit_v4)
        | ('ADDR_LIMIT_V6'i ws uval %set_limit_v6)
    );

    # A zonefile is composed of many resource records
    #  and commands and comments and such...
    statement = rr | cmd;
    main := (statement? ws? ((slc? nl) when !in_paren))*;

    write data;
}%%

static void scanner(zscan_t* z, const char* buf, const size_t bufsize) {
    dmn_assert(z); dmn_assert(buf); dmn_assert(bufsize);

    // This avoids the unfortunately common case of files with final lines
    //   that are unterminated by bailing out early.  This also incidentally
    //   but importantly protects from set_uval()'s strtoul running off the
    //   end of the buffer if we were parsing an integer at that point.
    if(buf[bufsize - 1] != '\n') {
        parse_error_noargs("No newline at end of file");
        return;
    }

    (void)zone_en_main; // silence unused var warning from generated code

    int cs = zone_start;

DMN_DIAG_PUSH_IGNORED("-Wswitch-default")
#ifndef __clang_analyzer__
    // ^ ... because the ragel-generated code for the zonefile parser is
    //   so huge that it makes analyzer runs take forever.
    const char* p = buf;
    const char* pe = buf + bufsize;
    const char* eof = pe;
    %%{ write exec; }%%
#endif // __clang_analyzer__
DMN_DIAG_POP

    if(cs == zone_error)
        parse_error_noargs("General parse error");
    else if(cs < zone_first_final)
        parse_error_noargs("Trailing incomplete or unparseable record at end of file");
}

// This is broken out into a separate function (called via
//   function pointer to eliminate the possibility of
//   inlining on non-gcc compilers, I hope) to avoid issues with
//   setjmp and all of the local auto variables in zscan_rfc1035() below.
typedef bool (*sij_func_t)(zscan_t*,const char*,const unsigned);
F_NONNULL F_NOINLINE
static bool _scan_isolate_jmp(zscan_t* z, const char* buf, const unsigned bufsize) {
    dmn_assert(z); dmn_assert(buf);

    if(!sigsetjmp(z->jbuf, 0)) {
        scanner(z, buf, bufsize);
        return false;
    }
    return true;
}

zscan_rfc1035_status_t zscan_rfc1035(zone_t* zone, const char* fn) {
    dmn_assert(zone);
    dmn_assert(zone->dname);
    dmn_assert(fn);
    log_debug("rfc1035: Scanning zone '%s'", logf_dname(zone->dname));

    gdnsd_fmap_t* fmap = gdnsd_fmap_new(fn, true);
    if(!fmap)
        return ZSCAN_RFC1035_FAILED_FILE;

    zscan_rfc1035_status_t rv = ZSCAN_RFC1035_SUCCESS;

    const size_t bufsize = gdnsd_fmap_get_len(fmap);
    const char* buf = gdnsd_fmap_get_buf(fmap);

    zscan_t* z = xcalloc(1, sizeof(zscan_t));
    z->lcount = 1;
    z->def_ttl = gcfg->zones_default_ttl;
    z->zone = zone;
    dname_copy(z->origin, zone->dname);
    z->lhs_dname[0] = 1; // set lhs to relative origin initially

    sij_func_t sij = &_scan_isolate_jmp;
    if(sij(z, buf, bufsize))
        rv = ZSCAN_RFC1035_FAILED_PARSE;

    if(gdnsd_fmap_delete(fmap))
        rv = ZSCAN_RFC1035_FAILED_FILE;

    if(z->texts) {
        for(unsigned i = 0; i < z->num_texts; i++)
            if(z->texts[i])
                free(z->texts[i]);
        free(z->texts);
    }
    if(z->rfc3597_data)
        free(z->rfc3597_data);
    free(z);

    return rv;
}
