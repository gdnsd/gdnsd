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
#include <gdnsd/dname.h>

#include <gdnsd/dmn.h>
#include <gdnsd/compiler.h>
#include <gdnsd/misc.h>

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

/* The semantics of these functions are described in gdnsd/dname.h ... */

unsigned gdnsd_dns_unescape(char* restrict out, const char* restrict in, const unsigned len) {
    dmn_assert(out); dmn_assert(len);

    char* optr = out;
    for(unsigned i = 0; i < len; i++) {
        if(likely(in[i] != '\\')) {
            *optr++ = in[i];
        }
        else {
            i++;
            if(unlikely(i >= len)) { // dangling escape
                optr = out;
                break;
            }
            if(in[i] <= '9' && in[i] >= '0') {
                if(unlikely( // incomplete numeric escape
                    ((i + 2) >= len)
                    || (in[i + 1] > '9')
                    || (in[i + 1] < '0')
                    || (in[i + 2] > '9')
                    || (in[i + 2] < '0')
                )) {
                    optr = out;
                    break;
                }
                int x = ((in[i++] - '0') * 100);
                x += ((in[i++] - '0') * 10);
                x += (in[i] - '0');
                if(unlikely(x > 255 || x < 0)) { // numeric escape val too large
                    optr = out;
                    break;
                }
                *optr++ = x;
            }
            else {
                *optr++ = in[i];
            }
        }
    }

    return optr - out;
}

gdnsd_dname_status_t gdnsd_dname_from_string(uint8_t* restrict dname, const char* restrict instr, const unsigned len) {
    dmn_assert(dname); dmn_assert(instr || !len);

    // A label can be at most 63 bytes after unescaping,
    //  which means up to 252 bytes while escaped...
    char label_buf[252];

    // If string len is >1004, it cannot possibly decode legally.
    if(len > 1004)
        return DNAME_INVALID;

    // Cursor for writing to the output dname
    uint8_t* dname_cursor = dname;

    // Initialize overall len to account for final byte,
    //  and move cursor to first label start
    *dname_cursor++ = 1;

    // Special-case for len == 0 as an empty partial, just in case.
    //  (rest of the code can't handle len == 0)
    if(!len) {
        *dname_cursor = 255;
        dmn_assert(dname_status(dname) == DNAME_PARTIAL);
        return DNAME_PARTIAL;
    }

    const char* label_start = instr;
    const char* instr_cursor = instr;
    const char* instr_last = instr + len - 1;

    // escape_next is tracking for escaped dots "\.", and
    //  escaped slashes "\\" in the simplest reasonable manner, so that
    //  we can accurately track label boundaries before we fully unescape
    //  the individual labels.
    bool escape_next = false;

    while(1) {
        // Label-terminal conditions, not mutually exclusive:
        const bool end_of_input = instr_cursor == instr_last;
        bool cursor_has_dot = false;

        if(escape_next) {
            escape_next = false;
        }
        else if(*instr_cursor == '\\') {
            escape_next = true;
        }
        else if(*instr_cursor == '.') {
            cursor_has_dot = true;
        }

        // We're mid-label, advance cursor and continue
        if(!cursor_has_dot && !end_of_input) {
            instr_cursor++;
            continue;
        }

        // Raw label length before unescaping
        unsigned raw_llen = instr_cursor - label_start;

        // If we're at string end without a terminal '.',
        //  we must bump the label len by one.
        if(!cursor_has_dot) {
            raw_llen++;
        }
        // ... empty labels can only happen via '.'
        else if(!raw_llen) {
            // Special Case: "." == DNS Root
            if(len == 1) {
                *dname_cursor = 0;
                return DNAME_VALID;
            }

            // Any other empty-label case ("..", "foo..com", etc) is invalid
            return DNAME_INVALID;
        }

        // Raw label too long even before unescaping
        if(raw_llen > 252) return DNAME_INVALID;

        // unescape to label_buf
        unsigned llen = gdnsd_dns_unescape(label_buf, label_start, raw_llen);

        // Label invalid (error return from above)
        if(!llen) return DNAME_INVALID;

        // Label too long
        if(llen > 63) return DNAME_INVALID;

        // Check for domainname overall len overflow
        if(llen + 1U + *dname > 255U) return DNAME_INVALID;

        // normalize case
        gdnsd_downcase_bytes(label_buf, llen);

        // Copy label updating overall length, setting current label length,
        //   and advancing dname_cursor.
        *dname += (llen + 1);
        *dname_cursor++ = llen;
        memcpy(dname_cursor, label_buf, llen);
        dname_cursor += llen;

        // If this was the end of the whole input string we're done
        if(end_of_input) {
            if(cursor_has_dot) {
                *dname_cursor = 0;
                dmn_assert(dname_status(dname) == DNAME_VALID);
                return DNAME_VALID;
            }
            else {
                *dname_cursor = 255;
                dmn_assert(dname_status(dname) == DNAME_PARTIAL);
                return DNAME_PARTIAL;
            }
        }

        // Advance instr_cursor while resetting label_start
        label_start = ++instr_cursor;
    }
}

unsigned gdnsd_dname_to_string(const uint8_t* restrict dname, char* restrict str) {
    dmn_assert(dname);
    dmn_assert(dname_status(dname) != DNAME_INVALID);

    const char* str_base = str; // for output length later
    dname++; // skip overall length byte, we don't use it here

    unsigned llen; // label len
    while((llen = *dname++) && llen != 255U) {
        // output "label."
        for(uint8_t i = 0; i < llen; i++) {
            char x = (char)*dname++;
            if(x > 0x20 && x < 0x7F) {
                *str++ = x;
            }
            else {
                *str++ = '\\';
                *str++ = '0' + (x / 100);
                *str++ = '0' + ((x / 10) % 10);
                *str++ = '0' + (x % 10);
            }
        }
        *str++ = '.';
    }

    // In the special case that logf_dname() was called on a DNAME_PARTIAL
    //   we need to undo any final dot added at the end of the last loop above
    if(llen == 255U && str > str_base)
        str--;
    *str++ = '\0';

    dmn_assert(str > str_base);
    return (unsigned)(str - str_base);
}

gdnsd_dname_status_t gdnsd_dname_cat(uint8_t* restrict dn1, const uint8_t* restrict dn2) {
    dmn_assert(dname_status(dn1) != DNAME_INVALID);
    dmn_assert(dname_status(dn2) != DNAME_INVALID);

    gdnsd_dname_status_t rv = DNAME_INVALID;
    const unsigned dn1_len = *dn1;
    const unsigned dn2_len = *dn2;
    const unsigned final_len = (dn1_len + dn2_len - 1);

    if(final_len < 256) {
        dn1[0] = final_len;
        memcpy(dn1 + dn1_len, dn2 + 1, dn2_len);
        rv = (dn1[final_len] == 0) ? DNAME_VALID : DNAME_PARTIAL;
    }

    return rv;
}

gdnsd_dname_status_t gdnsd_dname_status(const uint8_t* dname) {
    dmn_assert(dname);

    // over-all length zero is invalid
    const unsigned oal = *dname++;
    if(!oal)
        return DNAME_INVALID;

    const uint8_t* dnptr = dname;
    unsigned llen;

    // Step by-label until we reach llen==0 (end of fqdn)
    //   or llen==255 (DNAME_PARTIAL).
    while((llen = *dnptr++) && llen != 255) {
        dnptr += llen;
        if(&dname[oal] <= dnptr)
            return DNAME_INVALID; // tried to run off the end!
    }

    // We came up short (hit terminal label-len byte before running
    //   out of overall length)
    if(&dname[oal] > dnptr)
        return DNAME_INVALID;

    dmn_assert(&dname[oal] == dnptr);

    return llen ? DNAME_PARTIAL : DNAME_VALID;
}

uint32_t gdnsd_dname_hash(const uint8_t *k) {
    dmn_assert(k);

    const uint32_t len = *k++ - 1U;
    return gdnsd_lookup2(k, len);
}
