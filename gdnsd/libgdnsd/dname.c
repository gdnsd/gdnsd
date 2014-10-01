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

#include "config.h"

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include <gdnsd/dmn.h>
#include <gdnsd/compiler.h>
#include <gdnsd/misc.h>
#include <gdnsd/dname.h>

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
                unsigned x = ((in[i++] - '0') * 100);
                x += ((in[i++] - '0') * 10);
                x += (in[i] - '0');
                if(unlikely(x > 255)) { // numeric escape val too large
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

gdnsd_dname_status_t gdnsd_dname_from_raw(uint8_t* restrict dname, const uint8_t* restrict raw) {
    unsigned offset = 0;
    unsigned llen;
    while((llen = raw[offset])) {
        llen++; // include len byte itself
        if(offset + llen > 254)
            return DNAME_INVALID;
        memcpy(&dname[offset + 1], &raw[offset], llen);
        offset += llen;
    }
    dname[++offset] = 0;
    dname[0] = offset;

    return DNAME_VALID;
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

    unsigned cur_oal = 1; // for terminal \0 or 255

    while(1) {
        // Get next label len (or terminal byte)
        const unsigned llen = *dname;

        // End of input
        if(oal == cur_oal) {
            if(!llen)
                return DNAME_VALID;
            if(llen == 255)
                return DNAME_PARTIAL;
            else
                return DNAME_INVALID;
        }

        // Update cur_oal
        cur_oal++;
        cur_oal += llen;

        // check oal overflow (label ran off end)
        if(cur_oal > oal)
            return DNAME_INVALID;

        // advance dname to next len byte (or terminal byte)
        dname++;
        dname += llen;
    }

    return DNAME_VALID;
}

bool gdnsd_dname_isinzone(const uint8_t* zone, const uint8_t* dname) {
    dmn_assert(zone); dmn_assert(dname);
    dmn_assert(dname_status(zone) == DNAME_VALID);
    dmn_assert(dname_status(dname) == DNAME_VALID);

    const unsigned plen = *zone++;
    const unsigned clen = *dname++;

    if(plen <= clen) {
        int ldiff = clen - plen;
        dmn_assert(ldiff > -1);
        if(!memcmp(dname + ldiff, zone, plen)) {
            while(ldiff > 0) {
                ldiff--;
                const unsigned cllen = *dname++;
                dname += cllen;
                ldiff -= cllen;
            }
            if(ldiff == 0) return true;
        }
    }

    return false;
}

bool gdnsd_dname_isparentof(const uint8_t* parent, const uint8_t* child) {
    dmn_assert(parent); dmn_assert(child);
    dmn_assert(dname_status(parent) == DNAME_VALID);
    dmn_assert(dname_status(child) == DNAME_VALID);

    const unsigned plen = *parent++;
    const unsigned clen = *child++;

    if(plen < clen) {
        int ldiff = clen - plen;
        dmn_assert(ldiff > 0);
        if(!memcmp(child + ldiff, parent, plen)) {
            while(ldiff > 0) {
                ldiff--;
                const unsigned cllen = *child++;
                child += cllen;
                ldiff -= cllen;
            }
            if(ldiff == 0) return true;
        }
    }

    return false;
}

uint32_t gdnsd_dname_hash(const uint8_t *k) {
    dmn_assert(k);

    const uint32_t len = *k++ - 1;
    return gdnsd_lookup2((const char*)k, len);
}
