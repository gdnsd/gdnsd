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

#include "gdnsd-dmn.h"
#include "gdnsd-compiler.h"
#include "gdnsd-misc.h"
#include "gdnsd-dname.h"

/* The semantics of these functions are described in gdnsd-dname.h ... */

// Map uppercase ASCII to lowercase while preserving other bytes.
static const uint8_t lcmap[256] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
  0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
  0x40,

// The part that really matters:
//  0x41-0x5A (A-Z) => 0x61->0x7A (a-z)

        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
  0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
  0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
  0x78, 0x79, 0x7A,

                    0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
  0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
  0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
  0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
  0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
  0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
  0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
  0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
  0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
  0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
  0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
  0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
  0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
  0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
  0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
  0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
  0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
  0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
  0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
  0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
};

static void map_lc(uint8_t* data, unsigned len) {
    for(unsigned i = 0; i < len; i++)
        data[i] = lcmap[data[i]];
}

unsigned gdnsd_dns_unescape(uint8_t* restrict out, const uint8_t* restrict in, const unsigned len) {
    dmn_assert(out); dmn_assert(len);

    uint8_t* optr = out;
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
                *optr++ = (uint8_t)x;
            }
            else {
                *optr++ = in[i];
            }
        }
    }

    return optr - out;
}

gdnsd_dname_status_t gdnsd_dname_from_string(uint8_t* restrict dname, const uint8_t* restrict instr, const unsigned len) {
    dmn_assert(dname); dmn_assert(instr || !len);

    // A label can be at most 63 bytes after unescaping,
    //  which means up to 252 bytes while escaped...
    uint8_t label_buf[252];

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

    const uint8_t* label_start = instr;
    const uint8_t* instr_cursor = instr;
    const uint8_t* instr_last = instr + len - 1;

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
        map_lc(label_buf, llen);

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
