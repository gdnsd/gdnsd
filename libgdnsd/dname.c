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

#include <gdnsd/compiler.h>
#include <gdnsd/misc.h>

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

/* The semantics of these functions are described in gdnsd/dname.h ... */

unsigned gdnsd_dns_unescape(char* restrict out, const char* restrict in, const unsigned len)
{
    gdnsd_assert(len);

    char* optr = out;
    for (unsigned i = 0; i < len; i++) {
        if (likely(in[i] != '\\')) {
            *optr++ = in[i];
        } else {
            i++;
            // check: dangling escape
            if (unlikely(i >= len))
                return 0;
            // check: incomplete numeric escape
            if (in[i] <= '9' && in[i] >= '0') {
                if (unlikely(((i + 2) >= len)
                             || (in[i + 1] > '9')
                             || (in[i + 1] < '0')
                             || (in[i + 2] > '9')
                             || (in[i + 2] < '0')
                            ))
                    return 0;
                int x = ((in[i++] - '0') * 100);
                x += ((in[i++] - '0') * 10);
                x += (in[i] - '0');
                // check: numeric escape val too large
                if (unlikely(x > 255 || x < 0))
                    return 0;
                *optr++ = x;
            } else {
                *optr++ = in[i];
            }
        }
    }

    return optr - out;
}


// As above, but checks label-specific conditions as well, and downcases the
// output if the length looks legit.  Output buffer should be 252 bytes long,
// although final output len in legit cases will never be more than 63.
F_NONNULL
static unsigned gdnsd_dns_unescape_label(char* restrict out, const char* restrict in, const unsigned len)
{
    unsigned rv = 0;
    // Even if full of escapes, input llen > 252 means output label is illegally long
    if (len <= 252) {
        rv = gdnsd_dns_unescape(out, in, len);
        if (rv <= 63) // max legal label len
            gdnsd_downcase_bytes(out, rv);
        else
            rv = 0;
    }
    return rv;
}

gdnsd_dname_status_t gdnsd_dname_from_string(uint8_t* restrict dname, const char* restrict instr, const unsigned len)
{
    // If string len is >1004, it cannot possibly decode legally.
    if (len > 1004)
        return DNAME_INVALID;

    // Cursor for writing to the output dname
    uint8_t* dname_cursor = dname;

    // Initialize overall len to account for final byte,
    //  and move cursor to first label start
    *dname_cursor++ = 1;

    // Special-case for len == 0 as an empty partial, just in case.
    //  (rest of the code can't handle len == 0)
    if (!len) {
        *dname_cursor = 255;
        gdnsd_assert(dname_status(dname) == DNAME_PARTIAL);
        return DNAME_PARTIAL;
    }

    // Special case for root of DNS
    if (len == 1 && instr[0] == '.') {
        *dname_cursor = 0;
        return DNAME_VALID;
    }

    // escape_next is tracking for escaped dots "\.", and
    //  escaped slashes "\\" in the simplest reasonable manner, so that
    //  we can accurately track label boundaries before we fully unescape
    //  the individual labels.
    bool escape_next = false;

    const unsigned last_char = len - 1;
    bool cursor_has_dot = false;
    unsigned label_start = 0;
    for (unsigned i = 0; i < len; i++) {
        // Raw label length before unescaping, without the terminal dot,
        // assuming we're at the end of a label so-terminated.
        unsigned raw_llen = i - label_start;

        char c = instr[i];
        cursor_has_dot = false;
        if (escape_next)
            escape_next = false;
        else if (c == '\\')
            escape_next = true;
        else if (c == '.')
            cursor_has_dot = true;

        // No unescaped dot at this position
        if (!cursor_has_dot) {
            // If we're looking at the final char, we need to process the final
            // label, so increase the raw_llen to cover the final real label
            // data byte since there's no dot to avoid, and fall into the
            // bottom of the loop as if we'd otherwise seen a terminal dot
            if (i == last_char)
                raw_llen++;
            // Else we're just mid-label and need to loop again until we find
            // the end of the label or input
            else
                continue;
        }

        // Empty labels are invalid (root case handled outside of loop)
        if (!raw_llen)
            return DNAME_INVALID;

        // unescape+downcase to label_buf with basic checks for length issues
        char label_buf[252];
        unsigned llen = gdnsd_dns_unescape_label(label_buf, &instr[label_start], raw_llen);
        if (!llen)
            return DNAME_INVALID;

        // Check for domainname overall len overflow
        if (llen + 1U + *dname > 255U)
            return DNAME_INVALID;

        // Copy label updating overall length, setting current label length,
        //   and advancing dname_cursor.
        *dname += (llen + 1);
        *dname_cursor++ = llen;
        memcpy(dname_cursor, label_buf, llen);
        dname_cursor += llen;

        // Reset label start for next label (doesn't matter if we're at end already)
        label_start = i + 1;
    }

    // Final byte must be 0 or 255 depending on whether the dname was fully
    // qualified with a terminal dot:

    if (!cursor_has_dot) {
        *dname_cursor = 255;
        gdnsd_assert(dname_status(dname) == DNAME_PARTIAL);
        return DNAME_PARTIAL;
    }

    *dname_cursor = 0;
    gdnsd_assert(dname_status(dname) == DNAME_VALID);
    return DNAME_VALID;
}

unsigned gdnsd_dname_to_string(const uint8_t* restrict dname, char* restrict str)
{
    gdnsd_assert(dname_status(dname) != DNAME_INVALID);

    const char* str_base = str; // for output length later
    dname++; // skip overall length byte, we don't use it here

    unsigned llen; // label len
    while ((llen = *dname++) && llen != 255U) {
        // output "label."
        for (uint8_t i = 0; i < llen; i++) {
            char x = (char)(*dname++);
            if (x > 0x20 && x < 0x7F) {
                *str++ = x;
            } else {
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
    if (llen == 255U && str > str_base)
        str--;
    *str++ = '\0';

    gdnsd_assert(str > str_base);
    return (unsigned)(str - str_base);
}

gdnsd_dname_status_t gdnsd_dname_cat(uint8_t* restrict dn1, const uint8_t* restrict dn2)
{
    gdnsd_assert(dname_status(dn1) != DNAME_INVALID);
    gdnsd_assert(dname_status(dn2) != DNAME_INVALID);

    gdnsd_dname_status_t rv = DNAME_INVALID;
    const unsigned dn1_len = *dn1;
    const unsigned dn2_len = *dn2;
    const unsigned final_len = (dn1_len + dn2_len - 1);

    if (final_len < 256) {
        dn1[0] = final_len;
        memcpy(dn1 + dn1_len, dn2 + 1, dn2_len);
        rv = (dn1[final_len] == 0) ? DNAME_VALID : DNAME_PARTIAL;
    }

    return rv;
}

gdnsd_dname_status_t gdnsd_dname_status(const uint8_t* dname)
{
    // over-all length zero is invalid
    const unsigned oal = *dname++;
    if (!oal)
        return DNAME_INVALID;

    const uint8_t* dnptr = dname;
    unsigned llen;

    // Step by-label until we reach llen==0 (end of fqdn)
    //   or llen==255 (DNAME_PARTIAL).
    while ((llen = *dnptr++) && llen != 255) {
        dnptr += llen;
        if (&dname[oal] <= dnptr)
            return DNAME_INVALID; // tried to run off the end!
    }

    // We came up short (hit terminal label-len byte before running
    //   out of overall length)
    if (&dname[oal] > dnptr)
        return DNAME_INVALID;

    gdnsd_assert(&dname[oal] == dnptr);

    return llen ? DNAME_PARTIAL : DNAME_VALID;
}
