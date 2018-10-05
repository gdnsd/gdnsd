/* Copyright © 2016 Brandon L Black <blblack@gmail.com>
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

#ifndef GDNSD_CS_H
#define GDNSD_CS_H

#include <gdnsd/compiler.h>
#include <gdnsd/log.h>

#include <inttypes.h>

typedef union {
    char raw[8];
    struct {
        char key;
        uint8_t v0;
        uint8_t v1;
        uint8_t v2;
        uint32_t d;
    };
} csbuf_t;

F_UNUSED F_CONST
static uint32_t csbuf_make_v(uint8_t v0, uint8_t v1, uint8_t v2)
{
    return (uint32_t) v0 << 16 | (uint32_t) v1 << 8 | (uint32_t) v2;
}

F_UNUSED F_NONNULL
static uint32_t csbuf_get_v(const csbuf_t* c)
{
    return csbuf_make_v(c->v0, c->v1, c->v2);
}

F_UNUSED F_NONNULL
static void csbuf_set_v(csbuf_t* c, const uint32_t v)
{
    gdnsd_assert(!(v & 0xFF000000));
    c->v0 = v >> 16;
    c->v1 = v >> 8;
    c->v2 = v;
}

// Legal values for "key"
#define REQ_TAK1  '1'
#define REQ_TAK2  '2'
#define RESP_ACK  'A'
#define REQ_CHALF 'c'
#define REQ_CHAL  'C'
#define REQ_STATE 'E'
#define RESP_FAIL 'F'
#define RESP_LATR 'L'
#define REQ_INFO  'I'
#define REQ_REPL  'R'
#define REQ_STAT  'S'
#define REQ_SHAND 's'
#define REQ_TAKE  'T'
#define RESP_UNK  'U'
#define REQ_STOP  'X'
#define REQ_ZREL  'Z'

// AFAIK there's no portable way to know the max FDs that can be sent in an
// SCM_RIGHTS message.  I only know the Linux limit for sure, so in the
// non-Linux case I'm picking a fairly conservative value of 32 for now.
#ifdef __linux__
#  define SCM_MAX_FDS 253U
#else
#  define SCM_MAX_FDS 32U
#endif

#endif // GDNSD_CS_H
