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

#ifndef GDNSD_DNSWIRE_H
#define GDNSD_DNSWIRE_H

#include "config.h"
#include "gdnsd/compiler.h"
#include <inttypes.h>

// Our UDP input buffers are shared with output buffer
//  space, and the output buffer size in turn has
//  a minimum size of 4K, default 16K.
// However, we only advertise a buffer size of 1280 (IPv6
//  Min MTU) via EDNS0.
// We use this size as our recvmsg() limit as well,
//  discarding anything larger to save ourselves
//  processing it.  Really, we could even advertise
//  512 here since, we don't support anything
//  that warrants larger input sizes, but this is
//  reasonable.
#define DNS_EDNS0_SIZE 1280U
#define DNS_RECV_SIZE DNS_EDNS0_SIZE

/*** Wire formats ***/

/* DNS Header */
typedef struct {
    uint16_t id;
    uint8_t flags1;
    uint8_t flags2;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} wire_dns_header_t;

/* DNS RR fixed part (generic) */
typedef struct {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    // left out rdatalen, but don't forget it in code: uint16_t rdata_len;
} wire_dns_rr_fixed_t;

/* DNS OPT RR for EDNS0 */
/* (for basic EDNS0, it's a fixed structure) */
/* Note the initial one-bye NULL domainname
 * is left out */
typedef struct {
    uint16_t type;
    uint16_t maxsize;
    uint32_t extflags;
    uint16_t rdlen;
    uint8_t  rdata[0];
} wire_dns_rr_opt_t;

// Use this for the size of the above, so that
//  the compiler's final 2 bytes of padding are
//  not counted, and only counts the fixed part.
//  (not the initial \0 label, and none of rdata).
#define sizeof_optrr 10

/* macros to pull data from wire_dns_header */
#define DNSH_GET_ID(_h)      (ntohs(gdnsd_get_una16(&(_h)->id)))
#define DNSH_GET_QR(_h)      ((_h)->flags1 & 0x80)
// technically one must >> 3 to get the real opcode
//  but we only really care whether it's zero or not
#define DNSH_GET_OPCODE(_h)  ((_h)->flags1 & 0x78)
#define DNSH_GET_AA(_h)      ((_h)->flags1 & 0x04)
#define DNSH_GET_TC(_h)      ((_h)->flags1 & 0x02)
#define DNSH_GET_RD(_h)      ((_h)->flags1 & 0x01)
#define DNSH_GET_RA(_h)      ((_h)->flags2 & 0x80)
#define DNSH_GET_AD(_h)      ((_h)->flags2 & 0x20)
#define DNSH_GET_CD(_h)      ((_h)->flags2 & 0x10)
#define DNSH_GET_RCODE(_h)   ((_h)->flags2 & 0x0F)
#define DNSH_GET_QDCOUNT(_h) (ntohs(gdnsd_get_una16(&(_h)->qdcount)))
#define DNSH_GET_ANCOUNT(_h) (ntohs(gdnsd_get_una16(&(_h)->ancount)))
#define DNSH_GET_NSCOUNT(_h) (ntohs(gdnsd_get_una16(&(_h)->nscount)))
#define DNSH_GET_ARCOUNT(_h) (ntohs(gdnsd_get_una16(&(_h)->arcount)))

/* DNS Response Codes */
#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_FORMERR 1
#define DNS_RCODE_SRVFAIL 2
#define DNS_RCODE_NXDOMAIN 3
#define DNS_RCODE_NOTIMP 4
#define DNS_RCODE_REFUSED 5
#define DNS_EXT_RCODE_BADVERS 1

/* Macros to pull data from wire_dns_rr_opt */
#define DNS_OPTRR_GET_TYPE(_r)     (ntohs(gdnsd_get_una16(&(_r)->type)))
#define DNS_OPTRR_GET_MAXSIZE(_r)  (ntohs(gdnsd_get_una16(&(_r)->maxsize)))
#define DNS_OPTRR_GET_EXTRCODE(_r) ((uint8_t)(ntohl(gdnsd_get_una32(&(_r)->extflags)) >> 24))
#define DNS_OPTRR_GET_VERSION(_r)  ((uint8_t)((ntohl(gdnsd_get_una32(&(_r)->extflags)) & 0x00FF0000) >> 16))

// NOT ASSIGNED BY IANA!:
#define EDNS_CLIENTSUB_OPTCODE 0x50fa

/* DNS RR Types */
#define DNS_TYPE_A	1
#define DNS_TYPE_NS	2
#define DNS_TYPE_CNAME	5
#define DNS_TYPE_SOA	6
#define DNS_TYPE_PTR	12
#define DNS_TYPE_MX	15
#define DNS_TYPE_TXT	16
#define DNS_TYPE_AAAA	28
#define DNS_TYPE_SRV	33
#define DNS_TYPE_NAPTR	35
#define DNS_TYPE_OPT	41
#define DNS_TYPE_SPF	99
#define DNS_TYPE_IXFR   251
#define DNS_TYPE_AXFR   252
#define DNS_TYPE_ANY    255

#define DNS_CLASS_IN	1
#define DNS_CLASS_ANY	255

/* Network-order TYPE+CLASS as a 32-bit uint */

#ifdef WORDS_BIGENDIAN
#define _mkrrf(_t,_c) (((_t)<<16)|(_c))
#else
#define _mkrrf(_t,_c) (((_t)<<8)|((_c)<<24))
#endif

static const uint32_t DNS_RRFIXED_A     = _mkrrf(DNS_TYPE_A, DNS_CLASS_IN);
static const uint32_t DNS_RRFIXED_NS    = _mkrrf(DNS_TYPE_NS, DNS_CLASS_IN);
static const uint32_t DNS_RRFIXED_CNAME = _mkrrf(DNS_TYPE_CNAME, DNS_CLASS_IN);
static const uint32_t DNS_RRFIXED_SOA   = _mkrrf(DNS_TYPE_SOA, DNS_CLASS_IN);
static const uint32_t DNS_RRFIXED_PTR   = _mkrrf(DNS_TYPE_PTR, DNS_CLASS_IN);
static const uint32_t DNS_RRFIXED_MX    = _mkrrf(DNS_TYPE_MX, DNS_CLASS_IN);
static const uint32_t DNS_RRFIXED_TXT   = _mkrrf(DNS_TYPE_TXT, DNS_CLASS_IN);
static const uint32_t DNS_RRFIXED_AAAA  = _mkrrf(DNS_TYPE_AAAA, DNS_CLASS_IN);
static const uint32_t DNS_RRFIXED_SRV   = _mkrrf(DNS_TYPE_SRV, DNS_CLASS_IN);
static const uint32_t DNS_RRFIXED_NAPTR = _mkrrf(DNS_TYPE_NAPTR, DNS_CLASS_IN);
static const uint32_t DNS_RRFIXED_OPT   = _mkrrf(DNS_TYPE_OPT, DNS_CLASS_IN);
static const uint32_t DNS_RRFIXED_SPF   = _mkrrf(DNS_TYPE_SPF, DNS_CLASS_IN);

#endif // GDNSD_DNSWIRE_H
