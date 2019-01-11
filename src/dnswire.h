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

#include <gdnsd/compiler.h>

#include <inttypes.h>
#include <arpa/inet.h>

// Our UDP input buffers are shared with output buffer space, and the output
// buffer size is 16K.
// However, we only advertise a buffer size of 1024, to be absolutely sure that
// even in the face of an IPv6 min-MTU link and lots of extra headers and
// whatnot, it will always be a single fragment.
// We use this size as our recvmsg() limit as well, discarding anything larger
// to save ourselves processing it.  And in the TCP case, we immediately close
// if a size greater than this is sent as the message length field.
#define DNS_EDNS_SIZE 1024U
#define DNS_RECV_SIZE DNS_EDNS_SIZE

// Sizes our output buffers, we never generate packets longer than this.
// This can't be changed arbitrarily to another number by editing the define
// here, as the 16K boundary has other magic effects (e.g. on DNS compression).
#define MAX_RESPONSE_BUF 16384U

// EDNS Padding block size from RFC 8467
#define PAD_BLOCK_SIZE 468U

// This is similar to MAX_RESPONSE_BUF, but for checking real data output
// lengths, so that there's always room within MAX_RESPONSE_BUF to pad to a
// multiple of 468 bytes for EDNS Padding, which has a min padding size of 4
// bytes: (468*35 - 4) = 16376
#define MAX_RESPONSE_DATA 16376U

/*** Wire formats ***/

/* DNS Header */
typedef struct S_PACKED {
    uint16_t id;
    uint8_t flags1;
    uint8_t flags2;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} wire_dns_header_t;

/* macros to pull data from wire_dns_header */
#define DNSH_GET_ID(_h)      (ntohs((_h)->id))
#define DNSH_GET_QR(_h)      ((_h)->flags1 & 0x80)
#define DNSH_GET_OPCODE(_h)  (((_h)->flags1 & 0x78) >> 3)
#define DNSH_GET_AA(_h)      ((_h)->flags1 & 0x04)
#define DNSH_GET_TC(_h)      ((_h)->flags1 & 0x02)
#define DNSH_GET_RD(_h)      ((_h)->flags1 & 0x01)
#define DNSH_GET_RA(_h)      ((_h)->flags2 & 0x80)
// Reserved: #define DNSH_GET_XXXXXX(_h)  ((_h)->flags2 & 0x40)
#define DNSH_GET_AD(_h)      ((_h)->flags2 & 0x20)
#define DNSH_GET_CD(_h)      ((_h)->flags2 & 0x10)
#define DNSH_GET_RCODE(_h)   ((_h)->flags2 & 0x0F)
#define DNSH_GET_QDCOUNT(_h) (ntohs((_h)->qdcount))
#define DNSH_GET_ANCOUNT(_h) (ntohs((_h)->ancount))
#define DNSH_GET_NSCOUNT(_h) (ntohs((_h)->nscount))
#define DNSH_GET_ARCOUNT(_h) (ntohs((_h)->arcount))

/* DNS Response Codes */
#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_FORMERR 1
#define DNS_RCODE_SRVFAIL 2
#define DNS_RCODE_NXDOMAIN 3
#define DNS_RCODE_NOTIMP 4
#define DNS_RCODE_REFUSED 5
#define DNS_EXT_RCODE_BADVERS 1

// EDNS option codes
#define EDNS_NSID_OPTCODE          0x0003
#define EDNS_CLIENTSUB_OPTCODE     0x0008
#define EDNS_COOKIE_OPTCODE        0x000A
#define EDNS_TCP_KEEPALIVE_OPTCODE 0x000B
#define EDNS_PADDING               0x000C

/* DNS RR Types */
#define DNS_TYPE_A 1U
#define DNS_TYPE_NS 2U
#define DNS_TYPE_CNAME 5U
#define DNS_TYPE_SOA 6U
#define DNS_TYPE_PTR 12U
#define DNS_TYPE_HINFO 13U
#define DNS_TYPE_MX 15U
#define DNS_TYPE_TXT 16U
#define DNS_TYPE_AAAA 28U
#define DNS_TYPE_SRV 33U
#define DNS_TYPE_NAPTR 35U
#define DNS_TYPE_OPT 41U
#define DNS_TYPE_IXFR 251U
#define DNS_TYPE_AXFR 252U
#define DNS_TYPE_ANY 255U

#define DNS_CLASS_IN 1U
#define DNS_CLASS_CH 3U
#define DNS_CLASS_ANY 255U

// Our own synthetic 'type' for DYNC
//   Note that current standards mark
//   the range 0xFF00 -> 0xFFFF for
//   "private use".  We never intend
//   to read this from or write this
//   to packets on the wire, it's just
//   for the internal database...
#define DNS_TYPE_DYNC    0xFF0F

/* Network-order TYPE+CLASS as a 32-bit uint */

#define _mkrrf(_t) ((uint32_t)htonl(_t << 16 | DNS_CLASS_IN))
#define DNS_RRFIXED_A     _mkrrf(DNS_TYPE_A)
#define DNS_RRFIXED_NS    _mkrrf(DNS_TYPE_NS)
#define DNS_RRFIXED_CNAME _mkrrf(DNS_TYPE_CNAME)
#define DNS_RRFIXED_SOA   _mkrrf(DNS_TYPE_SOA)
#define DNS_RRFIXED_PTR   _mkrrf(DNS_TYPE_PTR)
#define DNS_RRFIXED_MX    _mkrrf(DNS_TYPE_MX)
#define DNS_RRFIXED_TXT   _mkrrf(DNS_TYPE_TXT)
#define DNS_RRFIXED_AAAA  _mkrrf(DNS_TYPE_AAAA)
#define DNS_RRFIXED_SRV   _mkrrf(DNS_TYPE_SRV)
#define DNS_RRFIXED_NAPTR _mkrrf(DNS_TYPE_NAPTR)
#define DNS_RRFIXED_OPT   _mkrrf(DNS_TYPE_OPT)

#endif // GDNSD_DNSWIRE_H
