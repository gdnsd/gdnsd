# DNSSEC Implementation Notes

A basic understanding of DNSSEC is a prerequisite for reading this!

[TODO] Because our DNSSEC support is still very much in the prototype phase,
some of the items here are marked [TODO] because it's something I think I've
decided on, but haven't implemented yet!

[TODO] We should probably also have a separate doc that acts as a basic users'
guide to DNSSEC configuration and management with gdnsd.  This doc isn't that,
it's more of a detailed deep dive into implementation details!

## Keys, Algorithms, and Signing

### Keys

- Key management of any kind is unsupported in this early prototyping phase.
- All ZSKs are Combined ZSKs with SEP; there is no support for separate KSKs.
- All ZSKs are ephemeral and are uniquely auto-generated per zone each time it is (re-)loaded.  ZSKs are created by the statements `$BREAK_MY_ZONE_ED25519` and/or `$BREAK_MY_ZONE_P256` in a zonefile, which can be specified multiple times to test multi-ZSK arrangements.
- A DNSKEY RRSet is auto-generated at the zone apex, with one DNSKEY per auto-generated ZSK, and the whole set signed by all ZSKs (as are all the other records in the zone).
- [TODO] Support external key management with KSK/ZSK splitting, where the external tool creates the zone apex DNSKEY RRSet and its signature (but does not sign the rest of the zone, I think).  We'll still require an online ZSK private which matches one of the DNSKEYs, to use for our online signing.

### Algorithms

- Only ED25519 and ECDSAP256SHA256 zone signing keys are supported.
- Ed25519 support comes from libsodium.  It's fast, light, simple, and deterministic, and should be used when possible!
- P256 can be optionally provided by libgnutls (>= 3.6.10).  If not built with libgnutls, then only ED25519 is available.
- The config option `dnssec_deterministic_ecdsa` can be set to use the deterministic variant of P256 from RFC 6979 (which gives consistent outputs for the same signed data every time and isn't susceptible to RNG flaws), as recommended by RFC 8624 for DNSSEC.

A benchmarking tool `gdnsd_dnssec_bench` is included to test the approximate single-threaded signing speeds on your own machine with your own build of gdnsd and the relevant libraries.  A sample output from my laptop with both libraries:

    $ src/gdnsd_dnssec_bench -i 100000 -s 256
    Benchmark: 100000 iterations signing 256 byte messages:
    Alg: Ed25519 (libsodium, deterministic)  Rate: 40.045/ms
    Alg: P256 (libgnutls, non-deterministic) Rate: 14.171/ms
    Alg: P256 (libgnutls, deterministic)     Rate: 13.094/ms

### Signing

- gdnsd doesn't support truly-offline signing.  It only does online signing and thus requires runtime access to the private part of any ZSKs.
- gdnsd's online signatures are, for most cases, pre-generated when a zone is loaded, sort of like a last-minute offline signing operation that happens in memory only.
- [TODO] A timer will force a reload of zone data in order to regenerate RRSIGs if no natural, user-driven reload happens within a reasonable margin of RRSIG expiry (meaning they haven't reloaded in weeks, I think).  There's still a lot of things to work out about this so that we don't hand users footguns, but we can't just let stale, expired RRSIGs persist either.

- There are some cases in which truly-online signing happens:
- NXDomain cases cause online signing, and will be covered in more detail later in this document.
- [TODO] Ephemeral ACME challenge TXT records are signed on creation, and re-signed on zone reloads.

## Positive responses from signed zones

- RRSIGs are emitted just after any authoritative RRSet if the query has the DO (DNSSEC OK) bit.
- DS record parsing works, and it supports arbitrary future digest algorithm numbers with up to 64 bytes of digest data.  It does enforce correct digest lengths for the types that are already known at this time.
- Secure delegation DO-bit responses from signed zones return unsigned NS and a signed DS in the auth section and necessary, unsigned glue in the additional section.
- Insecure delegation DO-bit responses from signed zones return unsigned NS and a signed NSEC with typemask `NS NSEC RRIG` in the auth section (and unsigned glue as above).
- QTYPE=DS queries at a delegation point in a signed zone return the signed DS or NSEC from above in the answer section as authoritative, with an AA-bit too.  Even for non-DO-bit queries we return auth data for an unsigned DS if it exists (but do not emit NSEC if it doesn't).
- Non-DO-bit delegation responses return a standard legacy delegation whether or not the zone is signed.
- QTYPE=ANY - For extant names in signed zones, we respond with an accurately-typed NSEC record (signed if DO-bit query, unsigned otherwise).  For unsigned zones, we continue to respond with RFC 8482's HINFO strategy.
- QTYPE=NSEC - If the queried name in a signed zone has a CNAME RR, we will return the node's NSEC rather than the CNAME.
- QTYPE=RRSIG - We return REFUSED in the case of an extant name in a signed zone, if the DO bit is set.  For all other cases, qtype=RRSIG will just return NOERROR or NXDOMAIN as appropriate with no data.  RRSIG doesn't exist as a separately-queryable RRSet in our data structures.
- [TODO] Zonefile parser also supports DNSKEY, CDNSKEY, CDS, RRSIG (probably only for DNSKEY) - all for key management purposes.

## Wildcards

Currently, wildcards are disallowed in signed zones.  I haven't found a design
direction on this that I'm happy with, and I'm not confident that there's any
great strategy to balance online signing and wildcard support in a way that
doesn't have some significant DoS risks.  We could trivially implement handling
them with the the same caching and ratelimiting scheme as NXDOMAINs, but the
no-response failure mode when ratelimited would potentially harm useful queries
when under attack, unlike in the NXDOMAIN case.  We may have to just implement
that with a great big warning, or as an option that has to be turned on
explicitly (and perhaps with separated cache and limiter state).

## Negative Responses

Here, I think we have to get a bit more expository in laying out the current
state of affairs with DNSSEC Negative Responses and all the prior work before
delving into our specific solution.  If you're already fully versed in the
various online-signing negative response schemes already, you can skip over the
"History" section below and fast-forward to "Observations".

### History

[at least, a sort of reductionist alternate history that makes enough sense for
our explanatory purpose, and starts at RFC40[345]]

#### Basic original NSEC

Basic RFC 403[345] -level DNSSEC had only NSEC records, and specified that
NSECs formed a chain from one real name to the next, denying the existence of
those names that fell between them, according to a complex sort order of all
the hypothetical namespace beneath a zone apex.  `a NSEC d` proves that both
`a` and `d` exist, and also proves that `b` and `c` do not.  NSEC also carries
a type mask which hands out information about which RR types are or aren't
present at `a`, which is used in NOERROR empty responses for `a` to prove that
certain types don't exist, but it's the chain-of-names part that's far more
interesting and tricky.

There's one other important point here, which is that NXDOMAIN responses
actually require up to two NSEC records to disprove the existence of a name:
one is an NSEC chain record covering the name itself, and the other is one that
covers the wildcard that could've been used to synthesize the response.
Sometimes one NSEC covers both names, and sometimes it doesn't.

After some realization that (a) this made remote zone contents enumeration
super-easy and this makes some zone owners uncomfortable and (b) NSEC chains
were a difficult proposition for online signers with potentially very dynamic
zone data, some efforts were spawned to address these concerns.

#### NSEC3

One was NSEC3.  This replaced the chain-of-names with a chain-of-hashed-names,
sorted by the hash order rather than the orignal name order.  It was thought
that hashing the names would stop the zone contents enumeration leak.  This
scheme also requires a new meta-RR called NSEC3PARAM to set the hash
parameters, and inflates NSEC's 1-2 records for a name denial to 2-3 NSEC3
records, because due to NSEC3's flattening of the namespace, it has to
additionally prove things about the next-closest-encloser in the hierarchical
layout of the actual data.  NSEC3 adds a ton of complexity, and in the end it
didn't stop enumeration; attackers just walk the hash chain like they did the
name chain before, and then brute force the hashes with rainbow attacks and
GPUs offline at their leisure, and it doesn't take very long.

NSEC3 does have one redeeming value, though, which is that an Opt-Out bit was
added, which makes updates to very large delegation zones with lots of insecure
delegations (think .com) much less costly, because the NSEC3 chain can skip
over long runs of insecure delegations which do not affect the secure parts of
the zone.  Theoretically you could add a similar bit to NSEC to gain the same
benefits, but there's no room to add things like that to it now without
defining yet another new NSEC type.

#### Minimally Covering NSEC Records

The other interesting outcome was RFCs 4470 and 4471.  RFC 4470 is all about
online signing and "minimally covering NSEC records".  It redefines the meaning
of the NSEC next-name field a bit from the original definition.  Now `a NSEC d`
still proves that `b` and `c` don't exist, but it doesn't prove anything about
`d` at all, and `d` doesn't have to be a name that actually exists.  There was
a lot of exposition about how one could generate much smaller NSEC coverage
ranges to make online signing easier while also thwarting enumeration.

RFC 4470 mentions that while you could synthesize an NSEC NXDOMAIN denial of
the arbitrary name N by using an exact predecessor and successor function to
generate the two names that immediately surround it, it might be more-practical
to use less-perfect functions so that you don't create crazy-long unreadable
names.  This is mostly because, according to the canonical sort order of names,
the perfect single-step predecessor of any given name is usually a
~maximal-length name full of \255 bytes, which isn't very response size
friendly and isn't all that easy to generate.  You also would need to do a
lookup for this name in your data to make sure you didn't step on a "real"
name that has other type bits, and this gets more likely to happen if you're
using a less-perfect function to avoid super-long names.  The successor names,
however, are generally pretty short and easy to create, and don't have lookup
concerns.

RFC 4471 gave specific algorithms for how to calculate precise predecessors and
successors for an arbitrary name, which is helpful because it's really tricky
to derive these from the sort order definition.  These RFCs effectively define
what I think of as a broad definition of "NSEC1 White Lies", but this is a
retcon as I don't think anyone was calling them that at the time.

#### NSEC3 White Lies

The author of a DNSSEC proxy called Phreebird implemented a scheme dubbed
"NSEC3 White Lies", which applied the principles of RFC 447[01] to NSEC3 and
did online signing with minimized NSEC3 hash ranges.  The predecessor and
successor functions for NSEC3 hash values are much simpler, and we don't get
~255 byte names inflating packet sizes.  Also, the likelihood of one of these
false hashes colliding with real data is greatly diminished, maybe to the point
that some could comfortably ignore the problem.

#### Black Lies

Next up was the "Black Lies" denial-synthesis strategy from Cloudflare.
Traditional NSEC denials require 1-2 records, the Perfect NSEC1 White Lies of
RFC 4470 require 1-2 records and very long names, and NSEC3 White Lies require
2-3 records, but Black Lies promises a single NSEC with a short name.  Their
scheme is simply to never serve actual NXDOMAIN responses, but instead treat
all such cases as NOERROR responses with a minimal NSEC cover which deny the
queried type (but only that one!) in their NSEC type map.  These don't need the
extra wildcard denial because the owner name is an exact match, but they
sacrifice the whole concept of NXDOMAIN-ness in the process.

While they're at it, they also go ahead and also sacrifice the NSEC type map
information as well, returning fake lists full of common types and only leaving
out the bit for the one type that was being queried for, even in non-NXDOMAIN
cases.  From an outside observer's point of view, it's as if Black Lies zones
contain every theoretical name and common type in their namespace with some
kind of data, it's just unlikely to be the data you were asking for with your
exact question in the moment.

One of the rationales for this approach that's decscibed in Cloudflare's own
writing on the topic is that their unique DNS server implementation doesn't
actually know anything about topology or the types present at any given node.
It's implied that they basically operate from a flat database keyed on
domainname|type, and thus it's just not easy for them to know accurate
typemasks or whether they've hit an NXDOMAIN.  Since the origin has no topology
or typemask data to work with in the first place, Black Lies is the only easy
way for them to go!

While this strategy is superb at minimizing response sizes, some of its
sacrifices (the whole concept of NXDOMAIN-ness) are hard to swallow.

### Observations

A key point to observe in all of the above is that it really matters how easily
an authserver divulges topological and type presence data, and while more
information is a good thing for aggressive DNSSEC caches (see RFC 8198 about
aggressive DNSSEC caches), providing more information can be a bad thing for
enumeration concerns, and requiring it can be hard for online signing.  You
really have to get into the details of "exactly what information" to find an
optimal balance.

Black lies went full-tilt towards the extreme of information denial.  There's
no real possibility of aggressive dnssec caching against a Black Lies server,
and it leaks even less information about a zone's contents than legacy DNS
does, but it's very easy to implement online signing this way, and the
authserver doesn't even have to know anything about its own zones' topology or
data other than the answer to the specific question at hand.

Another interesting point is that even if one doesn't have a strong need for
truly-online signing of most responses, if you want to effectively prevent
enumeration attacks you have to minimize your NSEC or NSEC3 coverage ranges,
and thus you'll have to dynamically generate responses to NXDOMAIN situations,
necessitating online signing.  You can't have it both ways and mitigate
enumeration effectively while also keeping all your data signing and ZSK
privates offline, at least not within the scope of anything that's presently
standardized.  The NSEC5 proposal tried to come up with a creative crypto
answer to this problem that kept the true ZSK offline and had different online
secret that was only used for short-term denials, but I don't think it
ultimately went anywhere.

### Violet Lies

gdnsd shares the aim of strongly wanting to minimize response sizes and
authserver complexity while supporting online signing.  We also don't want to
make zone enumeration too easy, but we do want to help aggressive DNSSEC caches
learn more about the truly NXDOMAIN spaces of the zone, and we *do* know our
own zones' topology and type data.  To that end, gdnsd has its own strategy,
which I've dubbed "Violet Lies".

A quick technical bullet list of the shape of this Violet Lies scheme:

- We use NSEC rather than NSEC3
- There's always only a single NSEC for negative responses
- There are two name-sucessor functions we use in generating NSEC next-name fields which I've labeled PFE (Perfect Forward Epsilon) and SFE (Subdomain Forward Epsilon).
- PFE is the same as the "absolute method" successor function from RFC 4471 Sec 3.1.2.  It covers no names beyond the owner.
- SFE is basically just like that function, except that the first step from the RFC is always skipped.  This produces a next-name which covers no names beyond the owner at the same level of the hierarchy, but denies the existence of all subdomains of the owner.

    Incidentally, the SFE function is also what we use for the DS-denying NSEC of insecure delegation nodes, as this is the next name within the authoritative data of the zone that doesn't cross into delegated space!

- NSEC records belonging to real nodes with real data have accurate type map bits, and are used for NOERROR no-data responses on those nodes.  Their next-name field is PFE(owner), e.g. `foo.example.com NSEC \000.foo.example.com A AAAA RRSIG NSEC`, and does not deny the existence of any other name.
- Empty non-terminal nodes (ENTs) produce NOERROR responses with NSEC records using a PFE next-name just like the ones above, but with only the type bits `RRSIG NSEC`.

    This is a technical violation of standards (RFC 4035 Sec 2.3 "[...] MUST NOT create NSEC or RRSIG RRs for owner name nodes that were not the owner name of any RRset before the zone was signed."), but I think this requirement is rather onerous for smart online signers, and this deviation follows the spirit of other online signing schemes, and shouldn't create problems in practice.

- In a true NXDOMAIN scenario, gdnsd returns a singular NSEC record with only the bits `RRSIG NSEC`, much like our ENT response above.  However, the owner name of the NSEC record is the furthest (closest to root) encloser of the QNAME which is an NXDOMAIN in our data, and the next-name is SFE(owner), denying the existence of all subdomains of the owner.  If the furthest encloser was the QNAME itself, then the rcode is NOERROR (as we're emitting a record at the QNAME), but otherwise we use the NXDOMAIN RCODE.
- To clarify the above by example: if the zone `example.com` has a legacy NXDOMAIN case at `foo.example.com`, the answers to DNSSEC questions about `x.y.z.foo.example.com` or `z.foo.example.com` are an NXDOMAIN RCODE and `foo.example.com NSEC foo\000.example.com RRSIG NSEC`, which denies all useful RRTYPEs at `foo` itself, and also denies all subdomains beneath `foo` (including the QNAME itself) as NXDOMAIN cases.  If the QNAME had been `foo.example.com` itself, the same response would occur, but with a NOERROR RCODE.

This scheme is very simple to implement for an online signer that understands
their own topology.  It also blends well with leaf data injection, like gdnsd
uses for ephemeral ACME challenge responses and the like.  Its most redeeming
points, though, are about the data divulgence tradeoffs between enumeration and
aggressive negative caching.  While it technically sacrifices the NXDOMAIN
RCODE like Black Lies in some cases (but not all), it doesn't sacrifice the
concept or cache utility of NXDOMAIN-ness in general.  In some cases it
actually expands on what a legacy insecure NXDOMAIN or other Lies schemes would
prove about the topology in a single response, but in practice it doesn't make
the zone signficantly easier to enumerate than traditional DNS does.

From the perspective of enumeration attackers and aggressive caches, to recap:
legacy insecure NXDOMAIN proves that QNAME and all subdomains of QNAME don't
exist.  Black lies proves nothing.  NSEC3 white lies and NSEC1 white lies prove
something in the middle that's pretty minimal and not very helpful for
aggressive caching, and also have some other complexity and response-size costs
of their own.  What Violet lies proves depends on how deep QNAME is within an
NXDOMAIN area of the zone's tree:

In the case where `foo.example.com` would be an NXDOMAIN, and the QNAME is
exactly `foo.example.com`, the response looks like `foo.example.com NSEC
foo\000.example.com RRSIG NSEC`.  It proves exactly what legacy NXDOMAIN proves
about all the subdomains of `foo` (they all don't exist), but technically
doesn't prove non-existence for `foo` itself, but does at least prove that
`foo` has no useful (other than DNSSEC metadata) types.

In the same zone, a QNAME of `x.y.z.foo.example.com` returns the exact same
response as above, but with the RCODE set to NXDOMAIN.  This actually does
completely prove the NXDOMAIN-ness of the QNAME and everything beneath it like
a legacy insecure response would, and additionally proves NXDOMAIN-ness further
up the tree for all subdomains of `foo`.  This is very useful for the
aggressive caches, but doesn't actually help enumeration attackers much, as it
would only be a small extra effort for them to test `y.z.foo`, `z.foo`, and
`foo` for themselves after such a query.  It still doesn't tell the enumeration
attacker about any siblings of `foo` at the same level though, so the zone is
still quite difficult to fully enumerate.

Note that these responses also implicitly deny all possible wildcard matches
for the QNAME, and thus (like Black Lies) they don't ever need an excess NSEC
record (plus RRSIG) to disprove a wildcard, either.

## Caching and Ratelimiting of Synthesized NXDOMAIN Responses

[TODO] all of this
