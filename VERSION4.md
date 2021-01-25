# GDNSD VERSION 4 EXTENDED RELEASE NOTES

[Work In Progress during the 3.99-alpha phase of things!]

This is an attempt at a human-usable breakdown of all the human-affecting changes in the major version bump from gdnsd 3.x to 4.x.

## Notable Feature Changes

### DNS

* RRSets are now sorted in DNSSEC canonical order when loading zone data.  Most RRSets will be served in this same order on the wire, regardless of original zonefile order (except for address RR-sets, which continue to be randomly shuffled at output time).
* Our advertised EDNS buffer size for incoming queries has changed from `1024` to `1232`.

### Zonefiles

* Static `_acme_challenge` records now override anything supplied by the dynamic system for temporary uses.  Removing a static entry will expose dynamic ones on zone reload.
* Out-of-zone glue address records are no longer supported and will cause zonefile load failure.
* Unused glue addresses in delegated parts of a zone no longer cause any kind of warning or error.
* Legacy `DYNC` records must reference legacy plugin resources which return only `CNAME` results, not address (`A`, `AAAA`) results.  This was deprecated and warned about starting in v3.4.2.
* NS RRSets are no longer limited to 64 RRs
* All RRSets are now limited to 1024 RRs
* The zone parser continues to require that all possible responses must fit in a 16KiB response packet.  Previously, we conservatively rejected responses which even heuristically looked like they *might* exceed this threshold.  Now the calculation is precise (because the responses are entirely pre-generated at zone load time), and thus will afford more edge cases close to the limit.
* Most warnings about trivial zonefile data consistency issues (e.g. MX pointing at a non-existent name in the same zone) have been dropped.  If the data can be legally loaded and served at the protocol level, that's all that matters in this sense.
* A new pseudo RR type `NXDOMAIN` exists to create an explicit NXDOMAIN at a given name.  These have no rdata at all.  Attempting to create other RRs at or beneath these names will result in a zonefile parse error.  These can be useful as policy or history communication mechanisms to other editors of the zonefile, and they're envisioned to help more in the future with DNSSEC operational issues.

### Feature Regressions

* The `USR1` signal is no longer handled at all, and thus may terminate the daemon.  It was previously handled as a no-op in 3.x, for backwards compatibility with dead 2.x features.
* The control socket protocol is no longer compatible with the old 2.99-beta releases of gdnsd.

## Configuration changes

* A long list of config options which were effectively-removed in the 3.0 release, but still parsed as no-ops to ease transition, are now completely removed and have become syntax errors:
  * `username`
  * `weaker_security`
  * `include_optional_ns`
  * `realtime_stats`
  * `zones_strict_startup`
  * `zones_rfc1035_auto`
  * `any_mitigation`
  * `priority`
  * `log_stats`
  * `max_response`
  * `max_cname_depth`
  * `max_addtl_rrsets`
  * `zones_rfc1035_auto_interval`
  * `zones_rfc1035_quiesce`
  * `http_listen`
  * `max_http_clients`
  * `http_timeout`
  * `http_port`
  * `plugin_search_path`

### New options

Experimental DNSSEC options (see bottom of this file) - no guarantees on the stability of these!

* `dnssec_enabled` - Boolean, default `false`
* `dnssec_deterministic_ecdsa` - Boolean, default `false`
* `dnssec_max_active_zsks` - Integer, default `1`, range `1 - 4`
* `dnssec_nxd_cache_scale` - Integer, default `10`, range `8 - 20`
* `dnssec_nxd_sign_rate` - Integer, default `2`, range `1 - 1000`

### Options with changed defaults or allowed values

* `max_edns_response` and `max_edns_response_v6` - Minimum value changed from `512` to `1220`.

### Options removed completely

* `experimental_no_chain` - This option has been removed.  It will still parse successfully for now to ease transitions, but will emit a warning on startup about being useless.  The new behavior is the previous default `true` value for this option.  This option was added in v3.1.0 with a `false` default, and then in v3.4.0 the default was changed to `true` and an error message was emitted on startup asking for reports of anyone who found a need for it to be `false`.  No such reports were received.  Remove this line from your config before 5.x makes it a parse error.

## Commandline changes for the main daemon

* The options `-f`, `-s`, and `-x`, which were deprecated and useless throughout 3.x, are now removed.

## Other changes of interest to builders and packagers

* Autoconf: min version bumped from 2.64 to 2.69 (2.70+ recommended!)
* Automake: min version bumped from 1.13 to 1.14
* C: Minimum standards version bumped from C99 to C11
* C Data Model: Tightened constraints in ways which may exclude some exotic, ancient, and/or tiny CPU targets.  As far as I know, this doesn't exclude any common/modern server platforms.  All of the constraints below apply to the equivalent unsigned case as well:
  * `char` must be exactly 8 bits wide.
  * `short` must be exactly 16 bits wide.
  * `int` must be exactly 32 bits wide.
  * `long long` must be exactly 64 bits wide.
  * pointers can be either 32 or 64 bits wide.
  * `long`, `size_t`, `intptr_t`, and `ptrdiff_t` must match the pointer width.
  * Must support lock-free C11 atomics on pointers.
* libsodium: min version bumped to 1.0.12
* `recvmmsg()` and `sendmmsg()` are now hard requirements.  The compile- and run- time detection and fallback to plain `recvmsg()` and `sendmsg()` has been removed.
* autoconf can detect and link libgnutls as an optional part of the experimental DNSSEC support code (more on this at the bottom of this doc), however, this is *not* recommended for any kind of distribution or other shared build, as this code is not production-ready.

## Revamping internals

* All response packets are pre-generated at zone loading time, rather than assembled during runtime query processing.  This unlocks significant efficiency gains and code simplifications, and will make it easier to add more RR-types to the parser.  It's also a critical design element in how we'll approach DNSSEC implementation.
* DNS packet compression is now more aggressive and thorough, because we can afford the expense now that it's done during pre-generation as well.
* Most uses of `typedef` removed from the codebase, other than a few cases with reasonable justification.
* All uses of `volatile` (cross-thread stats sharing + signal handlers) have been replaced by the appropriate use of equivalent C11 atomics.
* Many internal efficiency improvements

## DNSSEC on the horizon

This version has **partial**, **experimental** support for DNSSEC in the core code.  This experimental DNSSEC code is completely unsupported and is not intended for real production use!  A lot of the really heavy internal redesign that was needed is complete, and a lot of basic things (generating signatures, etc) are more-or-less working.  However:

  * Zonefile parser support is incomplete.  It can parse simple DS records for delegation cases, but has no support for other necessary bits, especially at the zone root for DNSKEY, CDNSKEY, CDS, RRSIG for managing real keys.  We may opt to manage these outside the zonefile anyways and have them injected as appropriate.
  * Key management and loading real keys is completely non-existent in general.  The only way to test the code is to let the daemon auto-generate randomized keys, using special zonefile directives that are appropriately-named `$BREAK_MY_ZONE_ED25519` and `$BREAK_MY_ZONE_P256`.  These auto-generate one ZSK of a given algorithm per use, and can be used multiple times.
  * The DNSSEC-specific code has no tests.  It has only been manually tested by me during development.
  * The existing mechanisms for dynamic ACME challenge responses is not DNSSEC-integrated.  This can likely be fixed without major changes.
  * The existing plugin-based DYN[AC] records are not supported with DNSSEC.  This one isn't at all trivial.  We'll either have to pare back the features and capabilities of this model significantly, or replace it with a simpler equivalent that covers most reasoanble use-cases.  I lean towards the latter, as then we can leave the old DYN[AC] stuff as deprecated-but-working in 4.x alongside the new stuff.

For these and many other reasons, it is not at all advisable to use this with production zones or servers yet.  It may iteratively become more-complete and better tested in future 4.x releases.  I intend for it to be really usable, somehow, before we get to 5.0.

There's some nascent design-level documentation in docs/DNSSEC.md that goes into more details about what's currently working and how, and what design decisions have been made so far.
