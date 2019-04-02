# GDNSD VERSION 4 EXTENDED RELEASE NOTES

[Work In Progress during the 3.99-alpha phase of things!]

This is an attempt at a human-usable breakdown of all the human-affecting changes in the major version bump from gdnsd 3.x to 4.x.

## Notable Feature Changes

### DNS

### Zonefiles

* Out-of-zone glue address records are no longer supported and will cause zonefile load failure.
* Unused glue addresses in delegated parts of a zone no longer cause any kind of warning or error.

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

### Options with changed defaults or allowed values

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

## Revamping internals

* Most uses of `typedef` removed from the codebase, other than a few cases with reasonable justification.
* All uses of `volatile` (cross-thread stats sharing + signal handlers) have been replaced by the appropriate use of equivalent C11 atomics.
* Many internal efficiency improvements

## DNSSEC on the horizon
