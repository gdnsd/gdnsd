# GDNSD VERSION 4 EXTENDED RELEASE NOTES

[Work In Progress during the 3.99-alpha phase of things!]

This is an attempt at a human-usable breakdown of all the human-affecting changes in the major version bump from gdnsd 3.x to 4.x.

## Notable Feature Changes

### DNS

### Zonefiles

### Feature Regressions

## Configuration changes

### New options

### Options with changed defaults or allowed values

### Options removed completely

## Commandline changes for the main daemon

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

## Revamping internals

## DNSSEC on the horizon
