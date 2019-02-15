# GDNSD VERSION 3 EXTENDED RELEASE NOTES

This is an attempt at a human-usable breakdown of all the human-affecting changes in the major version bump from gdnsd 2.x to 3.x.

## Notable Feature Changes

### DNS

* The TCP DNS code was upgraded substantially:
  * Follows the spirit and recommendations of RFC 7766 "DNS Transport over TCP - Implementation Requirements"
  * Supports TCP Fastopen
  * Implements the RFC 7828 EDNS tcp-keepalive option
  * Pipelined requests should work fine, and will always be answered in-order due to implementation details
  * Partial progress on "DNS Stateful Operations" draft - logic/state is already in place to handle it well, but not protocol implementation
  * Resiliency under heavy load or attack-like conditions, including slow-read/write, is greatly improved and should allow legitimate clients to continue making requests under adverse conditions
  * PROXY procotol support can be enabled for specific special listen addresses.  This is intended for testing encrypted connections such as DNS-over-TLS using an external daemon for the secure transport, and also by default enables EDNS Padding to help secure against response length analysis.
  * Several new stat counters added for per-connection TCP stats, alongside the existing per-request ones:
    * `tcp.conns` - TCP conns we accepted (excludes extremely early failures, e.g. accept() itself returning an error)
    * `tcp.close_c` - TCP conns closed cleanly by the client (the most-desirable outcome)
    * `tcp.close_s_ok` - TCP conns closed cleanly by the server, usually due to an idle timeout being reached or during thread shutdown, etc.
    * `tcp.close_s_err` - TCP conns closed by the server due to an error such as `tcp_recvfail`, `tcp_sendfail`, or `dropped` from the general stats.
    * `tcp.close_s_kill` - TCP conns closed by the server, which were killed early to make room for a new client when `max_clients_per_thread` was reached.
    * `tcp.proxy` - TCP conns initiated on PROXY protocol listeners (also incs `tcp.conns`)
    * `tcp.proxy_fail` - TCP PROXY conns killed for failure to parse an acceptable PROXY protocol header (also incs `tcp.close_s_err`)
* edns-client-subnet support updated to match RFC 7871
* The nsid EDNS option from RFC 5001 is implemented, allowing identification of members of a loadbalanced or anycast server set
* All responses are completely minimized:
  * A and AAAA responses no longer include opposite-family records in the additional section
  * The answer section usually contains only one rrset, unless CNAMEs are involved (we still output CNAME chains within local zone data)
  * The auth section is only ever used for negative responses (1x SOA) and delegations (NS records at a zone cut)
  * The additional section only ever contains actual mandatory glue IPs (out-of-zone glue or glue within any delegated subzone of the delegating zone); it is no longer used for other purposes like A/AAAA additionals for answer-section MX, SRV, etc.
  * ANY-queries are now answered with a minimal, synthetic HINFO RR per RFC 8482
* Input query parsing is now much more robust and future-proof in general.  We now at least minimally parse all query RRs and seek the OPT RR anywhere within the additional section, and we're much more likely to respond explicitly with a FORMERR or NOTIMP in some cases where we'd have previously not responded at all to oddly-formed queries from future standards efforts we're not aware of.
* The default maximum EDNS output size over UDPv6 should better avoid loss in the real-world IPv6 Internet.
* TCPv6 now also uses a minimal MTU/MSS setup to avoid similar loss/performance issues.
* The DNSSEC OK (DO) bit in the EDNS flags field is now echoed back in responses as per RFC 3225 (but we continue to not support DNSSEC so far, so no functional impact on the response).
* A new stat counter `edns_do` tracks the count of EDNS requests with the DO bit set.
* EDNS Cookies from RFC 7873 are implemented to help with off-path response forgery and forged amplification attacks.  These add 4 new stats counters:
  * `edns_cookie_init` - Received a client cookie with no server cookie
  * `edns_cookie_ok` - Received a client cookie with a server cookie, and it validates
  * `edns_cookie_bad` - Received a client cookie with a server cookie, and it failed validation
  * `edns_cookie_formerr` - Recived an EDNS Cookie option that was malformed (also increments the normal formerr stat)

### Zonefiles

* Zone (re-)loading still scans the zones directory for zonefiles and automatically names zones based on filenames as before
* Zonefiles are now only ever reloaded by explicit command, never by filesystem monitoring
* Zone reloads are considered synchronous and atomic: there is no mechanism to reload individual zones, and the entire dataset must load successfully or none of it affects the runtime
* `$INCLUDE` files supported (use subdirectories, which are otherwise ignored, to avoid confusing them for zones)
* Symlinks now work for aliasing zones, assuming there are no explicit references to the zone name within the data.  To help with that:
* `@Z` and `@F` macros implemented, which represent the original (line zero) `$ORIGIN` of the zone or the current file.  You can use these in situations like: `$ORIGIN foo.@F [... records ...] $ORIGIN bar.@F`, which would otherwise be impossible without hardcoding the zone name in the second origin statement, breaking symlink zone aliasing
* Support for the gdnsd-specific `$ADDR_LIMIT_V4` and `$ADDR_LIMIT_V6` directives has been removed.

### gdnsdctl

The daemon now has a control socket, and `gdnsdctl` is shipped as the canonical client for it.  All gdnsdctl commands are synchronous and status-reporting, meaning they do not exit until the requested operation has either succeeded or failed fully, and always reflect success with a zero exit code and failure with non-zero.  The commands currently implemented by gdnsdctl include:

* `status` - Basic status check, reports version and PID of running daemon
* `stats` - Dumps current statistics from the daemon in JSON format to stdout
* `states` - As above, but states for healthcheck monitoring
* `stop` - Stops the running daemon
* `reload-zones` - Reloads zonefiles
* `acme-dns-01` - Creates ephemeral TXT records for ACME DNS-01 challenge responses
* `replace` - Requests that the daemon replace itself seamlessly (no downtime, no lost requests):
  * This mechanism supports seamless configuration changes or code updates
  * Replacement is a fresh execution of the same binary pathname with CLI options preserved
  * Spawned as a child of the running daemon in order to preserve as much execution context as possible
  * Listening sockets are handed off seamlessly with no loss or interruption of DNS services
  * ACME DNS-01 challenge data is handed off seamlessly
  * Stats counters also hand off seamlessly (no stats rollover blips from restarts in your graphs!)
  * The old daemon can continue operations as it was before if the new dies before finishing the handoff
  * gdnsdctl monitors the entire sequence: watches the previous daemon report a successful takeover by the replacement, witnesses the exit of the old daemon, and reconnects to the new daemon to ensure it survived the transition
  * Critically, this mechanism is systemd compatible

### Feature Regressions

* The geoip plugin no longer supports the legacy GeoIP1 database format
* The `listen => scan` option, which scanned interfaces for IPs to bind to, has been removed completely.  It was deprecated with runtime warnings and removed from the documentation back in v2.2.0
* The HTTP listener and its previous stats/state output code in various formats is gone completely, replaced by the control socket stuff above
* Automatic and/or asynchronous per-zonefile reloads are gone completely.  All zone data reloads are now commanded, synchronous, and atomic with respect to the entire dataset
* The daemon no longer reloads zonefiles on SIGUSR1, but it does handle the signal as a no-op with a warning for compatibility reasons.
* The daemon does not implement any security-related code anymore.  This job has been foisted off on the init script/system (more on this below in "Security, daemon management, and init systems")
* The semantics of the sub-fields of NAPTR records are no longer validated in any way
* NS record nameserver hostnames are no longer allowed to point at DYNA records in local data
* NS record sets are limited to 64 records per set and are no longer randomly rotated in the output
* The server does not support emitting responses greater than ~16KB in size over any protocol.  Zone data is explicitly validated against this constraint, and zonefiles will fail to load if they contain record sets which could generate an over-sized response packet.  The checks are somewhat conservative in corner cases and may reject data which would technically barely fit in practice.
* DYNC and related plugin configurations have two new restrictions: all configured dynamic CNAME values must be fully-qualified (end in dot), and DYNC cannot be used to emit a CNAME that points into the same zone (in others words, if `example.com` has the RR `foo DYNC %weighted!some-cnames`, the weighted plugin's configuration for the resource `some-cnames` cannot contain any CNAME values within the zone `example.com`; they must be names in other domains).
* Support for DSO plugins developed out of tree is removed.  The existing "plugins" are now compiled into the daemon, but otherwise work as they did before for now.
* The configuration and zonefile parsers no longer accept DOS-style line endings (`"\r\n"`).  This was considered a convenience before, but it's not worth the complexity/fraily costs in the parsers.

### Other minor things

* The GeoIP distance calculations are now slightly faster and more accurate.
* The source code has been through a bunch of cleanup for clarity, simplicity, and formatting

## Configuration changes

### New options

These are all new options for new features:

* `acme_challenge_ttl` - Sets the time in seconds for records injected by `gdnsdctl acme-dns-01` to expire, as well as the advertised TTL.  min/def/max is 60/600/3600.
* `nsid` - Sets the raw binary data returned by the NSID EDNS option.  Up to 128 raw bytes, encoded as up to 256 characters of ascii hex in a single string.
* `nsid_ascii` - Convenience alternative to the above, sets the NSID binary data to the bytes of the specified printable ASCII string of at most 128 characters.
* `tcp_fastopen` - Sets the queue size for TCP Fastopen (global, per-socket).  min/def/max is 0/256/1048576, zero disables.
* `disable_cookies` - Disables EDNS Cookies (not recommended!)
* `cookie_key_file` - Loads the master cookie secret key from a file controlled by the administrator, useful for synchronizing cookie support across a set of loadbalanced or anycasted gdnsd instances.  The file's contents must be a 32-byte chunk of binary data generated securely and randomly for direct use as a secret key!
* `max_nocookie_response` - Limits UDP response sizes when clients present no valid cookie auth.  This is disabled by default for now.
* `max_edns_response_v6` - Like existing `max_edns_response` parameter (which is now v4-only), but for IPv6, and defaulting to 1212.
* `tcp_proxy` - Enables PROXY protocol support for a specific TCP listen address:port, see docs for details
* `tcp_pad` - Controls EDNS Padding for TCP connections (default off for normal TCP listeners, default on for the `tcp_proxy` case).
* `tcp_backlog` - Optional non-default backlog argument for TCP `listen()` (default is `SOMAXCONN`)

### Options with changed defaults or allowed values

You'll need to fix values for these in existing config before trying an upgrade, if your current values are out of range for the new limits:

* `max_edns_response` - max changed from 64000 to 16384
* `tcp_threads` - Default changed from 1 to 2, minimum changed from 0 to 1
* `tcp_timeout` - min/default/max changed from 3/5/60 to 5/37/1800 (see docs for other related changes)
* `tcp_clients_per_thread` - Default changed from 128 to 256
* `udp_threads` - Default changed from 1 to 2, minimum changed from 0 to 1

### Options removed completely

None of these generate a syntax error for now, they merely log a non-fatal error to ease transition.  They'll become syntax errors in a future major version update:

* `any_mitigation` - No longer applicable
* `include_optional_ns` - Fixed off (same as previous default)
* `max_addtl_rrsets` - No longer applicable
* `max_cname_depth` - Fixed at 16 (same as previous default)
* `max_response` - Fixed 16384 (same as previous default)
* `plugin_search_path` - No longer applicable
* `udp_recv_width` - Fixed at 16 (prev default was 8)
* `zones_strict_startup` - Fixed on (same as previous default)

* `zones_rfc1035_auto` - Removed with zonefile autoscanning
* `zones_rfc1035_auto_interval` - Removed with zonefile autoscanning
* `zones_rfc1035_quiesce` - Removed with zonefile autoscanning

* `http_listen` - Removed with HTTP listener
* `http_port` - Removed with HTTP listener
* `http_timeout` - Removed with HTTP listener
* `log_stats` - Removed with HTTP listener
* `max_http_clients` - Removed with HTTP listener
* `realtime_stats` - Removed with HTTP listener

* `priority` - see "Security, daemon management, and init systems" below
* `username` - see "Security, daemon management, and init systems" below
* `weaker_security` - see "Security, daemon management, and init systems" below

## Commandline changes for the main daemon

* All of these CLI action verbs are removed and effectively replaced by `gdnsdctl`: `stop`, `reload-zones`, `restart`, `condrestart`, `try-restart`, `status`.
* The remaining verbs are:
  * `start` - Starts a foreground process, non-daemonizing with log output to stderr by default.
  * `daemonize` - Starts a background daemon process.  The daemonization is minimal, but correct and complete.  It properly goes through the `fork()->setsid()->fork()` sequence, it ignores `SIGHUP` (unlike `start`), and it closes off the stdio files and sends its logging to syslog.  The original foreground process waits on the daemonized child to report successful startup (through offering live runtime service) before it exits with status zero.
  * `checkconf` - Goes through much of the initial sequence of `start`, including loading the configuration and zonefiles, but does not attempt to start runtime listener services or control socket code.
* Flags:
  * Unchanged: `-c` - sets the configuration directory, if not using the hardcoded default path from build time.
  * Unchanged: `-D` - requests debug-level logging output (in production builds it's not too spammy for most things.  In `--enable-developer` debug builds, the output from this flag can be unreasonably verbose).
  * Unchanged: `-S` - upgrades all zonefile warnings to errors, like config setting `zones_strict_data`
  * Removed: `-f` (foreground) - replaced by the `start`/`daemonize` distinction above
  * Removed: `-x` (no syslog) - Stderr logging is the default
  * Removed: `-s` (zones strict startup) - this is now always true and doesn't make sense as a flag
  * Added: `-l` - explicitly switches log output from stderr to syslog for the `start` and `checkconf` actions.
  * Added: `-R` - allows `start` or `daemonize` to replace another running daemon instance in a smooth (downtime-less, loss-free) way.  This is what's used when the daemon spawns its own replacement process when commanded to do so by `gdnsdctl replace`.  Without `-R`, if another daemon instance were already running, `start` or `daemonize` would complain and exit.
  * Added: `-i` - Idempotent mode for `start` or `daemonize`, will exit with zero immediately if another instance is already running

All the removed flags (`-f`, `-s`, and `-x`) are still allowed for compatibility reasons and emit non-fatal log messages, to ease transition of tools/scripts.

## Security, daemon management and init systems

The TL;DR here is that gdnsd doesn't manage its own OS security or privileges anymore.  It just runs and assumes the environment was already secured by the init system or script, and assumes it can bind port 53.  The init script/system is also responsible for taking care of other optional bits gdnsd used to do for itself as root before dropping its own privileges: setting the working directory sanely, setting locked memory (and/or other) resource limits, setting process priority, dropping privileges for the daemon, etc.  Since most installations will want gdnsd to run as a non-root user and also to bind port 53, that means a system-specific mechanism will have to be employed.  For Linux this means `CAP_NET_BIND_SERVICE`, and for FreeBSD it's `mac_portacl`, but in general this is not an area where portable solutions exist.  More rationale and background on this further down below.

For systemd-based Linux distributions, an example unit file which handles all the things is built along with the software at `init/gdnsd.service`.  A similar example is provided for traditional Linux LSB sysvinit at `init/gdnsd.init`.  Some FreeBSD example config and init code from my basic testing is documented in `docs/Manual.md`.

## Other changes of interest to builders and packagers

* Autotools updates: building from git now requires autoconf 2.64+ and automake 1.13+
* We no longer depend on libtool, and don't install any shared libraries, DSO modules, or headers.
* We newly depend on libsodium-1.x as our current crypto lib of choice
* The userspace-rcu library (liburcu) is now a build requirement rather than an optional recommendation
* The testsuite now requires Perl module Net::DNS version 1.03+
* GeoIP2 support, while still optional, requires libmaxminddb 1.2.0+ if enabled at all
* In general, lots of source-level backwards compatibility for older systems and/or kernels was removed where the assumptions seemed safe for a new major release in 2019.  If cases arise where certain operating systems are still in support and require patching, I'd be happy to add back the necessary bits.  Examples here include the assumptions about `SO_REUSEPORT`, `SOCK_CLOEXEC`, `SOCK_NONBLOCK`, and `accept4()`.
* The generated C sources `src/zscan_rfc1035.c` and `libgdnsd/vscf.c`, which are built with `ragel`, are once again being included in tarball releases, but not in the git repo.  This is in response to ragel dependency hell reported by some who build from source on every machine.

### The big changes around security, daemon management, and init systems

In the past, gdnsd has tried to take care of all security and daemon management functions internally.  It managed a number of execution aspects which typically require initial root privileges: setting process priority, raising the locked memory ulimit for `lock_mem => true`, binding the privileged port 53, limiting security scope via Linux -specific calls like prctl(), etc... and then took care of dropping its own process uid and gid to unprivileged ones safely and permanently.  Some of this was already portability-problematic for some platforms, but the real nail in the coffin for all of this was systemd.

Another key feature was the ability to do downtime-less restarts for changing code and/or configuration, and I had a strong desire to preserve that feature and try to keep it portable.  The original mechanisms gdnsd used for downtime-less restarts relied only on reasonably-portable assumptions and widely-available POSIX/unix APIs, and integrated well (if in a complicated manner!) with all of the privileged operations performed at startup above.  Because a running daemon had already permanently lost all of its elevated privileges, the new daemon during a replace had to be independently started as root to accomplish all the same things for itself, including critically the binding of port 53 (even with `SCM_RIGHTS` handoff, new listeners could be configured).

Systemd didn't allow for this to work the way it had under traditional init systems in the past, and as a result gdnsd 2.x lost this smooth replace-restart capability on systemd-based systems, which for better or worse came to dominate the Linux (and thus all servers) market during its lifetime.  The primary crux of incompatibility was that systemd wouldn't allow any kind of overlapped-restart by a process which wasn't a child of the original daemon and inheriting its cgroup settings, not even from processes started by other commands in the unit file such as `ExecReload`, and my various mailing list posts about finding ways to fix the situation and allow daemons to manage smooth restarts with independent replacement daemons fell on deaf ears.  And again, since the running daemon was unprivileged, there was no easy way for it to spawn a replacement that needed to perform privileged operations on startup.

I expended many months of effort and many ultimately-doomed code branches trying to come up with a sane way to still do everything else we were doing in this area portably while appeasing the requirements of systemd, but all of my efforts either resulted in other serious design flaws, or simply had way too high a complexity and fragility burden to be reasonable.  At the end of the day, the only reasonable path forward given systemd's dominance was to give in and structure things in the way that pleased systemd the most, while still preserving some ability to get similar results under traditional init systems and/or on non-Linux platforms manually, and that ended up being to push all related things back on the init system/script and be security-oblivious in the daemon code.  I apologize to all the non-systemd users, but I couldn't find a better way out of this mess!
