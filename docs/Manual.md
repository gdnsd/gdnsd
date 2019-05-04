# GDNSD MANUAL

## Overview

This manual attempts to cover things that don't logically fit in the man pages or other documents.

This manual is not intended to be an exhaustive reference. For a complete rundown of every configuration and commandline option and its precise technical meaning, see the man pages.


## General Portability Notes

Modern 64-bit Linux/x86\_64 is the primary development and deployment platform, with 32-bit Linux/x86 and the in-between Linux/x32 ABI being close seconds.

Compatibility with the open source \*BSD distributions is important, and bug reports are welcome for any breakage there.  Unfortunately the author doesn't use these regularly, so portability mistakes may creep in that need reporting.  FreeBSD 11.2 and 12 were tested during the final beta releases leading up to gdnsd 3 and seems to work out great with `mac_portacl` handling the issue of binding port 53.  Probably the biggest issue facing OpenBSD, NetBSD and other \*BSD builds right now is that even if they build, I have no idea how to handle non-root processes binding port 53 on them, which is a new requirement as of gdnsd 3.  They may have to fall back on using PF to remap port 53 traffic to unprivileged ports gdnsd is listening on.

Through the official Debian packaging of gdnsd, it gets some testing on exotic CPU architectures, and generally shouldn't have issues with any of the well-supported Debian target architectures.  The code does try to be clean on endian-ness and alignment issues at least.

There are a few gcc-isms in the source, but they're either older ones that tend to be well-supported by other modern compilers, or there's fallback support when they're not available.  Clang is explicitly supported and works great.

The code **requires** the userspace RCU library `liburcu`, and this in itself could limit portability.  However, currently `liburcu` seems to have a wider amount of portability than gdnsd itself, so it shouldn't be a major impediment.

MacOS/Darwin is no longer supported.  I don't happen to have a Mac around, they don't allow emulation, and they don't make server hardware.  The code may happen to build and/or run successfully there by virtue of the code's general BSD compatibility, but I think that's unlikely with recent gdnsd and MacOS versions.

I take absolutely no interest in portability to Microsoft platforms, and would probably reject pull requests for it if they add significant noise and/or complexity to the codebase, which seems likely.  It's simply not worth it.

## Platform and/or Architecture -specific notes

### Linux and `CAP_NET_BIND_SERVICE`

Because running a daemon as root is a Bad Idea, and because systemd more or less forced us into a model where this daemon no longer manages its own privileges: to get gdnsd running as a non-root user on Linux, you need a way to provide it with the `CAP_NET_BIND_SERVICE` capability in a way that inherits to future child processes as well.  Linux kernels 4.3 and higher support ambient capabilities, which is the best way to provide this.

For systemd-based Linux distributions: gdnsd requires systemd v229 or higher and kernel 4.3 or higher.  Systemd versions earlier than this do not support ambient capabilities.  All systemd versions (<229, or 229+ without the AmbientCapabilities setting in the unit file) fail to use the correct sequence of operations to support falling back to filesystem-level capabilities like the sysvinit case below.  This implies that for default (systemd) Debian installations, running gdnsd 3 securely requires stretch (the current stable) or higher.

For sysvinit-based Linux distributions: if you have kernel 4.3 or higher and setpriv from util-linux 2.31 or higher (recommended!), you can use ambient capabilities via the setpriv command as shown in the example initscript.  If one or both of these requirements can't be met, you can fall back to filesystem-level capabilities in place of ambient ones.  In this case, the package installation process should run `setcap cap_net_bind_service=ei /usr/sbin/gdnsd` every time it installs a new binary image, and the "--ambient-capabilities" argument to setpriv shown in the example initscript should be removed.  Filesystem capability support goes back to kernel 2.6.24, and there's no good reason for gdnsd to support (or users to run) anything older than that, as there would probably be other subtle (or not-so-subtle) issues.

### BSDs

I've tested the 3.x build on FreeBSD 11.2 and 12 (but not other BSDs, sorry!) under qemu.  Starting from a clean install, this stuff worked for FreeBSD 12:

Build/Test/Install:
```
pkg install liburcu libev libsodium libunwind libmaxminddb
pkg install p5-HTTP-Daemon p5-Net-DNS p5-IO-Socket-INET6
pkg install gmake
setenv CPPFLAGS "-isystem/usr/local/include"
setenv LDFLAGS "-L/usr/local/lib"
# If using FreeBSD 11.2, you may need to add "--disable-hardening" to configure
# below to avoid PIE-related flags, which seem to break building there.
# FreeBSD 12 is fine with the defaults and actually needs the PIE-related flags
# to build successfully.
./configure
gmake
gmake check
gmake install
```

Runtime setup stuff done manually:
```
# Create gdnsd user (for portacl rules at bottom, assuming uid is 1234)
# Confirm mac_portacl, accf_dns, and accf_data are loaded, look for them in the output of:
kldstat
# If not loaded, set them up in loader.conf.local for future boots:
echo 'mac_portacl_load="YES"' >>/boot/loader.conf.local
echo 'accf_dns_load="YES"' >>/boot/loader.conf.local
echo 'accf_data_load="YES"' >>/boot/loader.conf.local
# If not loaded, load them now for immediate use:
kldload mac_portacl
kldload accf_dns
kldload accf_data
# Add the necessary mac_portacl bits to /etc/sysctl.conf:
# (note, if portacl rules already exist, must append to existing ones!)
security.mac.portacl.suser_exempt=1
security.mac.portacl.port_high=1023
net.inet.ip.portrange.reservedlow=0
net.inet.ip.portrange.reservedhigh=0
security.mac.portacl.rules=uid:1234:udp:53,uid:1234:tcp:53
```

Very basic /usr/local/etc/rc.d/gdnsd script that seems to work.  Obviously it could be fleshed out a lot more (e.g. to wrap all the gdnsdctl commands, use gdnsdctl for stop, use gdnsdctl replace for reload/restart, etc).  Perhaps that's a future TODO as a real example script like the others in `init/`:
```
#! /bin/sh
#

# PROVIDE: gdnsd
# REQUIRE: DAEMON
# KEYWORD: shutdown

#
# Add the following lines to /etc/rc.conf to enable git_daemon:
#
# gdnsd_enable="YES"

. /etc/rc.subr

name="gdnsd"
rcvar="gdnsd_enable"

load_rc_config $name

: ${gdnsd_user:=gdnsd}
: ${gdnsd_group:=gdnsd}
: ${gdnsd_enable:=NO}
: ${gdnsd_flags:=daemonize}

command="/usr/local/sbin/gdnsd"
command_args=""
start_precmd="gdnsd_prestart"

gdnsd_prestart()
{
        mkdir -p /usr/local/var/run/gdnsd
        chown gdnsd:gdnsd /usr/local/var/run/gdnsd
        chmod 700 /usr/local/var/run/gdnsd
        # Could also set priority/nice/ulimit/etc stuff here
        return 0
}

run_rc_command "$1"
```

### 32-bit platforms in general

The daemon exports statistics counters which can reach very large values over time.  Because of some deep issues about implementing them efficiently and portably, on platforms with 32-bit-wide pointers, the stats counters are also only 32 bits wide.  This means that for a high volume authdns server, they can easily roll back over to zero after reaching ~4 billion, and whatever tooling you're using to consume and graph the stats will need to be able to sanely detect and handle the rollover.  On true 64-bit platforms with 64-bit pointers, all the stats counters are 64-bit and it's virtually impossible to roll them over in the real world.

I've implemented a special exception which turns on 64-bit stats for the known case of the x86\_64 x32 ABI, which has 32-bit pointers but is capable of efficiently and correctly supporting 64-bit stats counters.  The requirement for doing such hacks for other platforms with 32-bit pointers is that there's a C data type on the platform that can be incremented in a tear-free way (that is, concurrent access from another thread will not see a half-updated value), but we don't need multi-updater atomicity.  This was easy to do without assembly for x32.  It's technically possible to do it for 32-bit x86 on i486 or higher as well I think, using asm-level constructs built around `CMPXCHG8B`, but I haven't tried implementing it.  The Linux kernel demonstrates some related stuff in their `atomic64_t` support that could probably be cribbed.  It's tempting to use C11 atomics for this, but they carry the extra synchronization burden of being multi-updater atomic, so even in cases where they expose a "lock-free" 64-bit type on a 32-bit platform, they're not as efficient as they could be (e.g. on x86 they use unnecessary LOCK instruction prefixes at the asm level).  Patches welcome!

## Design Documentation

### Configuration

The configuration file's basic syntax is handled by "vscf", which parses a simple and clean configuration syntax with arbitrary structural depth in the form of arrays and hashes. At one time this was a separate library, but it has been bundled back into gdnsd's distribution at this point. Details of the configuration options are in the man page gdnsd.config(5).

### Threading

The gdnsd daemon uses pthreads to maximize performance and efficiency, but they don't contend with each other on locks at runtime.  Some pthread lock/condwait methods are used to synchronize threads during the daemon's startup sequence, and may be used for runtime side jobs that aren't performance-critical (e.g. reloading zonefiles or GeoIP databases), but nothing in the runtime flow of actual DNS requests blocks on any pthread locks.  Situations which might normally require locks in the request flow are instead handled using RCU QSBR-based mechanisms provided by the userspace-rcu library.  We design for no more than one thread writing to any shared memory location in the general case, although there may be many readers in some cases.  Thread-local writable memory is generally malloc()'d within the writing thread and the address is private to the thread.  There are three primary functional threads of execution, aside from actual DNS I/O handling:

The "main" thread of execution (the first thread of the process) primarily handles meta-level managerial functions once initial startup is done (control socket, signals, process management, etc.).  It also handles any configured health monitoring checks at runtime.

The geoip plugin spawns a separate persistent functional thread, whose only job is to watch for updates to configured GeoIP databases and handle the asynchronous reloading of their data.

When zone data reloads are requested, a temporary separate pthread is spawned just for the purpose of loading the zone data, which terminates after the operation is complete.  This thread may spawn other temporary sub-threads to parallelize zonefile loading.

The rest of the threads are all dedicated DNS I/O threads.  The general model employed is that every configured listening address (address/port/protocol combination) creates multiple `SO_REUSEPORT` listening sockets.  The number of duplicate listening sockets per address is controlled by the `udp_threads` and `tcp_threads` parameters, which default to 2.  There's exactly one I/O thread per listening socket, and they exist for the life of the daemon.  It's intended that the tcp/udp threads options should be tuned to roughly the CPU core count of the host machine.  For example, if two listen addresses are configured at 192.0.2.1:53 and 192.0.2.42:53, and the threads parameters are at their default value of two, there will be a total of 8 I/O threads created (2 tcp + 2 udp for each of the two IP:port, each thread having its own separate `SO_REUSEPORT` listening socket).

The UDP DNS threads use a tight loop over blocking network syscalls for their singular socket.  All of the code executed in the UDP threads at runtime is carefully crafted to avoid all syscalls (other than the necessary network syscalls) and other expensive or potentially-blocking operations (e.g. locks and dynamic memory allocation).  These threads should never block on anything other than their send/recv calls, and should execute ~2 syscalls per request.  It's sometimes a little over 2 under very light load due to excess setsockopt() calls to control blocking timeouts when there are multi-second idle periods, and sometimes significantly less than 2 under heavy load thanks to the multi-packet `sendmmsg()` and `recvmmsg()` interfaces.

The TCP DNS threads use a libev event loop to multiplex the handling of all traffic for all connections they accept on their listening socket and use non-blocking I/O.  The TCP code shares the efficient core DNS parsing and response code of the UDP threads, but it does use dynamic memory allocation and a plethora of per-request syscalls (some via the eventloop library) at the TCP connection-handling layer.

### Runtime data updates

There are multiple cases where the daemon dynamically loads new data or state at runtime: reloadable zonefiles, reloadable GeoIP databases, the extfile monitoring plugin, and the `admin_state` file.  In all of these cases, we rely on the magic of RCU to avoid performance issues on the network-facing side of the daemon.

Typically, one would implement such data reloads naively using pthread mutexes.  The DNS I/O threads impacted by the data updates would take reader-side locks around accesses to the data, and the reloader/writer threads would take write locks when they need to update things.  The problem with this is that at the latency, performance, and cpu/thread/socket scalability levels we're shooting for in the UDP DNS case, even pthread locks are ridiculously expensive operations.  They also tend to have priority and/or starvation problems when many threads are holding overlapping reader locks while one writer is waiting for a write lock.  You can either have the writer stalled out forever because there's never a gap in the overlapping read locks, or you can have the writer preempt and stall several readers unnecessarily.  There's not a good general-case answer with mutexes that has great properties under all runtime conditions.

The basic RCU algorithm offers an elegant answer to these kinds of problems.  It's perfect when reads far outnumber writes and performance degradation of the read side is far more important than the write side.  We specifically use the `QSBR` RCU algorithm variant from `liburcu`, the Userspace-RCU library.  The liburcu site has some links to read up on RCU fundamentals, which I won't cover in any great depth here: https://liburcu.org/ .

The gist of it is this: the reader side gets to access the data in a completely lock-free and stall-free way that doesn't impact thread scaling, and the writer side is guaranteed to make progress within a fairly short window of absolute time without causing any impact.  What happens from a sequential point of view is something like this:

1. The writer constructs a new set of data (e.g. from an updated input file)
2. The writer switches a data pointer that was pointing at the old data, to point at the new data, but doesn't yet delete any of the old data
3. Readers who were already in the middle of reading the old data continue doing so until they finish their current request
4. Readers who begin a new request after the data pointer switch read the new data and do not access the old data
5. The writer is able to magically stall until all readers are done using the old data for their in-progress requests at the time of the pointer switch, without impacting the readers' performance in any way.
6. Finally, the writer deletes the old data copy and goes back to looking for future updates to apply.

### Performance

I've done some basic UDP performance testing of the gdnsd 3.0 codebase just prior to release, but only on my laptop over the loopback.  Test conditions:

* Thinkpad Carbon X1 laptop with CPU "Intel(R) Core(TM) i7-7600U CPU @ 2.80GHz"
* Debian (stretch + various backports/testing packages, my normal everyday setup)
* Linux kernel 4.19
* gdnsd built with gcc-8 -O3 and default compiler hardening flags
* gdnsd configured for single thread (udp\_threads = 1), with 100 small zones loaded
* dnsperf from https://github.com/akamai/dnsperf.git for the client side
* dnsperf input file with 110K A-queries to test, ~9% of which are NXDOMAIN and the rest are NOERROR, spread randomly over the ~100 small zones' namespaces.
* dnsperf args: -s 127.0.0.1 -p $port -d $datafile -e -D -l 60

With this setup and zero latency over the loopback, gdnsd achieves a rate of ~450K reqs/sec with a single UDP server thread (I can't test parallel perf well on this hardware with only 2 real CPU cores), and 100% of responses are successful and correct.

To validate the smoothness of the "replace" takeover model for binary upgrades and/or config changes, I've also re-run the test while spamming replace operations (a loop performing "gdnsdctl replace" on the test server instance once per second, which re-executes the whole daemon with overlapped socket handoff), and the reliability and performance results are indistinguishable from a normal run even though the daemon was replaced with a whole new PID ~60 times during the test run, with correct stats matching dnsperf's output in the final copy of the daemon.

TODO: flesh this out with some more-realistic testing on server hardware over real NICs with realistic data and query stream.

### Statistics

The DNS threads keep reasonably detailed statistical counters of all of their activity. The core dns request handling code that both the TCP and UDP threads use tracks counters for all response types. Mostly these counters are named for the corresponding DNS response codes (RCODEs):

* refused - Request was refused by the server because the server is not authoritative for the queried name.
* nxdomain - Request was for a non-existent domainname. In other words, a name the daemon is authoritative for, but which does not exist in the database.
* notimp - Requested service not implemented by this daemon, such as zone transfer requests.
* badvers - Request had an EDNS OPT RR with a version higher than zero, which this daemon does not support (at the time of this writing, such a version doesn't even exist).
* formerr - Request was badly-formatted, but was sane enough that we did send a response with the rcode FORMERR.
* dropped - Request was so horribly malformed that we didn't even bother to respond (too short to contain a valid header, or had a UDP source port of zero).
* noerror - Request did not have any of the above problems.
* v6 -  Request was from an IPv6 client. This one isn't RCODE based, and is orthogonal to all other counts above.
* edns - Request contained an EDNS OPT-RR. Not RCODE-based, so again orthogonal to the RCODE-based totals above. Includes the ones that generated badvers RCODEs.
* edns\_do - EDNS requests which had the DO (DNSSEC OK) bit set
* edns\_client\_subnet - EDNS requests which contains a client-subnet option

These track client requests with the EDNS Cookie option.  Every such request increments exactly one of these four counters:

* edns\_cookie\_init - Cookie option contained just a client-side cookie value but no server cookie value
* edns\_cookie\_ok - Cookie option contained a correct client+server cookie combo we cryptographically validated
* edns\_cookie\_bad - Cookie option contained client+server cookies, but we don't recognize the values as valid
* edns\_cookie\_formerr - Cookie option had RFC-illegal cookie data length, causing FORMERR rejection of the request

The UDP thread(s) keep the following statistics at their own level of processing:

* udp.reqs - Total count of UDP requests received and passed on to the core DNS request handling code (this is synthesized by summing all of the RCODE-based stat counters above for the UDP threads).
* udp.recvfail - Count of UDP `recvmsg()` errors, where the OS indicated that something bad happened on receive. Obviously, we don't even get these requests, so they can't be processed and replied to.
* udp.sendfail - Count of UDP `sendmsg()` errors, which almost definitely resulted in dropped responses from the client's point of view.
* udp.tc - Non-EDNS (traditional 512-byte) UDP responses that were truncated with the TC bit set.
* udp.edns\_big - EDNS responses where the response was greater than 512 bytes (in other words, EDNS actually did something for you size-wise)
* udp.edns\_tc - EDNS responses where the response was truncated and the TC bit set, meaning that the client's specified edns buffer size (as also limited by our config) was too small for the data requested in spite of EDNS.

The TCP threads also count this stuff:

* tcp.reqs - Total count of TCP requests (again, synthesized by summing the RCODE-based stats for only TCP threads).
* tcp.recvfail - Count of abnormal failures in `recv()` on a DNS TCP socket, including ones where the sender indicated a payload larger than we're willing to accept.
* tcp.sendfail - Count of abnormal failures in `send()` on a DNS TCP socket.
* tcp.conns - Count of TCP connections we accepted (excludes extremely early failures, e.g. `accept()` itself returning an error)
* tcp.close\_c - Count of TCP connections closed cleanly by the client
* tcp.close\_s\_ok - Count of TCP connections closed cleanly by the server, usually due to an idle timeout being reached or during thread shutdown, etc.
* tcp.close\_s\_err - Count of TCP connections closed by the server due to an error such as `tcp_recvfail`, `tcp_sendfail`, or `dropped` from the general stats.
* tcp.close\_s\_kill - Count of TCP connections closed by the server, which were killed early to make room for a new client when `max_clients_per_thread` was reached.
* tcp.proxy - TCP conns initiated on PROXY protocol listeners (also incs `tcp.conns`)
* tcp.proxy\_fail - TCP PROXY conns killed for failure to parse an acceptable PROXY protocol header (also incs `tcp.close_s_err`)
* tcp.dso\_estab - TCP connections which established an RFC 8490 DSO session (can only happen up to once per connection)
* tcp.dso\_protoerr - TCP DSO sessions terminated un-gracefully due to client protocol violation (can only happen up to once per DSO session)
* tcp.dso\_typeni - Unrecognized DSO Request type received over TCP (could be with or without an established DSO session, and many times per connection/session).

These statistics are usually tracked in either 32-bit or 64-bit counters (depending on the platform) and exported to the user via `gdnsdctl stats`.  The implementation of the stats avoids stalls or locks in the I/O threads to minimize overhead.

### Truncation Handling

gdnsd generally aims for minimal responses in the first place, and follows very simplistic truncation rules.  It refuses to service partial RR sets or answers, and it only places RR sets in the additional section when they're necessary glue.  Therefore, from the truncation POV, there are only two kinds of responses: non-truncated ones that are full and complete, and truncated ones that contain zero RRs (other than the question and any application response OPT RR) and have the TC bit set.  The space for the EDNS OPT RR and any intended response option data is reserved from the start when applicable; it will never be elided to make room for other records.

## Rationale and Philosophy

This isn't a corporate-backed software.  There's no budget or team or financial interest at all.  Most of this software is written by me, a lone author who mostly works on this in gaps of spare time when I'm able.  I love the 3rd-party contributions the codebase has had from others over the years, but they've all been fairly minor in total scope.  We happen to also use it in production at my current day job at the non-profit Wikimedia Foundation, and also did so at my previous employer Logitech, and in those capacities I've occasionally been able to expend real work hours on this project where it directly impacted features we needed or bugs we cared about.  Beyond that though, while I have a fondness for this project and take pride in it, my time is limited.  This is reflected in the sometimes glacial pace of major feature development.  I'm also not the among the best developers in the world, so my capacity for handling increases in the complexity of this project is limited.  Any excess complexity burden slows things down even more.

I'm not a fan of the way most software is developed, where features accrete on features in endless succession like barnacles attaching to the hull of a ship until there's more barnacles than ship.  I think most developers don't spend enough time on quality, on refactoring, or on cleanliness, and I think they don't weigh the costs of every new feature (and every piece of old compatibility cruft) as heavily as they should.  I'm also not a fan of the kind of personal rigidity where one never questions one's own past decisions and thoughts.  I regularly make stupid design mistakes, and I don't want to have to live with them forever.  Software projects should at least try to value simplicity and purposeful design, and try to avoid the [Second System Effect](https://en.wikipedia.org/wiki/Second-system_effect).

It is in light of these values and my limited time and complexity budget that I've opted to ungracefully eradicate large swaths of gdnsd code and features during the development cycle leading up to the major version bump for 3.x.  In some cases I've backtracked on feature or design decisions because I think my past intents and/or rationales were flawed.  Sometimes it's that the world changed.  Sometimes it's just not worth the complexity budget anymore.  Many times it's a combination of several such factors.

The git statistics from v2.4.0..v3.0 (well, at the time of this writing, slightly before the cut of the actual 3.0) are telling, and I'm proud of the reductions shown there.  Ignoring all the quibbles about real "Lines of Code" (vs comments and whitespace and documentation and tests and build cruft, etc) and just looking at the raw git stats on files and lines, there was a net reduction of ~4K lines:

```
git diff --stat v2.4.0
[...]
258 files changed, 13646 insertions(+), 17748 deletions(-)
```

4K lines removed is roughly 6% of the original total, and the "deletions" stat is around 28%, if that's any better measure of total change.  This is all in spite of adding several new features.

## Future Directions

With the caveats that future is impossible to predict, and that if my thoughts on these subjects were fully-formed these things might already be done, these reflect my current mental state of affairs on various future gdnsd topics as of the release of 3.0.0:

### CPUs and IRQs

I'd like to implement auto-detection of CPU core counts for setting an automatic sane value for `udp_threads` and `tcp_threads`, perhaps ignoring thread-sibling CPU cores by default (physical core count rather than virtual).  Going a bit beyond this, we could also support explicitly taking better advantage of RSS IRQ spreading on Linux for those that have it configured, probably by allowing a manual or automatic mapping of I/O threads to CPU cores with affinity pinning, coupled with SO_ATTACH_REUSEPORT_EBPF or a similar mechanism to pin the traffic flow from card->gdnsd->card without ever leaving a single CPU core.  Possibly some of this should be NUMA-aware as well, as typically the NIC is attached directly to only one NUMA domain.  Some supporting features in this space may get added during a future 3.N feature release if I have time to sort out the details.

### Zone data and files

While I think 3.x's move to explicit, synchronous, whole reloads of all the zone data was the right move, I think some efficiency could be added back for those with giant sets of zonefiles without ruining the intent here.  Probably the simplest thing to do would be to track the full list of included files for a zone and all of their mtimes, and then simply not re-parse/load zones which haven't changed since they were last loaded, copying or aliasing the data over from the old dataset.  This would also need proper handling of symlink mtime/contents as well, to catch changes where e.g. a zone or include file is a symlink and just the symlink targeting changes.  Needs a flag to disable this as well, in case mtimes are known-bad or an operator with a small dataset doesn't want to take risks with mtime mistakes.

I still think we could hook up more advanced data backends, so long as they follow an explicit reload model.  For instance, we could have a SQL zone data backend, but there would be no live querying of SQL during live DNS response processing.  The data would be reloaded explicitly on-command, and the schema might ideally have some per-zone structure to it and some timestamp/serial by which we could optimize against reloading zones which haven't changed, as with files above.  I don't know when or if I'll have time to work on this myself, and I don't have any immediate needs for it myself, either.

### Plugins

The plugin APIs and all of the current plugins that use it are questionable and/or operating at the wrong abstraction levels.  I moved them into the daemon for now and killed the public API/ABI for 3.x as a first compat-breaking step towards fixing this situation.  I'd like to move all monitoring out of the main daemon through cleaner interfaces (more like current extfile/extmon methods, perhaps shipping a simple TCP/HTTP monitor to use with it?).  All of the non-trivial resolver plugins (simplefo, multifo, weighted, metafo, and geoip) could operate as a single new "plugin" from a unified structure and methodology that revolves around mapping and supports all their use-cases.  There might be a case for multiple in-daemon mappers to use with this plugin (e.g. swapping in something else where GeoIP or WRR fit into the scheme), but I think I'd still have those as in-tree alternatives and take source patches, as the cost/benefit just isn't there for a DSO system.

### The DYNA/DYNC resource types in general

I'm not fond of the design at this level either.  Probably DYNC should only return CNAMEs and not addresses (not really sure about this one), and probably DYNA should be broken up into separate types for A and AAAA.  Doing this to the existing names without breaking compatibility is hard, so I'll probably invent new names and leave some support in place for the old ones.  In light of all this, it would probably behoove users to move away from solutions that require DYNC to be able to return addresses, as that may be a major compatibility barrier in a future major version upgrade.

### Various DNS protocol-level privacy and security issues

The DNS really isn't where I'd like it to be on protocol level privacy and security issues.  DNSSEC only attacks the "can you trust your cache?" part of the problem, but ignores privacy and censorship issues and creates a lot of other problems along the way.  Other efforts are attempting to encrypt DNS communications to avoid both passive and active MITM of DNS communications as well as privacy leaks on the wire, but none of them are quite where they need to be yet, at least for the authserver case.  My random thoughts on various related (pseudo-)standards:

DNSSEC - I still dislike it.  I still think it has design issues, and should've been written off as a bad experiment years ago before it was widely deployed so we could do a fresh restart, instead of shoving it through into public usage.  I'm not going to detail all of its horrible faults here, it's easy enough these days to just provide links like [DNSSEC Outages](https://ianix.com/pub/dnssec-outages.html) (which has far more than outage info; scroll to the bottom for some great lists of DNSSEC-related CVEs and quotes from smart people bashing DNSSEC).  I think the DNS without DNSSEC is already incredibly complex, and with DNSSEC it's probably borderline impossible to build a reasonably-unbuggy implementation of an authserver that's reasonably fast and resilient.  I've been saying for years that I'll probably eventually be forced into implementing it by the rest of the world, but it hasn't happened yet!  Cloudflare has lead some important work in the past few years to make efficient and reasonable DNSSEC implementation and deployment much easier to achieve.  The primary things they've done in this space are: (1) Pushing against ANY use/abuse, resulting in the new HINFO ANY-refusal stuff that we're already implementing even in our non-DNSSEC code today, which is even more important under DNSSEC, (2) Coming up with the creative "black lies" solution to DNSSEC negative responses and (3) Pushing for ECDSA signing support and making it a viable option on the real Internet.  The thinking, research, experimentation, and advocacy they've done on these fronts is remarkable, and I think it's probably now within reach that gdnsd could conceivably implement DNSSEC (perhaps for 4.x) by following the path of these creative/pragmatic implementation decisions.

DNSCurve - I don't think DNSCurve is actually going anywhere anymore in terms of widespread adoption.  Much older versions of gdnsd implemented it for a while, but I eventually gave up on the standard.  I'm still sad about that, because there was a lot to really like about DNSCurve.  It just needed some minor fixups around key distribution and rollover practices (vs "encode the pubkey in the nameserver hostname").  DNSCrypt is similarly wonderful, but not applicable to gdnsd as an authserver.

DNS-over-HTTPS (DoH) - As far as I know, DoH efforts are only targeting the user-to-cache leg of things like DNSCrypt, and so they aren't really relevant here.  If this ever did apply to the authserver case, it would probably be simplest to just make it easy to configure a separate proxy daemon for it.

DNS-over-TLS (DoT) - Current standards for this also only target the user-to-cache leg, but DPRIVE is apparently eventually going to publish something about the cache-to-authserver leg, which is exciting.  I think we could implement this reasonably, assuming they don't end up making it require DNSSEC to be useful, in which case we'd be blocked on that until we support it.  Ditto for DNS-over-DTLS (DoDTLS?).  For now, gdnsd supports configuring a TCP PROXY protocol listener for use with an external TLS-terminating proxy daemon for experimentation in this area.  This may even be sufficient in the long haul, and is certainly much simpler than implementing TLS directly (even with a decent library!).
