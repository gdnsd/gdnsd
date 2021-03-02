# The gdnsd control socket protocol

## GENERAL RULES

The control socket protocol always has distinct "client" and "server" ends.
Generally the server is a gdnsd daemon, and the client is gdnsdctl or some
other obvious client.

More-concretely, however, the server is the party which `accept()`-ed a
connection on a listening socket, and the client is the one which connected to
it via `connect()`.  This distinction is important when considering the case of
inter-gdnsd-daemon connections for replace/takeover operations.  In these cases
it's always the newer daemon which connects as the client end and the existing
older daemon which accepts the connection as the server end.

## MESSAGES

All communications follow a standardized request message -> response message
pattern, where the client is always the first to speak with a request message,
and then the server replies with a response message.  *There is one corner-case
exception during the inter-daemon takeover procedure, which will be covered
later!*

All messages, in any direction, start with a standard 8-byte header.  The
sender of a message always sends a minimum of 8 bytes, and a receiver waiting
on a message always reads for a full 8 byte header initially.  In many cases,
the 8 byte header is the whole message.  In others, there is additional data
after the header, and the header provides enough information for the other end
to know what to expect.

The first header byte is always the key field `k`, which defines the type of
the message.  All keys are explicitly either a request-only key or a
response-only key.  In the gdnsd source code they're given mnemonic defines
like `REQ_FOO` or `RESP_FOO`.  All of the currently-defined keys are printable
ASCII bytes that have some mnemonic utility, but this isn't a hard requirement.

The next three bytes, in order, are called `v0`, `v1`, and `v2` (sometimes
collectively referred to as `v`), and then the final four bytes are
collectively called `d`:

| Byte: |  0  |  1  |  2  |  3  |  4  |  5  |  6  |  7  |
| ----- | --- | --- | --- | --- | --- | --- | --- | --- |
| Use:  |  k  |  v0 |  v1 |  v2 |  d  |  d  |  d  |  d  |

The meaning of the 7 bytes after the key are in general defined by the key and
can vary, but in broad general strokes:

The ordered `v` bytes sometimes contain gdnsd version numbers for protocol
compatibility, with `v0` carrying the major number, `v1` the minor, and `v2`
the patch level.  In some other contexts, the v bytes are used together as a
24-bit network-order unsigned integer representing some kind of "count" field
specific to the request (usually an abstract count of objects rather than a
count of bytes).

The four bytes of `d` are typically used as an unsigned 32-bit integer in host
order, and typically give the byte length of a block of data that follows the
header.

Currently the entire protocol is conducted using native host byte order where
that makes a difference.  Byte order doesn't matter for single-byte fields in
the first half of the header (`k`, `v0`, `v1`, and `v2`), but it does matter
for the the 4-byte `d` field, and it can matter for some of the extended data
responses that may follow a header.

For local unix sockets byte order doesn't normally present a problem, but we
did tack on TCP control socket support in the middle of the 3.x release series,
and there it does matter!  For the 3.x release series, these sockets will only
work correctly between clients and servers built on platforms of the same
endian-ness.  This is intended to be fixed in a backwards- and forwards-
compatible way in 4.x, with the result being that 4.x (and later) clients and
servers speak in network-order to each other, but emit and expect native host
order when speaking to 3.x clients and servers.

## RESPONSE KEYS:

There only five response message keys currently defined.  They're not specific
to certain request types, but instead are typed by the dispostion of the
request.  Quoting from the header file:

    #define RESP_ACK  'A' // response: OK (V, D, and following data defined by the request type)
    #define RESP_DENY 'D' // response: Denied by policy (e.g. for TCP)
    #define RESP_FAIL 'F' // response: Failed (generic failure, bubble up to user)
    #define RESP_LATR 'L' // response: Try Again Later (delay and/or reconnect!)
    #define RESP_UNK  'U' // response: Unknown request type

As noted above, the `v`, `d`, and possible follow-on response data bytes for a
`RESP_ACK` depend on the type of request it was in response to.  For all of the
others, the `v` and `d` bytes carry no meaning (and are currently set to zero)
and there is no further data.

`RESP_LATR` is currently sent in response to all state-changing requests (e.g.
reload-zones, replace, acme challenge requests, etc) when there is an active
daemon `replace` takeover attempt in progress.  The takeover attempt will
eventually either succeed (resulting in a brand-new server daemon at a
different PID handling the control socket) or fail (resulting in the existing
daemon going back to its normal operational mode), and the client is being
asked to delay and retry its operation until we reach one of those states and
it can get a normal response again.  The canonical `gdnsdctl` client handles
this by closing the client connection, sleeping for 1 second, and then trying
again on a fresh connection.  It loops on this behavior until it gets some
other response than `RESP_LATR`, or until its overall timeout limit is reached.

## REQUEST KEYS:

The request keys can be logically grouped into three sets: the "readonly" keys
which request information from the server but do not alter the server's state,
the "readwrite" keys which attempt to alter the server's state, and then the
special set of keys that are only used on connections between two daemons
during a takeover operation and aren't intended for use by any other client
(even gdnsdctl).  We'll go through the first two sets here one key at a time,
and then cover the inter-daemon set separately in the next section, which
describes the takeover sequence as a whole.

Note that while there are some operational notes here that might be relevant to
writing a client, in general this is a protocol-level description, and a fuller
explanation of the operational impacts is in the `gdnsdctl` documentation for
the equivalent action.

### `REQ_INFO` - Get basic version info and daemon PID

* REQ Key: `I`
* Type: Readonly
* REQ Fields: V: client version D: 0
* ACK Fields: V: server version D: PID of daemon

Note that the client side code in versions <= 3.6.0 did not send their version
info in the request and left the V fields as all-zeros, while later versions
are expected to fill it in properly.  The server side has always sent version
information in the ACK.

As a general rule, most connections should start with a `REQ_INFO` to establish
version info for compatibility and check the liveness and correctness of the
connection in general.  This is not a hard requirement yet, but it may
effectively become one with the byte order fixes expected in 4.x, for clients
expecting to navigate that transition smoothly!

### `REQ_STAT` - Get stats from the daemon

* REQ Key: `S`
* Type: Readonly
* REQ Fields: V: 0 D: 0
* ACK Fields: V: 0 D: bytes of data to follow
* ACK Data: A string of JSON text data of byte length D

### `REQ_STATE` - Get monitored states from the daemon

* REQ Key: `E`
* Type: Readonly
* REQ Fields: V: 0 D: 0
* ACK Fields: V: 0 D: bytes of data to follow
* ACK Data: A string of JSON text data of byte length D

### `REQ_ZREL` - Ask daemon to reload zonefiles

* REQ Key: `Z`
* Type: Readwrite
* REQ Fields: V: 0 D: 0
* ACK Fields: V: 0 D: 0

A `RESP_ACK` response to this command is synchronous and confirms that the
reload was already successfully completed.  In the case of a timeout,
disconnect, or other response type, the client cannot assume success.

### `REQ_STOP` - Ask the daemon to stop itself

* REQ Key: `X`
* Type: Readwrite
* REQ Fields: V: 0 D: 0
* ACK Fields: V: 0 D: 0

A `RESP_ACK` response to this command indicates that the server is willing to
stop and has begun the process of shutting itself down.  It does *not* indicate
that the stop is complete.  The file descriptor for the control socket
connection which sent the `REQ_STOP` will be left open by the server so that
the OS closes it implicitly on process exit, allowing the client to precisely
and synchronously observe when the process actually exits by waiting for an EOF
on the socket after the ACK.

### `REQ_REPL` - Ask the daemon to replace itself with a new daemon

* REQ Key: `R`
* Type: Readwrite
* REQ Fields: V: 0 D: 0
* ACK Fields: V: 0 D: 0

The `RESP_ACK` for this is synchronous and can take longer than most to arrive.
It indicates that the entire replacement operation was successful and the new
replacement daemon is up and running successfully and answering requests.
However, at this point the old daemon has not yet exited (it is sending the
ACK, after all).  Observing the exit of the old daemon is the same as
`REQ_STOP` above: read for EOF, which happens when the OS implicitly closes the
control socket file descriptor.  When `gdnsdctl` does a replace, after
observing the old daemon's death in this manner, it also does a `REQ_INFO` to
the new daemon on a fresh connection afterwards to confirm.

### `REQ_CHAL` - Add ACME challenge responses

* REQ Key: `C`
* Type: Readwrite
* REQ Fields: V: count D: data length in bytes
* REQ DATA: V items of challenge data totalling D bytes
* ACK Fields: V: 0 D: 0

Note that this is the only current *request* message that sends follow-on data
after the header.  The length of each challenge is variable (depends on the
hostname in question).  The format isn't actually documented here yet, and
that's partly because it's kind of ugly and might get fixed eventually.

### `REQ_CHALF` - Flush all ACME challenge responses

* REQ Key: `c`
* Type: Readwrite
* REQ Fields: V: 0 D: 0
* ACK Fields: V: 0 D: 0

## The inter-daemon takeover sequence and messages

The general `REQ_REPL` command above (which is what `gdnsdctl replace` does)
instructs a daemon to launch a replacement of itself, which it does by
executing a new copy of its own binary (which could be a different version on
disk) as a detached child process with a special commandline argument `-R` that
allows it to detect and take over operations from an existing daemon on
startup.

Replacement daemons can also be started up independently with that flag,
allowing for other execution models where it doesn't make sense to spawn the
replacement as a child of the old daemon.

The core protocol sequence here describes how the two daemon processes interact
during the takeover process, regardless of how the replacement daemon was
launched.  Some parts of the sequence re-use some of the standard message types
above, but the hard parts use four unique message types that only exist for use
in this sequence, which we'll describe below as we encounter them.

While we might make a best effort at maintaining and documenting compatibility
issues for third party control socket clients in the general case, the
takeover-specific parts aren't really meant for third party use and don't have
such guarantees.

What follows here is a description of the sequence of constrol socket requests
the new daemon sends to the old one, along with some explanatory text about
about what each daemon is doing at the time, at least in the common case of a
simple successful execution of the plan.

Not every operational detail is covered here.  In particular, both sides take
some defensive measures that aren't detailed here to ensure that at least one
daemon continues providing service in the case that the other daemon fails
mysteriously and/or spectacularly.  In some edge cases, this might even leave
both daemons running in parallel, but in this case there should be some
indication of a problem in the logs, or in the final result of `gdnsdctl`, to
alert the administrator.

### `REQ_INFO`

The very first step in a takeover is that the new daemon connects to the old
daemon's control socket as a client and sends a `REQ_INFO` like any other
client.  This is mostly just a healthcheck, but in some cases the version
exchange could provide critical compatibility info, especially if there have
been changes to this sequence over time.

### `REQ_TAK1` - Takeover phase 1 - notification/locking

* REQ Key: `1`
* Type: Takeover
* REQ Fields: V: 0 D: new daemon PID
* ACK Fields: V: 0 D: 0

The purpose of `REQ_TAK1` is to inform the server of our intent to take over
and get it to lock onto us as *the* replacement daemon.  If there are multiple,
independently-spawned replacement daemons racing each other, only one will win
here, and the others will get a `RESP_LATR`.  Both the new daemon's reported
PID and the connection become special at this point.  All further takeover
steps must share the same connection and PID value in order to be successful.

In the special (but common) case that a replacement daemon was spawned by the
old daemon itself (which happens with `REQ_REPL` from `gdnsdctl replace`), the
old daemon already knows the PID of the replacement daemon it spawned, and
locks onto that replacement PID value immediately and doesn't allow `REQ_TAK1`
from other PIDs, even if they manage to send their `REQ_TAK1` before the
self-spawned daemon it's waiting on.

Aside from locking onto a specific replacement PID and connection, the only
other immediate action the old daemon takes after a successful `REQ_TAK1` is
that it sends `RESP_LATR` to all outstanding control socket connections which
were waiting on the completion of a `REQ_ZREL` (reload-zones) operation.

From this point forward (until full success or failure of the takeover), the
old daemon begins responding to all other new requests for state-changing
operations from other clients with `RESP_LATR` as well.

The new daemon, after seeing the ACK of its `REQ_TAK1`, proceeds with all of
the expensive and time-consuming parts of a new daemon's startup: parsing and
handling all of the configuration, loading all of the zonefiles, setting up
plugins, geoip database loads, initial monitoring rounds, etc.  It doesn't yet
reach the point of doing publically visible things yet (like opening listen
sockets for the control socket itself or DNS).  Then it does:

### `REQ_TAK2` - Takeover phase 2 - challenge handoff

* REQ Key: `2`
* Type: Takeover
* REQ Fields: V: 0 D: new daemon PID
* ACK Fields: V: count of challenges D: data byte count for all challenges
* ACK DATA: all live challenges in the old daemon

As noted above, this can only be successful for the same connection and PID
value as a previously successful `REQ_TAK1`.

This requests the old daemon dump all live, ephemeral ACME challenge data
over to the new daemon, so that it can initialize the same set for itself to
preserve continuity.  The format is very similar to how regular clients send
new challenges to a server.  This data arrives with the old daemon's `RESP_ACK`
as noted above.  Technically, this whole phase could be skipped by a new daemon
that didn't care about ACME data and the protocol would still proceed
successfully.

The new daemon takes a few other quick startup steps at this point (related to
some quick plugin code setup and eventloop-related things), and then proceeds
onwards by sending:

### `REQ_TAKE` - Takeover phase 3 - Sockets!

* REQ Key: `T`
* Type: Takeover
* REQ Fields: V: 0 D: new daemon PID
* ACK Fields: V: count of socket fds D: 0
* ACK DATA: No actual in-band data, but the whole count of fds indicated above
is in one or more `SCM_RIGHTS` control messages over the socket.

Again, `REQ_TAKE` can only happen on the same connection that established
itself via `REQ_TAK1` earlier.

This is the heart of the real takeover process.  A lot of things happen very
quickly on both sides with almost no likelihood of any long-blocking
operations, so it's easier if we step through this slowly and describe what's
happening synchronously on both sides:

First, the new daemon attempts to lock the control socket lock, like a normal
non-replace startup would do.  This will fail because the old daemon is still
running and has it locked.  (If for some reason it doesn't fail (say, the old
daemon somehow exited or died on us since we started this process), the new
daemon will take the lock and proceed with a normal non-replace startup
sequence from here forward).  Then, the new daemon sends the actual `REQ_TAKE`
to the old daemon.

On reception of a legitimate `REQ_TAKE` message, the old daemon first stops
accepting new requests on its control socket listening fd(s), to ensure there
is only one daemon at a time accepting connections on them.  It's still
*listening* for new connections, it's just not actively invoking `accept()` to
receive them anymore and they're queueing up somewhere in the kernel.  If the
takeover process fails at some point from here forward (including even the
death or malfunction of the new daemon, or a timeout from some such thing), the
old daemon will eventually begin accepting fresh control socket connections
again after logging about the failure.

Then, the old daemon sends its `RESP_ACK` followed by a bunch of file
descriptors sent via `SCM_RIGHTS` control message(s).  The first two file
descriptors are the control socket listener's lock fd and socket fd.  The rest
of the fds are all of the DNS listener fds the old daemon is using to handle
DNS requests.

The new daemon takes possession of the passed csock lock and sock fds as if it
had created them for itself in a normal startup (but it's also not yet
`accept()`-ing on the listening socket just yet).  It has already parsed its
own DNS listener configuration much earlier, which may differ from the listener
configuration of the old daemon.  It iterates over all of the DNS listen
sockets given to it by the old daemon and matches them up with its new
configuration to re-use any that are still applicable (which would be all of
them, if there was no listener configuration change).

It then quickly closes any that it can't make use of (e.g. because a listen
address is no longer configured, or a thread/socket count was reduced), and
then creates new listening sockets for any configured ones that weren't
supplied by the old daemon (e.g. new listen addresses, increased thread/socket
counts), and then starts up its DNS listening threads, which can immediately
begin processing requests, and waits for them all to quickly report their
successful startups to the main thread through a mechanism based on pthread
condition variables.

Note that, at this moment in time, *both* daemons have active i/o threads
answering public requests, and you will get a blend of public responses from
both daemons for a very short time, which is how we ensure zero downtime on
replacement.

    Side note: This sounds scarier than it really is to some people sometimes,
    especially if the replace operation could carry zone data changes, but in
    the real world if this were a real problem, lots of other common things
    would be a real problem, too.  The same kind of overlap also happens (on a
    probably shorter timescale) between DNS I/O threads every time zone data is
    reloaded as well.  The bottom line is that no single change in the DNS
    (even without gdnsd) is globally-atomic anyways, and this also comes up in
    the case of applying zone data updates to multiple distinct authdns
    servers, as well as the view of those updates through various global 3rd
    party DNS caches and recursors.  This is why complex DNS changes must often
    be broken up into multiple distinct deployment steps, separated by
    TTL-based time, which are each individually ok for asynchronous deployment.

From this point forward the new daemon will not fail fatally due to anything
about this inter-daemon sequence below.  If the rest of this fails, it just
carries on and stays alive, as we are past the point of no return.

At this point the new daemon proceeds with sending....

### `REQ_STOP`

This is the same standard `REQ_STOP` that gdnsdctl uses to stop a daemon as
well, and the new daemon now uses it to to ask the old one to shut itself down
over the replacement connection (note, during this whole process, other
`REQ_STOP` from other arbitrary clients would just get a `RESP_LATR`).  The old
daemon ACKs the stop and begins its shutdown sequence, but with one exception
from the normal stop sequence:

After it has confirmed the clean shutdown of all of its DNS I/O threads
(meaning it can no longer process any new public DNS requests), but just before
it finally exits, it sends one last message over the replacement control
socket.  This is a truly oddball case, in that it's the only case where the
"server" end of the connection sends an unsolicited message to the "client" and
doesn't fit our general req -> resp model:

### `PSH_SHAND`

* PSH Key: `s`
* Type: Takeover
* PSH Fields: V: 0 D: data len (multiple of 8)
* PSH DATA: "D" bytes of data, which is D/8 64-bit stats counters.

This is the (old-)server-pushed stats handoff message.  Because the old daemon
is done handling requests, it can now hand off a consistent set of final stats
counters to the new daemon.  While the new daemon, at this stage, is already
answering requests and recording its own new stats counters, it has not yet had
its main thread enter its normal runtime eventloop, and thus it hasn't answered
any stats requests from clients yet.  It imports these numbers as a baseline
set of counts which its own running counters are added to at output time, and
thus from a naive client's point of view, stats continuity is always preserved
as if nothing funny ever happened and it was just one daemon running forever.

All stats are transmitted as 64-bit values regardless of the platform, even in
cases (e.g. 32-bit i386) where the internal stats counters normally roll over
at the 32-bit mark.  The set of stats is ordered according to an enum in
`src/statio.c`.  New stats can only be added at the end, and deprecated old
stat slots must be left in place  at zero for all time, basically.  In
downgrade cases, excess stats from a newer version are ignored.  There are only
34 stats so far as of this writing, so we're a long way from having to worry
about how simplistic this scheme is, for now!

As soon as it's done sending over the stats, the old daemon quickly exits.  As
soon as the new daemon receives these stats (or fails to, non-fatally), its
main thread enters the normal runtime eventloop where it will handle normal
control socket traffic, signals, etc, and we're done.
