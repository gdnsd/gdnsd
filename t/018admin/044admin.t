use _GDT ();
use Net::DNS;
use Test::More tests => 60;

my $pid = _GDT->test_spawn_daemon();

my $ext_statedir = $_GDT::OUTDIR . "/var/lib/gdnsd/extfile";
mkdir($ext_statedir)
    or die "mkdir('$_') failed: $!";

# ra: primary up, secondary up
_GDT->write_statefile('extfile/extf_admin', qq{
    127.3.3.3 => up
    192.0.2.3 => up
});

# The above makes no real changes, as the initial states for a missing
#  extfile are "up", but this should check the file is loaded at all
_GDT->test_log_output(q{plugin_extfile: Service type 'extf_admin': loaded new data from file });

### Initial state, nothing forced

_GDT->test_dns(
    qname => 'r1.example.com', qtype => 'A',
    answer => 'r1.example.com 42 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'r2.example.com', qtype => 'A',
    answer => 'r2.example.com 42 A 127.2.2.2',
);

_GDT->test_dns(
    qname => 'm1.example.com', qtype => 'A',
    answer => 'm1.example.com 42 CNAME m1cname.example.net',
);

_GDT->test_dns(
    qname => 'ra.example.com', qtype => 'A',
    answer => 'ra.example.com 42 A 127.3.3.3',
);

### Force r1+r2 primary addrs down via wildcard

_GDT->write_statefile('admin_state', qq{
    127.*/up => DOWN/33
});

_GDT->test_log_output([
    q{admin_state: state of '127.2.2.2/up' forced to DOWN/33, real state is UP/MAX},
    q{admin_state: state of '127.0.0.1/up' forced to DOWN/33, real state is UP/MAX},
]);

_GDT->test_dns(
    qname => 'r1.example.com', qtype => 'A',
    answer => 'r1.example.com 33 A 192.0.2.1',
);

_GDT->test_dns(
    qname => 'r2.example.com', qtype => 'A',
    answer => 'r2.example.com 33 A 192.0.2.2',
);

_GDT->test_dns(
    qname => 'm1.example.com', qtype => 'A',
    answer => 'm1.example.com 42 CNAME m1cname.example.net',
);

### Leave those down and also down m1cname for m1

_GDT->write_statefile('admin_state', qq{
    127.*/up => DOWN/33
    m1cname.example.net./up => DOWN/29
});

_GDT->test_log_output(q{admin_state: state of 'm1cname.example.net./up' forced to DOWN/29, real state is UP/MAX});

_GDT->test_dns(
    qname => 'r1.example.com', qtype => 'A',
    answer => 'r1.example.com 33 A 192.0.2.1',
);

_GDT->test_dns(
    qname => 'r2.example.com', qtype => 'A',
    answer => 'r2.example.com 33 A 192.0.2.2',
);

_GDT->test_dns(
    qname => 'm1.example.com', qtype => 'A',
    answer => 'm1.example.com 29 A 192.0.2.1',
);

### Leave m1cname down, remove the wildcard, but replace it with
###   a non-wildcard entry that covers just r2 primary

_GDT->write_statefile('admin_state', qq{
    m1cname.example.net./up => DOWN/29
    127.2.2.2/up => DOWN/33
});

_GDT->test_log_output(q{admin_state: state of '127.0.0.1/up' no longer forced (was forced to DOWN/33), real and current state is UP/MAX});

_GDT->test_dns(
    qname => 'r1.example.com', qtype => 'A',
    answer => 'r1.example.com 42 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'r2.example.com', qtype => 'A',
    answer => 'r2.example.com 33 A 192.0.2.2',
);

_GDT->test_dns(
    qname => 'm1.example.com', qtype => 'A',
    answer => 'm1.example.com 29 A 127.0.0.1',
);

### Remove the r2 primary entry

_GDT->write_statefile('admin_state', qq{
    m1cname.example.net./up => DOWN/29
});

_GDT->test_log_output(q{admin_state: state of '127.2.2.2/up' no longer forced (was forced to DOWN/33), real and current state is UP/MAX});

_GDT->test_dns(
    qname => 'r1.example.com', qtype => 'A',
    answer => 'r1.example.com 42 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'r2.example.com', qtype => 'A',
    answer => 'r2.example.com 42 A 127.2.2.2',
);

_GDT->test_dns(
    qname => 'm1.example.com', qtype => 'A',
    answer => 'm1.example.com 29 A 127.0.0.1',
);

### Empty the state file completely, back to original query results

_GDT->write_statefile('admin_state', qq{
});

_GDT->test_log_output(q{admin_state: state of 'm1cname.example.net./up' no longer forced (was forced to DOWN/29), real and current state is UP/MAX});

_GDT->test_dns(
    qname => 'r1.example.com', qtype => 'A',
    answer => 'r1.example.com 42 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'r2.example.com', qtype => 'A',
    answer => 'r2.example.com 42 A 127.2.2.2',
);

_GDT->test_dns(
    qname => 'm1.example.com', qtype => 'A',
    answer => 'm1.example.com 42 CNAME m1cname.example.net',
);

### down dc1 at the datacenter level

_GDT->write_statefile('admin_state', qq{
    metafo/m1/dc1 => DOWN
});

_GDT->test_log_output(q{admin_state: state of 'metafo/m1/dc1' forced to DOWN/MAX, real state is NA});

_GDT->test_dns(
    qname => 'r1.example.com', qtype => 'A',
    answer => 'r1.example.com 42 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'r2.example.com', qtype => 'A',
    answer => 'r2.example.com 42 A 127.2.2.2',
);

_GDT->test_dns(
    qname => 'm1.example.com', qtype => 'A',
    answer => 'm1.example.com 42 A 127.0.0.1',
);

### down dc1+dc2 at the datacenter level (so result is back to dc1)

_GDT->write_statefile('admin_state', qq{
    metafo/m1/dc? => DOWN
});

_GDT->test_log_output(q{admin_state: state of 'metafo/m1/dc2' forced to DOWN/MAX, real state is NA});

_GDT->test_dns(
    qname => 'r1.example.com', qtype => 'A',
    answer => 'r1.example.com 42 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'r2.example.com', qtype => 'A',
    answer => 'r2.example.com 42 A 127.2.2.2',
);

_GDT->test_dns(
    qname => 'm1.example.com', qtype => 'A',
    answer => 'm1.example.com 42 CNAME m1cname.example.net',
);

### switch over to dc2 still down, dc1 forced UP

_GDT->write_statefile('admin_state', qq{
    metafo/m1/dc1 => UP
    metafo/m1/dc2 => DOWN
});

_GDT->test_log_output(q{admin_state: state of 'metafo/m1/dc1' re-forced from DOWN/MAX to UP/MAX, real state is NA});

_GDT->test_dns(
    qname => 'r1.example.com', qtype => 'A',
    answer => 'r1.example.com 42 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'r2.example.com', qtype => 'A',
    answer => 'r2.example.com 42 A 127.2.2.2',
);

_GDT->test_dns(
    qname => 'm1.example.com', qtype => 'A',
    answer => 'm1.example.com 42 CNAME m1cname.example.net',
);

### ... now down the resource within dc1, which should
###   be suppressed by the forced UP state

_GDT->write_statefile('admin_state', qq{
    metafo/m1/dc1 => UP
    metafo/m1/dc2 => DOWN
    m1cname.example.net./up => DOWN/25
});

_GDT->test_log_output(q{admin_state: state of 'm1cname.example.net./up' forced to DOWN/25, real state is UP/MAX});

_GDT->test_dns(
    qname => 'r1.example.com', qtype => 'A',
    answer => 'r1.example.com 42 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'r2.example.com', qtype => 'A',
    answer => 'r2.example.com 42 A 127.2.2.2',
);

_GDT->test_dns(
    qname => 'm1.example.com', qtype => 'A',
    answer => 'm1.example.com 42 CNAME m1cname.example.net',
);

### ra tests extfile + admin state operating on the same resource,
###  with log checks for both

# admin-downing the primary for ra will flip it to the secondary answer
_GDT->write_statefile('admin_state', qq{
    metafo/m1/dc1 => UP
    metafo/m1/dc2 => DOWN
    127.3.3.3/extf_admin => DOWN
    m1cname.example.net./up => DOWN/25
});

_GDT->test_log_output(q{admin_state: state of '127.3.3.3/extf_admin' forced to DOWN/MAX, real state is UP/MAX});

_GDT->test_dns(
    qname => 'ra.example.com', qtype => 'A',
    answer => 'ra.example.com 42 A 192.0.2.3',
);

# ra: primary up, secondary down, this will flip the answer
#   back to primary with both effectively down
_GDT->write_statefile('extfile/extf_admin', qq{
    127.3.3.3 => up
    192.0.2.3 => down
});

_GDT->test_log_output(q{state of '192.0.2.3/extf_admin' changed from UP/MAX to DOWN/MAX});

_GDT->test_dns(
    qname => 'ra.example.com', qtype => 'A',
    answer => 'ra.example.com 42 A 127.3.3.3',
);

# now force the secondary up as well to flip it back again....
_GDT->write_statefile('admin_state', qq{
    metafo/m1/dc1 => UP
    metafo/m1/dc2 => DOWN
    127.3.3.3/extf_admin => DOWN
    192.0.2.3/extf_admin => UP
    m1cname.example.net./up => DOWN/25
});

_GDT->test_log_output(q{admin_state: state of '192.0.2.3/extf_admin' forced to UP/MAX, real state is DOWN/MAX});

_GDT->test_dns(
    qname => 'ra.example.com', qtype => 'A',
    answer => 'ra.example.com 42 A 192.0.2.3',
);

# this switches extfile state to match forced state, no real change
_GDT->write_statefile('extfile/extf_admin', qq{
    127.3.3.3 => down
    192.0.2.3 => up
});

_GDT->test_log_output([
    q{state of '127.3.3.3/extf_admin' changed from UP/MAX to DOWN/MAX, effective state remains administratively forced to DOWN/MAX},
    q{state of '192.0.2.3/extf_admin' changed from DOWN/MAX to UP/MAX, effective state remains administratively forced to UP/MAX},
]);

_GDT->test_dns(
    qname => 'ra.example.com', qtype => 'A',
    answer => 'ra.example.com 42 A 192.0.2.3',
);

# now mismatch them again, still not affecting output due to forcing
_GDT->write_statefile('extfile/extf_admin', qq{
    127.3.3.3 => up
    192.0.2.3 => down
});

_GDT->test_log_output([
    q{state of '127.3.3.3/extf_admin' changed from DOWN/MAX to UP/MAX, effective state remains administratively forced to DOWN/MAX},
    q{state of '192.0.2.3/extf_admin' changed from UP/MAX to DOWN/MAX, effective state remains administratively forced to UP/MAX},
]);

_GDT->test_dns(
    qname => 'ra.example.com', qtype => 'A',
    answer => 'ra.example.com 42 A 192.0.2.3',
);

# remove one of the administrative forcings, causing a visible change
_GDT->write_statefile('admin_state', qq{
    metafo/m1/dc1 => UP
    metafo/m1/dc2 => DOWN
    192.0.2.3/extf_admin => UP
    m1cname.example.net./up => DOWN/25
});

_GDT->test_log_output(q{admin_state: state of '127.3.3.3/extf_admin' no longer forced (was forced to DOWN/MAX), real and current state is UP/MAX});

_GDT->test_dns(
    qname => 'ra.example.com', qtype => 'A',
    answer => 'ra.example.com 42 A 127.3.3.3',
);

# switch extfile 127.3.3.3 to down.  if it were not for admin_state
#   still forcing 192.0.2.3 up, both being down would cause 127 to be returned...
_GDT->write_statefile('extfile/extf_admin', qq{
    127.3.3.3 => down
    192.0.2.3 => down
});

_GDT->test_run_gdnsdctl("states");

_GDT->test_log_output(q{state of '127.3.3.3/extf_admin' changed from UP/MAX to DOWN/MAX});

_GDT->test_dns(
    qname => 'ra.example.com', qtype => 'A',
    answer => 'ra.example.com 42 A 192.0.2.3',
);

# release the remaining forced-up admin_state by unlinking the whole file,
# switching the answer back to 127
unlink(${_GDT::OUTDIR} . "/var/lib/gdnsd/admin_state");

_GDT->test_log_output(q{admin_state: state of '192.0.2.3/extf_admin' no longer forced (was forced to UP/MAX), real and current state is DOWN/MAX});

_GDT->test_dns(
    qname => 'ra.example.com', qtype => 'A',
    answer => 'ra.example.com 42 A 127.3.3.3',
);

_GDT->test_kill_daemon($pid);
