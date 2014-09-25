
use _GDT ();
use FindBin ();
use File::Spec ();
use Net::DNS;
use Test::More tests => 41;

my $pid = _GDT->test_spawn_daemon();

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
    answer => [
        'm1.example.com 42 CNAME m1cname.example.com',
        'm1cname.example.com 42 A 192.0.2.42',
    ]
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
    answer => [
        'm1.example.com 42 CNAME m1cname.example.com',
        'm1cname.example.com 42 A 192.0.2.42',
    ]
);

### Leave those down and also down m1cname for m1

_GDT->write_statefile('admin_state', qq{
    127.*/up => DOWN/33
    m1cname/up => DOWN/29
});

_GDT->test_log_output(q{admin_state: state of 'm1cname/up' forced to DOWN/29, real state is UP/MAX});

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
    m1cname/up => DOWN/29
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
    m1cname/up => DOWN/29
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

_GDT->test_log_output(q{admin_state: state of 'm1cname/up' no longer forced (was forced to DOWN/29), real and current state is UP/MAX});

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
    answer => [
        'm1.example.com 42 CNAME m1cname.example.com',
        'm1cname.example.com 42 A 192.0.2.42',
    ]
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
    answer => [
        'm1.example.com 42 CNAME m1cname.example.com',
        'm1cname.example.com 42 A 192.0.2.42',
    ]
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
    answer => [
        'm1.example.com 42 CNAME m1cname.example.com',
        'm1cname.example.com 42 A 192.0.2.42',
    ]
);

### ... now down the resource within dc1, which should
###   be suppressed by the forced UP state

_GDT->write_statefile('admin_state', qq{
    metafo/m1/dc1 => UP
    metafo/m1/dc2 => DOWN
    m1cname/up => DOWN/25
});

_GDT->test_log_output(q{admin_state: state of 'm1cname/up' forced to DOWN/25, real state is UP/MAX});

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
    answer => [
        'm1.example.com 42 CNAME m1cname.example.com',
        'm1cname.example.com 42 A 192.0.2.42',
    ]
);

_GDT->test_kill_daemon($pid);
