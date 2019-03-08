# Test experimental non-chaining CNAME behavior

use _GDT ();
use Test::More tests => 5;

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'cn2.example.com', qtype => 'A',
    answer => 'cn2.example.com 86400 CNAME cn1.example.com',
);

_GDT->test_dns(
    qname => 'cn1.example.com', qtype => 'A',
    answer => 'cn1.example.com 86400 CNAME ns1.example.com',
);

_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.1',
);

_GDT->test_kill_daemon($pid);
