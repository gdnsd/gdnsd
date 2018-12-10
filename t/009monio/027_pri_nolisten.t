# Basic dynamic resource tests

use _GDT ();
use Net::DNS;
use Test::More tests => 6;

my $pid = _GDT->test_spawn_daemon('etc001');

_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.254',
);

_GDT->test_dns(
    qname => 'dyn.example.com', qtype => 'A',
    answer => 'dyn.example.com 120 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'mdyn.example.com', qtype => 'A',
    answer => [
        'mdyn.example.com 120 A 127.0.0.1',
        'mdyn.example.com 120 A 192.0.2.1',
    ]
);

_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.254',
);

_GDT->test_kill_daemon($pid);
