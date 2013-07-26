
# Basic dynamic resource tests

use _GDT ();
use FindBin ();
use File::Spec ();
use Net::DNS;
use Test::More tests => 9;

my $pid = _GDT->test_spawn_daemon('etc001');

_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.254',
);

_GDT->test_dns(
    qname => 'dyn.example.com', qtype => 'A',
    answer => 'dyn.example.com 60 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'mdyn.example.com', qtype => 'A',
    answer => [
        'mdyn.example.com 60 A 127.0.0.1',
        'mdyn.example.com 60 A 192.0.2.1',
    ]
);

_GDT->test_dns(
    qname => 'mdyn-lots.example.com', qtype => 'A',
    answer => [
        'mdyn-lots.example.com 60 A 127.0.0.1',
        'mdyn-lots.example.com 60 A 192.0.2.1',
    ],
);

_GDT->test_dns(
    qname => 'mdyn-one.example.com', qtype => 'A',
    answer => [
        'mdyn-one.example.com 60 A 127.0.0.1',
        'mdyn-one.example.com 60 A 192.0.2.1',
    ],
    limit_v4 => 1
);

_GDT->test_dns(
    qname => 'addtl.example.com', qtype => 'MX',
    answer => 'addtl.example.com 86400 MX 0 dyn.example.com',
    addtl => 'dyn.example.com 60 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.254',
);

_GDT->test_kill_daemon($pid);
