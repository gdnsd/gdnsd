# Basic dynamic resource tests

use _GDT ();
use Net::DNS;
use Test::More tests => 10;

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'up.example.com', qtype => 'A',
    answer => 'up.example.com 50 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'down2.example.com', qtype => 'A',
    answer => 'down2.example.com 50 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'timeout.example.com', qtype => 'A',
    answer => 'timeout.example.com 50 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'down.example.com', qtype => 'A',
    answer => 'down.example.com 50 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'down-100-5.example.com', qtype => 'A',
    answer => 'down-100-5.example.com 100 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'up-100-5.example.com', qtype => 'A',
    answer => 'up-100-5.example.com 100 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'up-100.example.com', qtype => 'A',
    answer => 'up-100.example.com 100 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'down-21.example.com', qtype => 'A',
    answer => 'down-21.example.com 21 A 127.0.0.1',
);

_GDT->test_kill_daemon($pid);
