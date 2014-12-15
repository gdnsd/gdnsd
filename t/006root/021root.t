# Basic dynamic resource tests

use _GDT ();
use Net::DNS;
use Test::More tests => 5;

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => '.', qtype => 'A',
    answer => '. 86400 A 192.0.2.3',
);

_GDT->test_dns(
    qname => 'www', qtype => 'A',
    answer => 'www 86400 A 192.0.2.4',
);

# A .com delegation
_GDT->test_dns(
    qname => 'www.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'com 86400 NS ns1.com',
        'com 86400 NS ns2.com',
    ],
    addtl => [
        'ns1.com 86400 IN A 192.0.2.5',
        'ns2.com 86400 IN A 192.0.2.6',
    ],
);

_GDT->test_kill_daemon($pid);
