# Basic plugin tests

use _GDT ();
use Test::More tests => 28;

my $neg_soa = 'example.com 900 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900';

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'example.com', qtype => 'SOA',
    answer => 'example.com 86400 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900',
);

_GDT->test_dns(
    v4_only => 1,
    qname => 'r.example.com', qtype => 'A',
    answer => 'r.example.com 86400 A 127.0.0.1',
);

_GDT->test_dns(
    v6_only => 1,
    qname => 'r.example.com', qtype => 'A',
    auth  => $neg_soa,
    addtl => 'r.example.com 86400 AAAA ::1',
);

_GDT->test_dns(
    v6_only => 1,
    qname => 'r.example.com', qtype => 'AAAA',
    answer => 'r.example.com 86400 AAAA ::1',
);

_GDT->test_dns(
    v4_only => 1,
    qname => 'r.example.com', qtype => 'AAAA',
    auth  => $neg_soa,
    addtl => 'r.example.com 86400 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'n.example.com', qtype => 'A',
    answer => 'n.example.com 86400 A 0.0.0.0',
    addtl => 'n.example.com 86400 AAAA ::',
);

_GDT->test_dns(
    qname => 'b41.example.com', qtype => 'A',
    answer => 'b41.example.com 86400 A 192.0.2.41',
);

_GDT->test_dns(
    qname => 'n-x.example.com', qtype => 'A',
    answer => 'n-x.example.com 86400 A 0.0.0.0',
    addtl => 'n-x.example.com 86400 AAAA ::',
);

_GDT->test_dns(
    qname => 'b41.example.com', qtype => 'A',
    answer => 'b41.example.com 86400 A 192.0.2.41',
);

_GDT->test_dns(
    qname => 'n-x.example.com', qtype => 'AAAA',
    answer => 'n-x.example.com 86400 AAAA ::',
    addtl => 'n-x.example.com 86400 A 0.0.0.0',
);

_GDT->test_dns(
    v4_only => 1,
    qname => 'addtl.example.com', qtype => 'MX',
    answer => 'addtl.example.com 86400 MX 0 r.example.com',
    addtl => 'r.example.com 86400 A 127.0.0.1',
);

_GDT->test_dns(
    v6_only => 1,
    qname => 'addtl.example.com', qtype => 'MX',
    answer => 'addtl.example.com 86400 MX 0 r.example.com',
    addtl => 'r.example.com 86400 AAAA ::1',
);

_GDT->test_dns(
    qname => 'f42.example.com', qtype => 'A',
    answer => 'f42.example.com 86400 A 192.0.2.42',
);

_GDT->test_dns(
    qname => 'example.com', qtype => 'NS',
    answer => [
        'example.com 86400 NS ns1.example.com',
        'example.com 86400 NS f42.example.com',
        'example.com 86400 NS ns1.example.net',
    ],
    addtl => [
        'ns1.example.com 86400 A 192.0.2.1',
        'f42.example.com 86400 A 192.0.2.42',
        'ns1.example.net 86400 A 192.0.2.41',
    ],
);

_GDT->test_dns(
    qname => 'www.subz.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subz.example.com 86400 NS ns1.subz.example.com',
    ],
    addtl => [
        'ns1.subz.example.com 86400 A 192.0.2.41',
    ],
);

_GDT->test_dns(
    qname => 'sfo1.example.com', qtype => 'A',
    answer => 'sfo1.example.com 86400 A 192.0.2.140',
);

_GDT->test_dns(
    qname => 'sfo2.example.com', qtype => 'A',
    answer => 'sfo2.example.com 86400 A 192.0.2.150',
);

_GDT->test_dns(
    qname => 'sfo3.example.com', qtype => 'A',
    auth => $neg_soa,
    addtl => 'sfo3.example.com 86400 AAAA 2001:DB8::DEAD',
);

_GDT->test_dns(
    qname => 'sfo4.example.com', qtype => 'AAAA',
    answer => 'sfo4.example.com 86400 AAAA 2001:DB8::B00',
);

_GDT->test_dns(
    qname => 'sfo5.example.com', qtype => 'AAAA',
    answer => 'sfo5.example.com 86399 AAAA 2001:DB8::AAA',
    addtl => 'sfo5.example.com 86399 A 192.0.2.170',
);

_GDT->test_dns(
    qname => 'mfo1.example.com', qtype => 'A',
    answer => [
        'mfo1.example.com 86400 A 192.0.2.101',
        'mfo1.example.com 86400 A 192.0.2.102',
        'mfo1.example.com 86400 A 192.0.2.103',
    ],
    addtl => [
        'mfo1.example.com 86400 AAAA 2001:DB8::101',
        'mfo1.example.com 86400 AAAA 2001:DB8::102',
    ],
);

_GDT->test_dns(
    qname => 'mfo1.example.com', qtype => 'AAAA',
    answer => [
        'mfo1.example.com 86400 AAAA 2001:DB8::101',
        'mfo1.example.com 86400 AAAA 2001:DB8::102',
    ],
    addtl => [
        'mfo1.example.com 86400 A 192.0.2.101',
        'mfo1.example.com 86400 A 192.0.2.102',
        'mfo1.example.com 86400 A 192.0.2.103',
    ],
);

_GDT->test_dns(
    qname => 'mfo2.example.com', qtype => 'A',
    answer => [
        'mfo2.example.com 86400 A 192.0.2.111',
        'mfo2.example.com 86400 A 192.0.2.112',
    ],
);

_GDT->test_dns(
    qname => 'mfo2.example.com', qtype => 'AAAA',
    auth => $neg_soa,
    addtl => [
        'mfo2.example.com 86400 A 192.0.2.111',
        'mfo2.example.com 86400 A 192.0.2.112',
    ],
);

_GDT->test_dns(
    qname => 'mfo3.example.com', qtype => 'AAAA',
    answer => [
        'mfo3.example.com 86400 AAAA 2001:DB8::Deca:fBad',
        'mfo3.example.com 86400 AAAA 2001:DB8::AD15:eA5e',
    ],
);

_GDT->test_dns(
    qname => 'adyn.example.com', qtype => 'A',
    answer => 'adyn.example.com 86400 A 192.0.2.41',
);

_GDT->test_kill_daemon($pid);
