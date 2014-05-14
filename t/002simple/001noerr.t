
# These are all the "positive" tests for 002simple's example.com zone,
#  as in tests that return actual valid data from the DB with NOERROR rcode

use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 19;

my $standard_auth = [
    'example.com 86400 NS ns1.example.com',
    'example.com 86400 NS ns2.example.com',
    'example.com 86400 NS ns3.goober.example.com',
    'example.com 86400 NS ns4.goober.example.com',
];

my $standard_auth_addtl = [
    'ns1.example.com 86400 A 192.0.2.5',
    'ns2.example.com 86400 A 192.0.2.6',
    'ns3.goober.example.com 86400 A 192.0.2.7',
    'ns4.goober.example.com 86400 A 192.0.2.8',
];

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'example.com', qtype => 'SOA',
    answer => 'example.com 86400 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900',
    auth => $standard_auth,
    addtl => $standard_auth_addtl,
);

_GDT->test_dns(
    qname => '3.0/27.2.0.192.in-addr.arpa', qtype => 'PTR',
    answer => '3.0/27.2.0.192.in-addr.arpa 86400 PTR foo.example.net',
    auth => '0/27.2.0.192.in-addr.arpa 86400 NS ns1.example.net',
);

_GDT->test_dns(
    qname => 'example.com', qtype => 'MX',
    answer => [
        'example.com 3600 MX 42 ns1.example.com',
        'example.com 3600 MX 44 foo.example.com',
    ],
    auth => $standard_auth,
    addtl => [
        'ns1.example.com 86400 A 192.0.2.5',
        'foo.example.com 515 A 192.0.2.4',
        'ns2.example.com 86400 A 192.0.2.6',
        'ns3.goober.example.com 86400 A 192.0.2.7',
        'ns4.goober.example.com 86400 A 192.0.2.8',
    ],
);

_GDT->test_dns(
    qname => 'example.com', qtype => 'NS',
    answer => $standard_auth,
    addtl => $standard_auth_addtl,
);

_GDT->test_dns(
    qname => 'example.com', qtype => 'TXT',
    answer => 'example.com 86400 TXT "foo bar baz" "asdf 123 123 foo"',
    auth => $standard_auth,
    addtl => $standard_auth_addtl,
);

_GDT->test_dns(
    qname => 'alias.example.com', qtype => 'CNAME',
    answer => 'alias.example.com 86400 CNAME www.example.com',
    auth => $standard_auth,
    addtl => $standard_auth_addtl,
);

_GDT->test_dns(
    qname => 'alias.example.com', qtype => 'A',
    answer => [
        'alias.example.com 86400 CNAME www.example.com',
        'www.example.com 3600 A 192.0.2.1',
        'www.example.com 3600 A 192.0.2.2',
        'www.example.com 3600 A 192.0.2.3',
    ],
    auth => $standard_auth,
    addtl => $standard_auth_addtl,
);

_GDT->test_dns(
    qname => 'foo.example.com', qtype => 'A',
    answer => 'foo.example.com 515 A 192.0.2.4',
    auth => $standard_auth,
    addtl => $standard_auth_addtl,
);

_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.5',
    auth => $standard_auth,
    addtl => [@$standard_auth_addtl[1,2,3]],
);

_GDT->test_dns(
    qname => 'ns2.example.com', qtype => 'A',
    answer => 'ns2.example.com 86400 A 192.0.2.6',
    auth => $standard_auth,
    addtl => [@$standard_auth_addtl[0,2,3]],
);

_GDT->test_dns(
    qname => 'ns3.goober.example.com', qtype => 'A',
    answer => 'ns3.goober.example.com 86400 A 192.0.2.7',
    auth => $standard_auth,
    addtl => [@$standard_auth_addtl[0,1,3]],
);

_GDT->test_dns(
    qname => 'ns4.goober.example.com', qtype => 'A',
    answer => 'ns4.goober.example.com 86400 A 192.0.2.8',
    auth => $standard_auth,
    addtl => [@$standard_auth_addtl[0,1,2]],
);

_GDT->test_dns(
    qname => 'www.example.com', qtype => 'A',
    answer => [
        'www.example.com 3600 A 192.0.2.1',
        'www.example.com 3600 A 192.0.2.2',
        'www.example.com 3600 A 192.0.2.3',
    ],
    auth => $standard_auth,
    addtl => $standard_auth_addtl,
);

_GDT->test_dns(
    qname => 'x.y.z.example.com', qtype => 'TXT',
    answer => qq{x.y.z.example.com 86400 TXT "\n\0\x19} . '9 some complicated stuff here \"\"\"\\\\' . qq{" "asdf" "xyz\n"},
    auth => $standard_auth,
    addtl => $standard_auth_addtl,
);

_GDT->test_dns(
    qname => '_http._tcp.example.com', qtype => 'SRV',
    answer => '_http._tcp.example.com 1209600 SRV 5 500 80 www.example.com',
    auth => $standard_auth,
    addtl => [
        'www.example.com 3600 A 192.0.2.1',
        'www.example.com 3600 A 192.0.2.2',
        'www.example.com 3600 A 192.0.2.3',
        @$standard_auth_addtl,
    ],
);

_GDT->test_dns(
    qname => '9.2.0.192.example.com', qtype => 'PTR',
    answer => [
        '9.2.0.192.example.com 86400 PTR foo.example.com',
        '9.2.0.192.example.com 86400 PTR ns2.example.com',
    ],
    auth => $standard_auth,
    addtl => [
        'ns1.example.com 86400 A 192.0.2.5',
        'ns2.example.com 86400 A 192.0.2.6',
        'ns3.goober.example.com 86400 A 192.0.2.7',
        'ns4.goober.example.com 86400 A 192.0.2.8',
    ]
);

_GDT->test_dns(
    qname => 'example.com', qtype => 'ANY',
    answer => [
        'example.com 86400 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900',
        'example.com 3600 MX 42 ns1.example.com',
        'example.com 3600 MX 44 foo.example.com',
        @$standard_auth,
        'example.com 86400 TXT "foo bar baz" "asdf 123 123 foo"',
        'example.com 1111 PTR foo.example.org',
    ],
    addtl => [
        'ns1.example.com 86400 A 192.0.2.5',
        'foo.example.com 515 A 192.0.2.4',
        'ns2.example.com 86400 A 192.0.2.6',
        'ns3.goober.example.com 86400 A 192.0.2.7',
        'ns4.goober.example.com 86400 A 192.0.2.8',
    ],
);

_GDT->test_kill_daemon($pid);
