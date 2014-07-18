
# This tests various forms of subzone delegation

use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 29;

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'subeasy.example.com', qtype => 'NS',
    header => { aa => 0 },
    auth => [
        'subeasy.example.com 21600 NS subeasyns1.example.com',
        'subeasy.example.com 21600 NS subeasyns2.example.com',
    ],
    addtl => [
        'subeasyns1.example.com 21600 A 192.0.2.3',
        'subeasyns2.example.com 21600 A 192.0.2.4',
    ]
);

_GDT->test_dns(
    qname => 'subeasy.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subeasy.example.com 21600 NS subeasyns1.example.com',
        'subeasy.example.com 21600 NS subeasyns2.example.com',
    ],
    addtl => [
        'subeasyns1.example.com 21600 A 192.0.2.3',
        'subeasyns2.example.com 21600 A 192.0.2.4',
    ]
);

_GDT->test_dns(
    qname => 'foo.subeasy.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subeasy.example.com 21600 NS subeasyns1.example.com',
        'subeasy.example.com 21600 NS subeasyns2.example.com',
    ],
    addtl => [
        'subeasyns1.example.com 21600 A 192.0.2.3',
        'subeasyns2.example.com 21600 A 192.0.2.4',
    ]
);

_GDT->test_dns(
    qname => 'subhard.example.com', qtype => 'NS',
    header => { aa => 0 },
    auth => [
        'subhard.example.com 21600 NS ns1.subhard.example.com',
        'subhard.example.com 21600 NS ns2.subhard.example.com',
    ],
    addtl => [
        'ns1.subhard.example.com 21600 A 192.0.2.5',
        'ns1.subhard.example.com 21600 A 192.0.2.55',
        'ns2.subhard.example.com 21600 A 192.0.2.6',
    ]
);

_GDT->test_dns(
    qname => 'subhard.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subhard.example.com 21600 NS ns1.subhard.example.com',
        'subhard.example.com 21600 NS ns2.subhard.example.com',
    ],
    addtl => [
        'ns1.subhard.example.com 21600 A 192.0.2.5',
        'ns1.subhard.example.com 21600 A 192.0.2.55',
        'ns2.subhard.example.com 21600 A 192.0.2.6',
    ]
);

_GDT->test_dns(
    qname => 'foo.subhard.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subhard.example.com 21600 NS ns1.subhard.example.com',
        'subhard.example.com 21600 NS ns2.subhard.example.com',
    ],
    addtl => [
        'ns1.subhard.example.com 21600 A 192.0.2.5',
        'ns1.subhard.example.com 21600 A 192.0.2.55',
        'ns2.subhard.example.com 21600 A 192.0.2.6',
    ]
);

_GDT->test_dns(
    qname => 'subext.example.com', qtype => 'NS',
    header => { aa => 0 },
    auth => [
        'subext.example.com 21600 NS ns-subext1.example.net',
        'subext.example.com 21600 NS ns-subext2.example.net',
    ],
);

_GDT->test_dns(
    qname => 'subext.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subext.example.com 21600 NS ns-subext1.example.net',
        'subext.example.com 21600 NS ns-subext2.example.net',
    ],
);

_GDT->test_dns(
    qname => 'foo.subext.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subext.example.com 21600 NS ns-subext1.example.net',
        'subext.example.com 21600 NS ns-subext2.example.net',
    ],
);

_GDT->test_dns(
    qname => 'subsemiext.example.com', qtype => 'NS',
    header => { aa => 0 },
    auth => [
        'subsemiext.example.com 21600 NS ns1.example.org',
        'subsemiext.example.com 21600 NS ns2.example.org',
        'subsemiext.example.com 21600 NS ns3.*.example.org',
        'subsemiext.example.com 21600 NS ns4.example.org',
    ],
    addtl => [
        'ns1.example.org 21600 A 192.0.2.200',
        'ns2.example.org 21600 A 192.0.2.207',
        'ns3.*.example.org 21600 A 192.0.2.209',
    ],
);

_GDT->test_dns(
    qname => 'subsemiext.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subsemiext.example.com 21600 NS ns1.example.org',
        'subsemiext.example.com 21600 NS ns2.example.org',
        'subsemiext.example.com 21600 NS ns3.*.example.org',
        'subsemiext.example.com 21600 NS ns4.example.org',
    ],
    addtl => [
        'ns1.example.org 21600 A 192.0.2.200',
        'ns2.example.org 21600 A 192.0.2.207',
        'ns3.*.example.org 21600 A 192.0.2.209',
    ],
);

_GDT->test_dns(
    qname => 'foo.subsemiext.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subsemiext.example.com 21600 NS ns1.example.org',
        'subsemiext.example.com 21600 NS ns2.example.org',
        'subsemiext.example.com 21600 NS ns3.*.example.org',
        'subsemiext.example.com 21600 NS ns4.example.org',
    ],
    addtl => [
        'ns1.example.org 21600 A 192.0.2.200',
        'ns2.example.org 21600 A 192.0.2.207',
        'ns3.*.example.org 21600 A 192.0.2.209',
    ],
);

_GDT->test_dns(
    qname => 'subfubar.example.com', qtype => 'NS',
    header => { aa => 0 },
    auth => [
        'subfubar.example.com 21600 NS subeasyns1.example.com',
        'subfubar.example.com 21600 NS ns1.subfubar.example.com',
        'subfubar.example.com 21600 NS ns-subfubar1.example.net',
        'subfubar.example.com 21600 NS ns1.example.org',
    ],
    addtl => [
        'ns1.subfubar.example.com 21600 A 192.0.2.9',
        'subeasyns1.example.com 21600 A 192.0.2.3',
        'ns1.example.org 21600 A 192.0.2.200',
    ],
);

_GDT->test_dns(
    qname => 'subfubar.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subfubar.example.com 21600 NS subeasyns1.example.com',
        'subfubar.example.com 21600 NS ns1.subfubar.example.com',
        'subfubar.example.com 21600 NS ns-subfubar1.example.net',
        'subfubar.example.com 21600 NS ns1.example.org',
    ],
    addtl => [
        'ns1.subfubar.example.com 21600 A 192.0.2.9',
        'subeasyns1.example.com 21600 A 192.0.2.3',
        'ns1.example.org 21600 A 192.0.2.200',
    ],
);

_GDT->test_dns(
    qname => 'foo.subfubar.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subfubar.example.com 21600 NS subeasyns1.example.com',
        'subfubar.example.com 21600 NS ns1.subfubar.example.com',
        'subfubar.example.com 21600 NS ns-subfubar1.example.net',
        'subfubar.example.com 21600 NS ns1.example.org',
    ],
    addtl => [
        'ns1.subfubar.example.com 21600 A 192.0.2.9',
        'subeasyns1.example.com 21600 A 192.0.2.3',
        'ns1.example.org 21600 A 192.0.2.200',
    ],
);

_GDT->test_dns(
    qname => 'subfubar.x.y.z.example.com', qtype => 'NS',
    header => { aa => 0 },
    auth => [
        'subfubar.x.y.z.example.com 21600 NS subeasyns1.example.com',
        'subfubar.x.y.z.example.com 21600 NS ns1.subfubar.x.y.z.example.com',
        'subfubar.x.y.z.example.com 21600 NS ns-subfubarxyz1.example.net',
        'subfubar.x.y.z.example.com 21600 NS ns1.example.org',
    ],
    addtl => [
        'ns1.subfubar.x.y.z.example.com 21600 A 192.0.2.11',
        'subeasyns1.example.com 21600 A 192.0.2.3',
        'ns1.example.org 21600 A 192.0.2.200',
    ],
);

_GDT->test_dns(
    qname => 'subfubar.x.y.z.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subfubar.x.y.z.example.com 21600 NS subeasyns1.example.com',
        'subfubar.x.y.z.example.com 21600 NS ns1.subfubar.x.y.z.example.com',
        'subfubar.x.y.z.example.com 21600 NS ns-subfubarxyz1.example.net',
        'subfubar.x.y.z.example.com 21600 NS ns1.example.org',
    ],
    addtl => [
        'ns1.subfubar.x.y.z.example.com 21600 A 192.0.2.11',
        'subeasyns1.example.com 21600 A 192.0.2.3',
        'ns1.example.org 21600 A 192.0.2.200',
    ],
);

_GDT->test_dns(
    qname => 'foo.subfubar.x.y.z.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subfubar.x.y.z.example.com 21600 NS subeasyns1.example.com',
        'subfubar.x.y.z.example.com 21600 NS ns1.subfubar.x.y.z.example.com',
        'subfubar.x.y.z.example.com 21600 NS ns-subfubarxyz1.example.net',
        'subfubar.x.y.z.example.com 21600 NS ns1.example.org',
    ],
    addtl => [
        'ns1.subfubar.x.y.z.example.com 21600 A 192.0.2.11',
        'subeasyns1.example.com 21600 A 192.0.2.3',
        'ns1.example.org 21600 A 192.0.2.200',
    ],
);

_GDT->test_dns(
    qname => 'x.y.z.example.com', qtype => 'A',
    auth => 'example.com 900 SOA ns1.example.com hmaster.example.net 1 7200 1800 259200 900',
);

_GDT->test_dns(
    qname => 'foo.y.z.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'example.com 900 SOA ns1.example.com hmaster.example.net 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'foo.x.y.z.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'example.com 900 SOA ns1.example.com hmaster.example.net 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'foo.subselfglue.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => 'subselfglue.example.com 21600 NS subselfglue.example.com',
    addtl => 'subselfglue.example.com 21600 A 192.0.2.12',
);

_GDT->test_dns(
    qname => 'www.subooz.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subooz.example.com 21600 NS ns1.example.net',
        'subooz.example.com 21600 NS ns2.example.net',
    ],
    addtl => [
        'ns1.example.net 21600 A 192.0.2.77',
        'ns2.example.net 21600 A 192.0.2.78',
        'ns2.example.net 21600 AAAA 2001:DB8::1',
    ],
);

_GDT->test_dns(
    qname => 'www.submixooz.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'submixooz.example.com 21600 NS ns1.example.net',
        'submixooz.example.com 21600 NS ns1.submixooz.example.com',
    ],
    addtl => [
        'ns1.example.net 21600 A 192.0.2.77',
        'ns1.submixooz.example.com 21600 A 192.0.2.79',
    ],
);

# These checks verify that "unused.glue.example.net" doesn't
#  infect the local data in any obvious way
_GDT->test_dns(
    qname => 'unused.glue.example.net', qtype => 'A',
    header => { aa => 0, rcode => 'REFUSED' },
    stats => [qw/udp_reqs refused/],
);
_GDT->test_dns(
    qname => 'unused.glue.example.net.example.org', qtype => 'A',
    auth => 'example.org 120 SOA ns1.example.org r00t.example.net 1 7200 1800 259200 120',
    addtl => 'unused.glue.example.net.example.org 43201 AAAA 0:0:0:0:0:0:0:1' # from wildcard...
);

# check that the minimal out-of-zone-glue domain mostly works
_GDT->test_dns(
    qname => 'example.xxx', qtype => 'NS',
    answer => 'example.xxx 21600 NS somewhere.over.the.rainbow'
);

_GDT->test_kill_daemon($pid);
