# Dynamic CNAME plugin tests

use _GDT ();
use Test::More tests => 16;

my $neg_soa = 'example.com 900 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900';

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'example.com', qtype => 'SOA',
    answer => 'example.com 86400 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900',
);

# null dynamic CNAME plugin
_GDT->test_dns(
    qname => 'cn.example.com', qtype => 'A',
    answer => 'cn.example.com 86400 CNAME invalid'
);

# dynamic CNAME to A
_GDT->test_dns(
    qname => 'toa.example.com', qtype => 'A',
    answer => ['toa.example.com 86400 CNAME a.example.com.',
                  'a.example.com 86400 A 192.0.2.2']
);

# null dynamic CNAME plugin
_GDT->test_dns(
    qname => 'cn-x.example.com', qtype => 'A',
    answer => 'cn-x.example.com 86400 CNAME invalid'
);

# dynamic CNAME to A (again)
_GDT->test_dns(
    qname => 'toa.example.com', qtype => 'A',
    answer => ['toa.example.com 86400 CNAME a.example.com.',
               'a.example.com 86400 A 192.0.2.2']
);

# dynamic CNAME to missing label
_GDT->test_dns(
    qname => 'tomissing.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    answer => 'tomissing.example.com 86400 CNAME missing.example.com',
    auth => $neg_soa,
    stats => [qw/udp_reqs nxdomain/],
);

# dynamic CNAME to missing 2-level label
_GDT->test_dns(
    qname => 'tomissing2.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    answer => 'tomissing2.example.com 86400 CNAME missing.deeper.example.com',
    auth => $neg_soa,
    stats => [qw/udp_reqs nxdomain/],
);

# dynamic CNAME to missing 3-level label
_GDT->test_dns(
    qname => 'tomissing3.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    answer => 'tomissing3.example.com 86400 CNAME missing.deeper.yet.example.com',
    auth => $neg_soa,
    stats => [qw/udp_reqs nxdomain/],
);

# dynamic CNAME to missing sub of self
_GDT->test_dns(
    qname => 'test.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    answer => 'test.example.com 86400 CNAME simple.test.example.com',
    auth => $neg_soa,
    stats => [qw/udp_reqs nxdomain/],
);

# dynamic CNAME to external domain
_GDT->test_dns(
    qname => 'cdn.example.com', qtype => 'A',
    answer => 'cdn.example.com 86400 CNAME cdn.net.',
);

# chain from static to dynamic cname and back to A record
_GDT->test_dns(
    qname => 'ctodyn.example.com', qtype => 'A',
    answer => ['ctodyn.example.com 86400 CNAME toa.example.com',
               'toa.example.com 86400 CNAME a.example.com',
               'a.example.com 86400 A 192.0.2.2', ]
);

# Chain through 3 DYNC's to an A
_GDT->test_dns(
    qname => 'chain1.example.com', qtype => 'A',
    answer => [
        'chain1.example.com 86400 CNAME chain2.example.com',
        'chain2.example.com 86400 CNAME chain3.example.com',
        'chain3.example.com 86400 CNAME chain4.example.com',
        'chain4.example.com 86400 A 192.0.2.3',
    ]
);

# chain to invalid
_GDT->test_dns(
    qname => 'f43.example.com', qtype => 'A',
    answer => ['f43.example.com 86400 CNAME cn-x.example.com',
               'cn-x.example.com 86400 CNAME invalid'],
);

# DYNC -> 5xA + 0xAAAA (exercise dnspacket v4a logic)
_GDT->test_dns(
    qname => 'fivec.example.com', qtype => 'A',
    answer => [
        'fivec.example.com 86400 A 192.0.2.131',
        'fivec.example.com 86400 A 192.0.2.132',
        'fivec.example.com 86400 A 192.0.2.133',
        'fivec.example.com 86400 A 192.0.2.134',
        'fivec.example.com 86400 A 192.0.2.135',
    ],
);

_GDT->test_kill_daemon($pid);
