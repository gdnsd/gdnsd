# This tests wildcard labels

use _GDT ();
use Test::More tests => 33;

my $neg_soa = 'example.org 120 SOA ns1.example.org r00t.example.net 1 7200 1800 259200 120';

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'xxx.example.org', qtype => 'AAAA',
    answer => 'xxx.example.org 43201 AAAA ::1',
);

_GDT->test_dns(
    qname => 'xxx.example.org', qtype => 'A',
    auth => $neg_soa,
);

_GDT->test_dns(
    qname => 'xxx.xxx.example.org', qtype => 'A',
    auth => $neg_soa,
);

_GDT->test_dns(
    qname => 'xxx.foo.example.org', qtype => 'AAAA',
    header => { rcode => 'NXDOMAIN' },
    auth => $neg_soa,
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'xxx.*.example.org', qtype => 'AAAA',
    header => { rcode => 'NXDOMAIN' },
    auth => $neg_soa,
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'bar.example.org', qtype => 'AAAA',
    answer => 'bar.example.org 43201 CNAME bar.baz.fox.example.org',
);

_GDT->test_dns(
    qname => 'barmx.example.org', qtype => 'MX',
    answer => 'barmx.example.org 43201 MX 0 barmx.xmrab.xxx.fox.example.org',
);

# Records beneath an explicit wildcard
_GDT->test_dns(
    qname => '*.sub.example.org', qtype => 'A',
    answer => '*.sub.example.org 43201 A 192.0.2.222',
);

_GDT->test_dns(
    qname => '*.sub.example.org', qtype => 'MX',
    auth => $neg_soa,
);

_GDT->test_dns(
    qname => 'foo.sub.example.org', qtype => 'A',
    answer => 'foo.sub.example.org 43201 A 192.0.2.222',
);

_GDT->test_dns(
    qname => 'foo.sub.example.org', qtype => 'MX',
    auth => $neg_soa,
);

_GDT->test_dns(
    qname => 'foo.foo.sub.example.org', qtype => 'A',
    answer => 'foo.foo.sub.example.org 43201 A 192.0.2.222',
);

_GDT->test_dns(
    qname => 'foo.foo.sub.example.org', qtype => 'MX',
    auth => $neg_soa,
);

_GDT->test_dns(
    qname => 'foo.foo.foo.sub.example.org', qtype => 'A',
    answer => 'foo.foo.foo.sub.example.org 43201 A 192.0.2.222',
);

_GDT->test_dns(
    qname => 'foo.foo.foo.sub.example.org', qtype => 'MX',
    auth => $neg_soa,
);

_GDT->test_dns(
    qname => 'foo.*.sub.example.org', qtype => 'A',
    answer => 'foo.*.sub.example.org 43201 A 192.0.2.223',
);

_GDT->test_dns(
    qname => 'foo.*.sub.example.org', qtype => 'MX',
    auth => $neg_soa,
);

# Implicit ENT-wildcard test that never gets real rrsets
_GDT->test_dns(
    qname => 'asdf.*.xyz.example.org', qtype => 'A',
    answer => 'asdf.*.xyz.example.org 43201 A 192.0.2.203',
);

_GDT->test_dns(
    qname => '*.xyz.example.org', qtype => 'A',
    auth => $neg_soa,
);

_GDT->test_dns(
    qname => 'foo.xyz.example.org', qtype => 'A',
    auth => $neg_soa,
);

_GDT->test_dns(
    qname => 'foo.foo.xyz.example.org', qtype => 'A',
    auth => $neg_soa,
);

_GDT->test_dns(
    qname => 'xyz.example.org', qtype => 'A',
    auth => $neg_soa,
);

_GDT->test_dns(
    qname => 'foo.*.xyz.example.org', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => $neg_soa,
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'wildmatch.example.org', qtype => 'MX',
    answer => [
        'wildmatch.example.org 43201 MX 0 wildmx0.example.org',
        'wildmatch.example.org 43201 MX 1 wildmx1.example.org',
        'wildmatch.example.org 43201 MX 2 wildmx2.example.org',
    ],
);

_GDT->test_dns(
    qname => 'foo.bar.wildmatch.example.org', qtype => 'MX',
    answer => [
        'foo.bar.wildmatch.example.org 43201 MX 0 wildmx0.example.org',
        'foo.bar.wildmatch.example.org 43201 MX 1 wildmx1.example.org',
        'foo.bar.wildmatch.example.org 43201 MX 2 wildmx2.example.org',
    ],
);

_GDT->test_dns(
    qname => '*.example.org', qtype => 'MX',
    answer => [
        '*.example.org 43201 MX 0 wildmx0.example.org',
        '*.example.org 43201 MX 1 wildmx1.example.org',
        '*.example.org 43201 MX 2 wildmx2.example.org',
    ],
);

_GDT->test_dns(
    qname => 'wildmatch.zzz.example.org', qtype => 'MX',
    answer => [
        'wildmatch.zzz.example.org 43201 MX 0 wildsubmx0.example.org',
        'wildmatch.zzz.example.org 43201 MX 1 wildsubmx1.example.org',
        'wildmatch.zzz.example.org 43201 MX 2 wildsubmx2.example.org',
    ],
);

_GDT->test_dns(
    qname => 'foo.bar.wildmatch.zzz.example.org', qtype => 'MX',
    answer => [
        'foo.bar.wildmatch.zzz.example.org 43201 MX 0 wildsubmx0.example.org',
        'foo.bar.wildmatch.zzz.example.org 43201 MX 1 wildsubmx1.example.org',
        'foo.bar.wildmatch.zzz.example.org 43201 MX 2 wildsubmx2.example.org',
    ],
);

_GDT->test_dns(
    qname => '*.zzz.example.org', qtype => 'MX',
    answer => [
        '*.zzz.example.org 43201 MX 0 wildsubmx0.example.org',
        '*.zzz.example.org 43201 MX 1 wildsubmx1.example.org',
        '*.zzz.example.org 43201 MX 2 wildsubmx2.example.org',
    ],
);

_GDT->test_dns(
    qname => 'foo.bar.*.example.org', qtype => 'MX',
    header => { rcode => 'NXDOMAIN' },
    auth => $neg_soa,
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'foo.bar.cnwild.example.org', qtype => 'AAAA',
    answer => 'foo.bar.cnwild.example.org 43201 CNAME ns1.example.org',
);

_GDT->test_kill_daemon($pid);
