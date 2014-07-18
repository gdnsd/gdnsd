
# This tests a zone with all of the constructs
#  which used to be only legal with strict_data = false
# These now universally generate mere warnings, and
#  there is no strict_data setting.

use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 10;

my $pid = _GDT->test_spawn_daemon();

my $neg_soa = 'example.com 10800 SOA foo.example.com hostmaster.example.com 1 7200 1800 259200 10800';

_GDT->test_dns(
    qname => 'abc.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    answer => 'abc.example.com 86400 CNAME foo.example.com',
    auth => $neg_soa,
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'bcd.example.com', qtype => 'A',
    answer => 'bcd.example.com 86400 CNAME bob.example.com',
    auth => $neg_soa,
);

_GDT->test_dns(
    qname => '123.example.com', qtype => 'PTR',
    answer => '123.example.com 86400 PTR foo.example.com',
);

_GDT->test_dns(
    qname => 'cde.example.com', qtype => 'MX',
    answer => 'cde.example.com 86400 MX 0 bob.example.com',
);

_GDT->test_dns(
    qname => 'def.example.com', qtype => 'SRV',
    answer => 'def.example.com 86400 SRV 5 500 80 foo.example.com',
);

_GDT->test_dns(
    qname => 'efg.example.com', qtype => 'NAPTR',
    answer => 'efg.example.com 86400 NAPTR 1 2 "***" "foo" "bar" foo.example.com',
);

_GDT->test_dns(
    qname => 'foobar.subz.example.com', qtype => 'A',
    header => { aa => 0 },
    auth  => 'subz.example.com 86400 NS ns.subz.example.com',
    addtl => 'ns.subz.example.com 300 A 192.0.2.3',
);

_GDT->test_dns(
    qname => 'mxcn.example.com', qtype => 'MX',
    answer => 'mxcn.example.com 86400 MX 0 ns1cn.example.com',
);

_GDT->test_kill_daemon($pid);
