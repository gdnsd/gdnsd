# Basic geoip plugin tests

use _GDT ();
use Test::More tests => 58 * 2;

my $test_bin = $ENV{INSTALLCHECK_BINDIR}
    ? "$ENV{INSTALLCHECK_BINDIR}/gdnsd_geoip_test"
    : "$ENV{TOP_BUILDDIR}/plugins/gdnsd_geoip_test";
my $test_exec = qq|$test_bin -c ${_GDT::OUTDIR}/etc|;

my $neg_soa = 'example.com 900 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900';

# We re-run the same suite of tests against
#  multiple config files with identical meaning,
#  expressed in different ways.  For example,
#  inherited vs directly-specified attributes
#  at various levels, and synthesized subplugin
#  config versus direct reference.

my @etcdirs = (qw/etc etc2/);

foreach my $etcdir (@etcdirs) { # loop ends at bottom of file

my $pid = _GDT->test_spawn_daemon($etcdir, q{
    0.0.0.0/1 => US
    128.0.0.0/1 => FR
});

_GDT->test_dns(
    qname => 'example.com', qtype => 'NS',
    answer => 'example.com 86400 NS ns1.example.com',
    addtl => 'ns1.example.com 86400 A 192.0.2.1',
);

# res1
_GDT->test_dns(
    qname => 'res1.example.com', qtype => 'A',
    answer => 'res1.example.com 86400 A 192.0.2.1',
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res1.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '10.10.0.0', src_mask => 16),
    answer => 'res1.example.com 86400 A 192.0.2.1',
    addtl => _GDT::optrr_clientsub(addr_v4 => '10.10.0.0', src_mask => 16, scope_mask => 1),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);
_GDT->test_dns(
    qname => 'res1.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32),
    answer => [ 'res1.example.com 86400 A 192.0.2.5', 'res1.example.com 86400 A 192.0.2.6' ],
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32, scope_mask => 1),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

#res1/na
_GDT->test_dns(
    qname => 'res1na.example.com', qtype => 'A',
    answer => 'res1na.example.com 86400 A 192.0.2.1',
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res1na.example.com', qtype => 'A',
    answer => 'res1na.example.com 86400 A 192.0.2.1',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32),
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32, scope_mask => 0),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

#res1/sa
_GDT->test_dns(
    qname => 'res1sa.example.com', qtype => 'A',
    answer => [ 'res1sa.example.com 86400 A 192.0.2.4', 'res1sa.example.com 86400 A 192.0.2.3' ],
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res1sa.example.com', qtype => 'A',
    answer => [ 'res1sa.example.com 86400 A 192.0.2.4', 'res1sa.example.com 86400 A 192.0.2.3' ],
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 15),
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 15, scope_mask => 0),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

#res1/eu
_GDT->test_dns(
    qname => 'res1eu.example.com', qtype => 'A',
    answer => [ 'res1eu.example.com 86400 A 192.0.2.5', 'res1eu.example.com 86400 A 192.0.2.6' ],
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res1eu.example.com', qtype => 'A',
    answer => [ 'res1eu.example.com 86400 A 192.0.2.5', 'res1eu.example.com 86400 A 192.0.2.6' ],
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 15),
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 15, scope_mask => 0),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

#res1/ap
_GDT->test_dns(
    qname => 'res1ap.example.com', qtype => 'A',
    answer => [ 'res1ap.example.com 86400 A 192.0.2.7', 'res1ap.example.com 86400 A 192.0.2.8', 'res1ap.example.com 86400 A 192.0.2.9' ],
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res1ap.example.com', qtype => 'A',
    answer => [ 'res1ap.example.com 86400 A 192.0.2.7', 'res1ap.example.com 86400 A 192.0.2.8', 'res1ap.example.com 86400 A 192.0.2.9' ],
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 1),
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 1, scope_mask => 0),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

# res2
_GDT->test_dns(
    qname => 'res2.example.com', qtype => 'A',
    answer => [],
    auth => $neg_soa,
    addtl => 'res2.example.com 86400 AAAA 2001:DB8::11',
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res2.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '10.10.0.0', src_mask => 16),
    answer => [], auth => $neg_soa,
    addtl => [
        'res2.example.com 86400 AAAA 2001:DB8::11',
        _GDT::optrr_clientsub(addr_v4 => '10.10.0.0', src_mask => 16, scope_mask => 1),
    ],
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);
_GDT->test_dns(
    qname => 'res2.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32),
    answer => 'res2.example.com 86400 A 192.0.2.10',
    addtl => [
        'res2.example.com 86400 AAAA 2001:DB8::10',
        _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32, scope_mask => 1),
    ],
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

#res2/dc1
_GDT->test_dns(
    qname => 'res2dc1.example.com', qtype => 'A',
    answer => 'res2dc1.example.com 86400 A 192.0.2.10',
    addtl => 'res2dc1.example.com 86400 AAAA 2001:DB8::10',
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res2dc1.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32),
    answer => 'res2dc1.example.com 86400 A 192.0.2.10',
    addtl => [
        'res2dc1.example.com 86400 AAAA 2001:DB8::10',
        _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32, scope_mask => 0),
    ],
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

#res2/dc2
_GDT->test_dns(
    qname => 'res2dc2.example.com', qtype => 'A',
    answer => [], auth => $neg_soa,
    addtl => 'res2dc2.example.com 86400 AAAA 2001:DB8::11',
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res2dc2.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32),
    answer => [], auth => $neg_soa,
    addtl => [
        'res2dc2.example.com 86400 AAAA 2001:DB8::11',
        _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32, scope_mask => 0),
    ],
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

#res2/dc3
_GDT->test_dns(
    qname => 'res2dc3.example.com', qtype => 'A',
    answer => 'res2dc3.example.com 86400 A 192.0.2.11',
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res2dc3.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32),
    answer => 'res2dc3.example.com 86400 A 192.0.2.11',
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32, scope_mask => 0),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

#res3
_GDT->test_dns(
    qname => 'res3.example.com', qtype => 'A',
    answer => 'res3.example.com 86400 CNAME dc2cn.example.com',
    auth => $neg_soa,
    addtl => 'dc2cn.example.com 86400 AAAA 2001:DB8::101',
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res3.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '10.10.0.0', src_mask => 16),
    answer => 'res3.example.com 86400 CNAME dc2cn.example.com',
    auth => $neg_soa,
    addtl => [
        'dc2cn.example.com 86400 AAAA 2001:DB8::101',
        _GDT::optrr_clientsub(addr_v4 => '10.10.0.0', src_mask => 16, scope_mask => 1),
    ],
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);
_GDT->test_dns(
    qname => 'res3.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32),
    answer => [
        'res3.example.com 86400 CNAME dc1cn.example.com',
        'dc1cn.example.com 86400 A 192.0.2.100',
    ],
    addtl => [
        _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32, scope_mask => 1),
    ],
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

#res3/dc1
_GDT->test_dns(
    qname => 'res3dc1.example.com', qtype => 'A',
    answer => [
        'res3dc1.example.com 86400 CNAME dc1cn.example.com',
        'dc1cn.example.com 86400 A 192.0.2.100',
    ],
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res3dc1.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32),
    answer => [
        'res3dc1.example.com 86400 CNAME dc1cn.example.com',
        'dc1cn.example.com 86400 A 192.0.2.100',
    ],
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32, scope_mask => 0),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

#res3/dc2
_GDT->test_dns(
    qname => 'res3dc2.example.com', qtype => 'A',
    answer => 'res3dc2.example.com 86400 CNAME dc2cn.example.com',
    auth => $neg_soa,
    addtl => 'dc2cn.example.com 86400 AAAA 2001:DB8::101',
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res3dc2.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '10.10.0.0', src_mask => 16),
    answer => 'res3dc2.example.com 86400 CNAME dc2cn.example.com',
    auth => $neg_soa,
    addtl => [
        'dc2cn.example.com 86400 AAAA 2001:DB8::101',
        _GDT::optrr_clientsub(addr_v4 => '10.10.0.0', src_mask => 16, scope_mask => 0),
    ],
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

#res3/dc3
_GDT->test_dns(
    qname => 'res3dc3.example.com', qtype => 'A',
    answer => [
        'res3dc3.example.com 86400 CNAME dc3cn.example.com',
        'dc3cn.example.com 86400 A 192.0.2.102',
    ],
    addtl => 'dc3cn.example.com 86400 AAAA 2001:DB8::102',
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res3dc3.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '10.10.0.0', src_mask => 16),
    answer => [
        'res3dc3.example.com 86400 CNAME dc3cn.example.com',
        'dc3cn.example.com 86400 A 192.0.2.102',
    ],
    addtl => [
        'dc3cn.example.com 86400 AAAA 2001:DB8::102',
        _GDT::optrr_clientsub(addr_v4 => '10.10.0.0', src_mask => 16, scope_mask => 0),
    ],
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

#dmx
_GDT->test_dns(
    qname => 'dmx.example.com', qtype => 'MX',
    answer => [
        'dmx.example.com 86400 MX 0 res1.example.com',
        'dmx.example.com 86400 MX 1 res2.example.com',
        'dmx.example.com 86400 MX 2 res3.example.com',
    ],
    addtl => [
        'res1.example.com 86400 A 192.0.2.1',
        'res2.example.com 86400 AAAA 2001:DB8::11',
    ],
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'dmx.example.com', qtype => 'MX',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32),
    answer => [
        'dmx.example.com 86400 MX 0 res1.example.com',
        'dmx.example.com 86400 MX 1 res2.example.com',
        'dmx.example.com 86400 MX 2 res3.example.com',
    ],
    addtl => [
       'res1.example.com 86400 A 192.0.2.5',
        'res1.example.com 86400 A 192.0.2.6',
        'res2.example.com 86400 A 192.0.2.10',
        'res2.example.com 86400 AAAA 2001:DB8::10',
        _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32, scope_mask => 1),
    ],
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

# limited dynamic AAAA+A
_GDT->test_dns(
    qname => 'res4.example.com', qtype => 'AAAA',
    answer => [
        'res4.example.com 86400 AAAA 2001:DB8::2:123',
        'res4.example.com 86400 AAAA 2001:DB8::2:456',
        'res4.example.com 86400 AAAA 2001:DB8::2:789',
    ],
    limit_v6 => 2,
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res44.example.com', qtype => 'A',
    answer => [
        'res44.example.com 86400 A 192.0.2.111',
        'res44.example.com 86400 A 192.0.2.112',
        'res44.example.com 86400 A 192.0.2.113',
    ],
    limit_v4 => 2,
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res4-dync.example.com', qtype => 'AAAA',
    answer => [
        'res4-dync.example.com 86400 AAAA 2001:DB8::2:123',
        'res4-dync.example.com 86400 AAAA 2001:DB8::2:456',
        'res4-dync.example.com 86400 AAAA 2001:DB8::2:789',
    ],
    limit_v6 => 2,
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res44-dync.example.com', qtype => 'A',
    answer => [
        'res44-dync.example.com 86400 A 192.0.2.111',
        'res44-dync.example.com 86400 A 192.0.2.112',
        'res44-dync.example.com 86400 A 192.0.2.113',
    ],
    limit_v4 => 2,
    stats => [qw/udp_reqs noerror/],
);

# over-limited dynamic AAAA
_GDT->test_dns(
    qname => 'res4-lots.example.com', qtype => 'AAAA',
    answer => [
        'res4-lots.example.com 86400 AAAA 2001:DB8::2:123',
        'res4-lots.example.com 86400 AAAA 2001:DB8::2:456',
        'res4-lots.example.com 86400 AAAA 2001:DB8::2:789',
    ],
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res44-lots.example.com', qtype => 'A',
    answer => [
        'res44-lots.example.com 86400 A 192.0.2.111',
        'res44-lots.example.com 86400 A 192.0.2.112',
        'res44-lots.example.com 86400 A 192.0.2.113',
    ],
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res4-lots-dync.example.com', qtype => 'AAAA',
    answer => [
        'res4-lots-dync.example.com 86400 AAAA 2001:DB8::2:123',
        'res4-lots-dync.example.com 86400 AAAA 2001:DB8::2:456',
        'res4-lots-dync.example.com 86400 AAAA 2001:DB8::2:789',
    ],
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res44-lots-dync.example.com', qtype => 'A',
    answer => [
        'res44-lots-dync.example.com 86400 A 192.0.2.111',
        'res44-lots-dync.example.com 86400 A 192.0.2.112',
        'res44-lots-dync.example.com 86400 A 192.0.2.113',
    ],
    stats => [qw/udp_reqs noerror/],
);

# DYNC that loops on itself until max_cname_depth (16) is reached...
_GDT->test_dns(
    qname => 'res5.example.com', qtype => 'AAAA',
    header => { rcode => 'NXDOMAIN' },
    answer => [],
    auth => $neg_soa,
    stats => [qw/udp_reqs nxdomain/],
);

#geoip + weighted
_GDT->test_dns(
    qname => 'res6.example.com', qtype => 'A',
    wrr_v4 => { 'res6.example.com' => { multi => 0, groups => [ 3, 3 ] } },
    answer => [
        'res6.example.com 86400 A 192.0.2.121',
        'res6.example.com 86400 A 192.0.2.122',
        'res6.example.com 86400 A 192.0.2.123',
        # -- group break --
        'res6.example.com 86400 A 192.0.2.221',
        'res6.example.com 86400 A 192.0.2.222',
        'res6.example.com 86400 A 192.0.2.223',
    ],
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res6.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32),
    limit_v4 => 1,
    answer => [
        'res6.example.com 86400 A 192.0.2.111',
        'res6.example.com 86400 A 192.0.2.112',
        'res6.example.com 86400 A 192.0.2.113',
    ],
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32, scope_mask => 1),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

#geoip DYNC weighted
_GDT->test_dns(
    qname => 'res7.example.com', qtype => 'A',
    # CNAME auto-limits to 1 RR
    answer => [
        'res7.example.com 86400 CNAME www1.example.org',
        'res7.example.com 86400 CNAME www2.example.org',
    ],
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res7.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32),
    # CNAME auto-limits to 1 RR
    answer => [
        'res7.example.com 86400 CNAME www1.example.net',
        'res7.example.com 86400 CNAME www2.example.net',
    ],
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32, scope_mask => 1),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

# failover, dc1 -> dc2
_GDT->test_dns(
    qname => 'res8.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32),
    answer => [
        'res8.example.com 86400 A 192.0.2.92',
        'res8.example.com 86400 A 192.0.2.93',
    ],
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32, scope_mask => 1),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

# failover, all of dc1/2/3 down, should roll back to dc1 results at half-ttl
_GDT->test_dns(
    qname => 'resA.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32),
    answer => [
        'resA.example.com 86400 A 192.0.2.90',
        'resA.example.com 86400 A 192.0.2.91',
    ],
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32, scope_mask => 1),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

# geoip -> metafo
_GDT->test_dns(
    qname => 'res9.example.com', qtype => 'A',
    answer => [
        'res9.example.com 86400 A 192.0.2.92',
        'res9.example.com 86400 A 192.0.2.93',
    ],
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res9.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32),
    answer => 'res9.example.com 86400 A 192.0.2.142',
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.1', src_mask => 32, scope_mask => 1),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

# metafo -> geoip without losing edns scope
_GDT->test_dns(
    qname => 'metascope.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '10.10.0.0', src_mask => 16),
    answer => 'metascope.example.com 86400 A 192.0.2.1',
    addtl => _GDT::optrr_clientsub(addr_v4 => '10.10.0.0', src_mask => 16, scope_mask => 1),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

# geoip -> empty addresses, no data (via DYNA then DYNC)
_GDT->test_dns(
    qname => 'res-empty-a.example.com', qtype => 'A',
    answer => [],
    auth => $neg_soa,
    stats => [qw/udp_reqs noerror/],
);
_GDT->test_dns(
    qname => 'res-empty-c.example.com', qtype => 'A',
    answer => [],
    auth => $neg_soa,
    stats => [qw/udp_reqs noerror/],
);

## geoip -> less than all DCs defined in resource, and a map entry creates an empty intersection
# US maps to just DC-A, res-u only defines DC-B,DC-C
_GDT->test_dns(
    qname => 'res-undef.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '10.1.0.0', src_mask => 16),
    answer => [],
    addtl => _GDT::optrr_clientsub(addr_v4 => '10.1.0.0', src_mask => 16, scope_mask => 1),
    auth => $neg_soa,
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);
# FR maps to DC-A,DC-B,DC-C, res-u only defines DC-B,DC-C, answer is DC-B
_GDT->test_dns(
    qname => 'res-undef.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.0', src_mask => 24),
    answer => 'res-undef.example.com 86400 A 192.0.2.180',
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.0', src_mask => 24, scope_mask => 1),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

_GDT->test_kill_daemon($pid);

# This re-tests a couple of the same results checked above, but using
#   the commandline gdnsd_geoip_test tool
$map1_10_result = qx{$test_exec map1 10.10.0.0};
$map1_192_result = qx{$test_exec map1 192.0.2.1};
Test::More::like($map1_10_result, qr{^map1 => 10.10.0.0/1 => na, sa$}m);
Test::More::like($map1_192_result, qr{^map1 => 192.0.2.1/1 => eu, na$}m);

}
