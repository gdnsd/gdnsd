# Test edns client subnet option via reflect plugin

use _GDT ();
use Socket qw/AF_INET/;
use Socket6 qw/AF_INET6 inet_pton/;
use IO::Socket::INET6 qw//;
use Test::More tests => 26;

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'example.com', qtype => 'SOA',
    answer => 'example.com 86400 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900',
);

_GDT->test_dns(
    qname => 'static.example.com', qtype => 'A',
    answer => 'static.example.com 86400 A 192.0.2.1',
);

_GDT->test_dns(
    qname => 'static.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.0', src_mask => 24),
    answer => 'static.example.com 86400 A 192.0.2.1',
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.0', src_mask => 24, scope_mask => 0),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

_GDT->test_dns(
    v4_only => 1,
    qname => 'reflect-dns.example.com', qtype => 'A',
    answer => 'reflect-dns.example.com 60 A 127.0.0.1',
);

_GDT->test_dns(
    v6_only => 1,
    qname => 'reflect-dns.example.com', qtype => 'AAAA',
    answer => 'reflect-dns.example.com 60 AAAA ::1',
);

_GDT->test_dns(
    v4_only => 1,
    qname => 'reflect-dns.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.0', src_mask => 24),
    answer => 'reflect-dns.example.com 60 A 127.0.0.1',
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.0', src_mask => 24, scope_mask => 24),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

_GDT->test_dns(
    v6_only => 1,
    qname => 'reflect-dns.example.com', qtype => 'AAAA',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.0', src_mask => 24),
    answer => 'reflect-dns.example.com 60 AAAA ::1',
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.0', src_mask => 24, scope_mask => 24),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

_GDT->test_dns(
    qname => 'reflect-edns.example.com', qtype => 'A',
    answer => 'reflect-edns.example.com 60 A 0.0.0.0',
);

_GDT->test_dns(
    qname => 'reflect-edns.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.0', src_mask => 24),
    answer => 'reflect-edns.example.com 60 A 192.0.2.0',
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.0', src_mask => 24, scope_mask => 24),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

_GDT->test_dns(
    qname => 'reflect-edns.example.com', qtype => 'AAAA',
    q_optrr => _GDT::optrr_clientsub(addr_v6 => '::5', src_mask => 128),
    answer => 'reflect-edns.example.com 60 AAAA ::5',
    addtl => _GDT::optrr_clientsub(addr_v6 => '::5', src_mask => 128, scope_mask => 128),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

_GDT->test_dns(
    v4_only => 1,
    qname => 'reflect-best.example.com', qtype => 'A',
    answer => 'reflect-best.example.com 60 A 127.0.0.1',
);

_GDT->test_dns(
    v6_only => 1,
    qname => 'reflect-best.example.com', qtype => 'AAAA',
    answer => 'reflect-best.example.com 60 AAAA ::1',
);

_GDT->test_dns(
    v4_only => 1,
    qname => 'reflect-best.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.0', src_mask => 24),
    answer => 'reflect-best.example.com 60 A 192.0.2.0',
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.0', src_mask => 24, scope_mask => 24),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

_GDT->test_dns(
    v6_only => 1,
    qname => 'reflect-best.example.com', qtype => 'AAAA',
    q_optrr => _GDT::optrr_clientsub(addr_v6 => '::5', src_mask => 128),
    answer => 'reflect-best.example.com 60 AAAA ::5',
    addtl => _GDT::optrr_clientsub(addr_v6 => '::5', src_mask => 128, scope_mask => 128),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

_GDT->test_dns(
    v4_only => 1,
    qname => 'reflect-both.example.com', qtype => 'A',
    answer => 'reflect-both.example.com 60 A 127.0.0.1',
);

_GDT->test_dns(
    v6_only => 1,
    qname => 'reflect-both.example.com', qtype => 'AAAA',
    answer => 'reflect-both.example.com 60 AAAA ::1',
);

_GDT->test_dns(
    v4_only => 1,
    qname => 'reflect-both.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.0', src_mask => 24),
    answer => [
        'reflect-both.example.com 60 A 127.0.0.1',
        'reflect-both.example.com 60 A 192.0.2.0',
    ],
    addtl => _GDT::optrr_clientsub(addr_v4 => '192.0.2.0', src_mask => 24, scope_mask => 24),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

_GDT->test_dns(
    v6_only => 1,
    qname => 'reflect-both.example.com', qtype => 'AAAA',
    q_optrr => _GDT::optrr_clientsub(addr_v6 => '::5', src_mask => 128),
    answer => [
        'reflect-both.example.com 60 AAAA ::1',
        'reflect-both.example.com 60 AAAA ::5',
    ],
    addtl => _GDT::optrr_clientsub(addr_v6 => '::5', src_mask => 128, scope_mask => 128),
    stats => [qw/udp_reqs edns edns_clientsub noerror/],
);

###### Various invalid edns-clientsub tests...

my @optrr_base = (
    type => "OPT",
    ednsversion => 0,
    name => "",
    class => 1024,
    extendedrcode => 0,
    ednsflags => 0,
);

my $optrr_basic = Net::DNS::RR->new(@optrr_base);

# V4 Mask too long
_GDT->test_dns(
    v4_only => 1,
    qname => 'reflect-best.example.com', qtype => 'A',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.0', src_mask => 33),
    header => { rcode => 'FORMERR', aa => 0 },
    addtl => $optrr_basic,
    stats => [qw/udp_reqs edns edns_clientsub formerr/],
);

# V6 Mask too long
_GDT->test_dns(
    v6_only => 1,
    qname => 'reflect-best.example.com', qtype => 'AAAA',
    q_optrr => _GDT::optrr_clientsub(addr_v6 => '::5', src_mask => 129),
    header => { rcode => 'FORMERR', aa => 0 },
    addtl => $optrr_basic,
    stats => [qw/udp_reqs edns edns_clientsub formerr/],
);

# V4 not enough addr bytes for src_mask
my $optrr_short_v4 = Net::DNS::RR->new(@optrr_base,
    optioncode => 0x0008,
    optiondata => pack('nCCa3', 1, 32, 0, inet_pton(AF_INET, "0.0.0.0")),
);
_GDT->test_dns(
    v4_only => 1,
    qname => 'reflect-best.example.com', qtype => 'A',
    q_optrr => $optrr_short_v4,
    header => { rcode => 'FORMERR', aa => 0 },
    addtl => $optrr_basic,
    stats => [qw/udp_reqs edns edns_clientsub formerr/],
);

# V6 not enough addr bytes for src_mask
my $optrr_short_v6 = Net::DNS::RR->new(@optrr_base,
    optioncode => 0x0008,
    optiondata => pack('nCCa15', 2, 128, 0, inet_pton(AF_INET6, "::")),
);
_GDT->test_dns(
    v6_only => 1,
    qname => 'reflect-best.example.com', qtype => 'AAAA',
    q_optrr => $optrr_short_v6,
    header => { rcode => 'FORMERR', aa => 0 },
    addtl => $optrr_basic,
    stats => [qw/udp_reqs edns edns_clientsub formerr/],
);

# Bad address family
my $optrr_badfam = Net::DNS::RR->new(@optrr_base,
    optioncode => 0x0008,
    optiondata => pack('nCCa16', 3, 128, 0, inet_pton(AF_INET6, "::")),
);
_GDT->test_dns(
    qname => 'reflect-best.example.com', qtype => 'AAAA',
    q_optrr => $optrr_badfam,
    header => { rcode => 'FORMERR', aa => 0 },
    addtl => $optrr_basic,
    stats => [qw/udp_reqs edns edns_clientsub formerr/],
);

# option too short
my $optrr_short_rdlen = Net::DNS::RR->new(@optrr_base,
    optioncode => 0x0008,
    optiondata => pack('C', 1),
);
_GDT->test_dns(
    qname => 'reflect-best.example.com', qtype => 'AAAA',
    q_optrr => $optrr_short_rdlen,
    header => { rcode => 'FORMERR', aa => 0 },
    addtl => $optrr_basic,
    stats => [qw/udp_reqs edns edns_clientsub formerr/],
);

_GDT->test_kill_daemon($pid);
