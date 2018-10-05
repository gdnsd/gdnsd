# This tests some corner cases for coverage, mostly
#  dealing with large additional record counts and/or
#  dnames being encoded/repeated past the 16K mark,
#  which affects compression.
# Also covers a few EDNS cases at the bottom

use _GDT ();
use Test::More tests => 8;

my $optrr = Net::DNS::RR->new(
    type => "OPT",
    ednsversion => 0,
    name => "",
    class => 1024,
    extendedrcode => 0,
    ednsflags => 0,
);

# The value "128" here is our expected keepalive advertisement with a single
# open connection under default settings.  The defaults are 128 max clients and
# 15s max timeout.  Following the code's logic for the 75% threshold, etc:
# --
# 75% threshold of 128 max = 96
# free connections / threshold, with 1 open = 95/96
# 15s max timeout, -2 for the internal timeout vs keepalive offset = 13s baseline
# floor(13 * (95/96) * 10) = 128 in 100ms units
my $optrr_keepalive = Net::DNS::RR->new(
    type => "OPT",
    ednsversion => 0,
    name => "",
    class => 1024,
    extendedrcode => 0,
    ednsflags => 0,
    optioncode => 11,
    optiondata => pack('n', 128),
);

my $long_rr = Net::DNS::rr_add('this.is.an.rr.thats.longer.than.an.opt.rr.in.order.to.make.coverage.work A 192.0.2.1');
my $long_root_rr = Net::DNS::rr_add('. MX 0 this.is.an.rr.thats.longer.than.an.opt.rr.in.order.to.make.coverage.work');

my $soa = 'example.com 900 SOA ns1.example.com hmaster.example.net 1 7200 1800 259200 900';

my $cname_16 = [
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef1.example.com 86400 CNAME 0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef2.example.com',
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef2.example.com 86400 CNAME 0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef3.example.com',
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef3.example.com 86400 CNAME 0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef4.example.com',
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef4.example.com 86400 CNAME 0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef5.example.com',
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef5.example.com 86400 CNAME 0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef6.example.com',
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef6.example.com 86400 CNAME 0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef7.example.com',
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef7.example.com 86400 CNAME 0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef8.example.com',
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef8.example.com 86400 CNAME 0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef9.example.com',
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef9.example.com 86400 CNAME 0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdefa.example.com',
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdefa.example.com 86400 CNAME 0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdefb.example.com',
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdefb.example.com 86400 CNAME 0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdefc.example.com',
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdefc.example.com 86400 CNAME 0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdefd.example.com',
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdefd.example.com 86400 CNAME 0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdefe.example.com',
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdefe.example.com 86400 CNAME 0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdeff.example.com',
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdeff.example.com 86400 CNAME 0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef0.example.com',
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef0.example.com 86400 CNAME sixteen.example.com',
];

my $pid = _GDT->test_spawn_daemon();

# MX/SRV targets pointed at root of DNS
_GDT->test_dns(
    qname => 'cov.example.com', qtype => 'MX',
    answer => 'cov.example.com 86400 MX 1 .',
);

# This one also tests that clientsub is effectively ignored when disabled
_GDT->test_dns(
    qname => 'cov.example.com', qtype => 'SRV',
    q_optrr => _GDT::optrr_clientsub(addr_v4 => '192.0.2.0', src_mask => 32),
    answer => 'cov.example.com 86400 SRV 1 2 3 .',
    addtl => $optrr,
    stats => [qw/udp_reqs noerror edns/],
);

my $chaos = Net::DNS::Packet->new();
$chaos->push('question', Net::DNS::Question->new('foo', 'TXT', 'CH'));
_GDT->test_dns(
    qpacket => $chaos,
    header => { aa => 0 },
    answer => 'foo CH TXT gdnsd',
);

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 0, udppacketsize => 32000 },
    qname => '0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef1.example.com', qtype => 'MX',
    header => { rcode => 'NXDOMAIN' },
    answer => $cname_16,
    auth => $soa,
    addtl => $optrr,
    stats => [qw/udp_reqs edns udp_edns_big nxdomain/],
);

# Questions containing Additional Records which are not OPT RRs...

{
    my $qpacket = Net::DNS::Packet->new();
    $qpacket->push('question', Net::DNS::Question->new('foo.example.com', 'A'));
    $qpacket->push('additional', $long_rr);
    _GDT->test_dns(
        qpacket => $qpacket,
        answer => 'foo.example.com 86400 A 192.0.2.3',
    );
}

{
    my $qpacket = Net::DNS::Packet->new();
    $qpacket->push('question', Net::DNS::Question->new('foo.example.com', 'A'));
    $qpacket->push('additional', $long_root_rr);
    _GDT->test_dns(
        qpacket => $qpacket,
        answer => 'foo.example.com 86400 A 192.0.2.3',
    );
}

_GDT->test_kill_daemon($pid);
