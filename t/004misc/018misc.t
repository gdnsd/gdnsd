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

my $pid = _GDT->test_spawn_daemon();

# MX/SRV targets pointed at root of DNS
_GDT->test_dns(
    qname => 'cov.example.com', qtype => 'MX',
    answer => 'cov.example.com 86400 MX 1 .',
);

_GDT->test_dns(
    qname => 'cov.example.com', qtype => 'SRV',
    answer => 'cov.example.com 86400 SRV 1 2 3 .',
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
    answer => '0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef1.example.com 86400 CNAME 0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab.cdef0123456789abcdef0123456789abcdef0123456789abcdef01234567.89abcdef0123456789abcdef0123456789abcdef2.example.com',
    addtl => $optrr,
    stats => [qw/udp_reqs edns noerror/],
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
