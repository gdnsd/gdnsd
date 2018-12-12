# This tests some corner cases for coverage, mostly
#  dealing with large additional record counts and/or
#  dnames being encoded/repeated past the 16K mark,
#  which affects compression.
# Also covers a few EDNS cases at the bottom

use _GDT ();
use Test::More tests => 12;

my $optrr = Net::DNS::RR->new(
    type => "OPT",
    version => 0,
    name => "",
    size => 1024,
    rcode => 0,
    flags => 0,
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
    answer => 'foo 0 CH TXT gdnsd/3',
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

# Queries containing Additional Records which are not OPT RRs...

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

# Try a bunch of records in all the non-question sections
{
    my $qpacket = Net::DNS::Packet->new();
    $qpacket->push('question', Net::DNS::Question->new('foo.example.com', 'A'));
    $qpacket->push('answer', Net::DNS::RR->new('. A 192.0.2.1')) for 1..15;
    $qpacket->push('auth', Net::DNS::RR->new('. AAAA ::192.0.2.1')) for 1..13;
    $qpacket->push('additional', Net::DNS::RR->new('. MX 0 192.0.2.1')) for 1..11;
    _GDT->test_dns(
        resopts => { usevc => 0, igntc => 1, udppacketsize => 1024 },
        qpacket => $qpacket,
        answer => 'foo.example.com 86400 A 192.0.2.3',
        addtl => $optrr,
        stats => [qw/udp_reqs noerror edns/],
    );
}

# An empty QUERY packet with no questions
{
    my $qpacket = Net::DNS::Packet->new();
    _GDT->test_dns(
        qpacket => $qpacket,
        header => { aa => 0, rcode => 'FORMERR' },
        noresq => 1,
        stats => [qw/udp_reqs formerr/],
    );
}

# A QUERY packet with *just* an OPT RR, but no questions, and no cookie, which
# will also FORMERR, but should still signal EDNS compliance
{
    my $qpacket = Net::DNS::Packet->new();
    _GDT->test_dns(
        resopts => { udppacketsize => 8080 },
        qpacket => $qpacket,
        header => { aa => 0, rcode => 'FORMERR' },
        noresq => 1,
        addtl => $optrr,
        stats => [qw/udp_reqs formerr edns/],
    );
}

# DO-bit should echo
{
    my @optrr_do = (
        type => "OPT",
        version => 0,
        name => "",
        size => 1024,
        rcode => 0,
        flags => 0x8000,
    );
    _GDT->test_dns(
        qname => 'cov.example.com', qtype => 'MX',
        q_optrr => Net::DNS::RR->new(@optrr_do),
        answer => 'cov.example.com 86400 MX 1 .',
        addtl => Net::DNS::RR->new(@optrr_do),
        stats => [qw/udp_reqs noerror edns edns_do/],
    );
}


_GDT->test_kill_daemon($pid);
