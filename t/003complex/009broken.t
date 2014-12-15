# Test various forms of "broken" queries

use _GDT ();
use Test::More tests => 17;

my $neg_soa = 'example.com 900 SOA ns1.example.com hmaster.example.net 1 7200 1800 259200 900';

my $pid = _GDT->test_spawn_daemon();

{   # more than one question
    my $qpacket = Net::DNS::Packet->new();
    $qpacket->push('question', Net::DNS::Question->new('foo.example.com', 'A'));
    $qpacket->push('question', Net::DNS::Question->new('foo.example.com', 'A'));
    _GDT->test_dns(
        qpacket => $qpacket,
        nores => 1,
        stats => [qw/udp_reqs dropped/],
    );
}

{   # QR bit set
    my $qpacket = Net::DNS::Packet->new('foo.example.com', 'A');
    $qpacket->header->qr(1);
    _GDT->test_dns(
        qpacket => $qpacket,
        nores => 1,
        stats => [qw/udp_reqs dropped/],
    );
}

{   # TC bit set
    my $qpacket = Net::DNS::Packet->new('foo.example.com', 'A');
    $qpacket->header->tc(1);
    _GDT->test_dns(
        qpacket => $qpacket,
        nores => 1,
        stats => [qw/udp_reqs dropped/],
    );
}

{   # AXFR - stats result should be NOTIMP over TCP
    eval {
        my @zone = _GDT->get_resolver()->axfr('example.com');
        die "AXFR gave us records???" if scalar @zone;
    };
    ok(!$@) or diag $@;
    _GDT->stats_inc(qw/tcp_reqs notimp/);
    _GDT->test_stats();
}

{   # non-QUERY opcode
    my $qpacket = Net::DNS::Packet->new('foo.example.com', 'A');
    $qpacket->header->opcode('IQUERY');
    $qpacket->header->rd(0); # No idea why Net::DNS flips this bit on here...
    _GDT->test_dns(
        qpacket => $qpacket,
        header => { rcode => 'NOTIMP', opcode => 'IQUERY', aa => 0 },
        noresq => 1,
        stats => [qw/udp_reqs notimp/],
    );
}

# An "unsupported" RR-type, as in one we don't ever have records
# for, or even functions to encode data for.
_GDT->test_dns(
    qname => 'foo.example.com', qtype => 'KEY',
    auth => $neg_soa,
);

# As above, but the code is >255
_GDT->test_dns(
    qname => 'foo.example.com', qtype => "TYPE300",
    auth => $neg_soa,
);

my @edns_base = (
    type => "OPT",
    ednsversion => 0,
    name => "",
    class => 1024,
    extendedrcode => 0,
    ednsflags => 0,
);

# EDNS badversion
{
    my $optrr_req = Net::DNS::RR->new(@edns_base, class => 512, ednsversion => 1);
    my $optrr_res = Net::DNS::RR->new(@edns_base, extendedrcode => 1);
    _GDT->test_dns(
        qname => 'foo.example.com', qtype => 'A',
        q_optrr => $optrr_req,
        header => { aa => 0 },
        addtl => $optrr_res,
        stats => [qw/udp_reqs edns badvers/],
    );
}

# EDNS unknown option
{
    my $optrr_req = Net::DNS::RR->new(@edns_base, optioncode => 0x5555, optiondata => 'foo');
    my $optrr_res = Net::DNS::RR->new(@edns_base);
    _GDT->test_dns(
        qname => 'foo.example.com', qtype => 'A',
        q_optrr => $optrr_req,
        answer => 'foo.example.com 21600 A 192.0.2.160',
        addtl => $optrr_res,
        stats => [qw/noerror udp_reqs edns/],
    );
}

# EDNS unknown option + zero optlen
{
    my $optrr_req = Net::DNS::RR->new(@edns_base, optioncode => 0x5555, optiondata => '');
    my $optrr_res = Net::DNS::RR->new(@edns_base);
    _GDT->test_dns(
        qname => 'foo.example.com', qtype => 'A',
        q_optrr => $optrr_req,
        answer => 'foo.example.com 21600 A 192.0.2.160',
        addtl => $optrr_res,
        stats => [qw/noerror udp_reqs edns/],
    );
}

# EDNS w/ rdlen that goes past end of packet...
{
    # optrr rdlen set to 1 nonexistent byte
    my $pkt = Net::DNS::Packet->new('example.com', 'A');
    $pkt->header->rd(0);
    $pkt->push(additional => Net::DNS::RR->new(@edns_base));
    my $id = $pkt->header->id;
    my $raw = $pkt->data;
    substr($raw, -2, 2, pack('n', 1));

    my $optrr_res = Net::DNS::RR->new(@edns_base);
    _GDT->test_dns(
        qpacket_raw => $raw,
        qname => 'example.com', qtype => 'A', qid => $id,
        header => { rcode => 'FORMERR', aa => 0},
        addtl => $optrr_res,
        stats => [qw/udp_reqs edns formerr/]
    );
}

# EDNS w/ rdata too short to parse as optcode+optlen
{
    # optrr rdata set to 3 bytes of 'xxx'
    my $pkt = Net::DNS::Packet->new('example.com', 'A');
    $pkt->header->rd(0);
    $pkt->push(additional => Net::DNS::RR->new(@edns_base));
    my $id = $pkt->header->id;
    my $raw = $pkt->data;
    substr($raw, -2, 2, pack('n', 3));
    $raw .= 'xxx';

    my $optrr_res = Net::DNS::RR->new(@edns_base);
    _GDT->test_dns(
        qpacket_raw => $raw,
        qname => 'example.com', qtype => 'A', qid => $id,
        header => { rcode => 'FORMERR', aa => 0},
        addtl => $optrr_res,
        stats => [qw/udp_reqs edns formerr/]
    );
}

# EDNS w/ valid rdlen, valid optcode, but optlen overrun
{
    # optrr rdlen is valid @ 5 bytes, but option len goes past that..
    my $pkt = Net::DNS::Packet->new('example.com', 'A');
    $pkt->header->rd(0);
    $pkt->push(additional => Net::DNS::RR->new(@edns_base));
    my $id = $pkt->header->id;
    my $raw = $pkt->data;
    substr($raw, -2, 2, pack('n', 5));
    $raw .= pack('nnC', 0x5555, 2, 1);

    my $optrr_res = Net::DNS::RR->new(@edns_base);
    _GDT->test_dns(
        qpacket_raw => $raw,
        qname => 'example.com', qtype => 'A', qid => $id,
        header => { rcode => 'FORMERR', aa => 0},
        addtl => $optrr_res,
        stats => [qw/udp_reqs edns formerr/]
    );
}

# Ordinary valid query, to sanity-check the server after the above.
#  For bonus points, as long as we're checking header bits in this
#  file in general, check that the RD bit is copied to the client,
#  since all other tests keep it clear (as it should be).
_GDT->test_dns(
    resopts => { recurse => 1 },
    qname => 'foo.example.com', qtype => 'A',
    header => { rd => 1 },
    answer => 'foo.example.com 21600 A 192.0.2.160',
);

_GDT->test_kill_daemon($pid);
