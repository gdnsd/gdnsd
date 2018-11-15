# Test various forms of "broken" queries

use _GDT ();
use Test::More tests => 15;

my $neg_soa = 'example.com 900 SOA ns1.example.com hmaster.example.net 1 7200 1800 259200 900';

my $pid = _GDT->test_spawn_daemon();

{   # more than one question, and using compression for the second name
    my $qpacket = Net::DNS::Packet->new();
    $qpacket->push('question', Net::DNS::Question->new('foo.example.com', 'A'));
    $qpacket->push('question', Net::DNS::Question->new('foo.example.com', 'A'));
    _GDT->test_dns(
        qpacket => $qpacket,
        header => { rcode => 'FORMERR', aa => 0 },
        stats => [qw/udp_reqs formerr/],
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

{   # TC bit set, which we ignore in queries
    my $qpacket = Net::DNS::Packet->new('foo.example.com', 'A');
    $qpacket->header->tc(1);
    _GDT->test_dns(
        qpacket => $qpacket,
        answer => 'foo.example.com 21600 A 192.0.2.160',
        stats => [qw/udp_reqs noerror/],
    );
}

{   # AXFR - stats result should be NOTIMP over TCP
    my @zone = ();
    eval { @zone = _GDT->get_resolver()->axfr('example.com'); };
    ok(!scalar @zone) or diag "AXFR gave us records???";
    _GDT->stats_inc(qw/tcp_reqs tcp_conns notimp/);
    _GDT->test_stats();
}

{   # non-QUERY opcode
    my $qpacket = Net::DNS::Packet->new('foo.example.com', 'A');
    $qpacket->header->opcode('IQUERY');
    $qpacket->header->rd(0); # No idea why Net::DNS flips this bit on here...
    _GDT->test_dns(
        qpacket => $qpacket,
        header => { rcode => 'NOTIMP', opcode => 'IQUERY', aa => 0 },
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
    version => 0,
    name => "",
    size => 1024,
    rcode => 0,
    flags => 0,
);

# EDNS unknown option
{
    my $optrr_req = Net::DNS::RR->new(@edns_base);
    $optrr_req->option(0x5555 => 'foo');
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
    my $optrr_req = Net::DNS::RR->new(@edns_base);
    $optrr_req->option(0x5555 => '');
    my $optrr_res = Net::DNS::RR->new(@edns_base);
    _GDT->test_dns(
        qname => 'foo.example.com', qtype => 'A',
        q_optrr => $optrr_req,
        answer => 'foo.example.com 21600 A 192.0.2.160',
        addtl => $optrr_res,
        stats => [qw/noerror udp_reqs edns/],
    );
}

my $optrr_resp = Net::DNS::RR->new(
    type => "OPT",
    version => 0,
    name => "",
    size => 1024,
    rcode => 0,
    flags => 0,
);

# NSID query when not configured
{
    my $optrr_nsid = Net::DNS::RR->new(
        type => "OPT",
        version => 0,
        name => "",
        size => 1024,
        rcode => 0,
        flags => 0,
    );
    $optrr_nsid->option(NSID => '');

    _GDT->test_dns(
        qname => 'foo.example.com', qtype => 'A',
        q_optrr => $optrr_nsid,
        answer => 'foo.example.com 21600 A 192.0.2.160',
        addtl => $optrr_resp,
        stats => [qw/udp_reqs edns noerror/]
    );
}

# NSID with illegal client-sent NSID data
{
    my $optrr_nsid_withdata = Net::DNS::RR->new(
        type => "OPT",
        version => 0,
        name => "",
        size => 1024,
        rcode => 0,
        flags => 0,
    );
    $optrr_nsid_withdata->option(NSID => pack('H*', '6578616D706C65'));

    _GDT->test_dns(
        qname => 'foo.example.com', qtype => 'A',
        q_optrr => $optrr_nsid_withdata,
        header => { rcode => 'FORMERR', aa => 0 },
        addtl => $optrr_resp,
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
