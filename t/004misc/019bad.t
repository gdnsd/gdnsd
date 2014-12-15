# This tests various malformed questions that have to be hand-encoded.
use _GDT ();
use Scalar::Util ();
use Test::More tests => 13;

my $_id = 5555;
sub make_query {
    my $qname = shift;
    my $arcount = shift || 0;
    my $qtype = shift || 1;
    return pack("nCCnnnna*nn",
        $_id++,
        0, # flags1
        0, # flags2
        1, # qdcount
        0, # ancount
        0, # nscount
        $arcount,
        $qname,
        $qtype,
        1, # qclass
    );
}

my $pid = _GDT->test_spawn_daemon();
sleep(1);
my $sock = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1:' . $_GDT::DNS_PORT,
    Proto => 'udp',
    Timeout => 2,
);

# A valid query, manually
my $test0 = make_query("\x07example\x03com\x00");
send($sock, $test0, 0);
eval {_GDT->check_stats(
    udp_reqs => 1,
    noerror => 1,
    dropped => 0,
)};
ok(!$@) or diag $@;

# Compressed label in question name
my $test1 = make_query("\x03ggg\xC0\x01");
send($sock, $test1, 0);
eval {_GDT->check_stats(
    udp_reqs => 2,
    noerror => 1,
    dropped => 1,
)};
ok(!$@) or diag $@;

# Question name illegally long
my $chrs_63 = '012345678901234567890123456789012345678901234567890123456789012';
my $test2 = make_query("\x3F$chrs_63\x3F$chrs_63\x3F$chrs_63\x3F$chrs_63\x3F$chrs_63\x00");
send($sock, $test2, 0);
eval {_GDT->check_stats(
    udp_reqs => 3,
    noerror => 1,
    dropped => 2,
)};
ok(!$@) or diag $@;

# A valid question, but truncate the packet before qclass has ended
my $test3_ok = make_query("\x03ggg\x00");
my $test3_bad = substr($test3_ok, 0, -1);
send($sock, $test3_bad, 0);
eval {_GDT->check_stats(
    udp_reqs => 4,
    noerror => 1,
    dropped => 3,
)};
ok(!$@) or diag $@;

# A valid question, but truncate the packet before qtype has ended
my $test4_ok = make_query("\x03ggg\x00");
my $test4_bad = substr($test4_ok, 0, -3);
send($sock, $test4_bad, 0);
eval {_GDT->check_stats(
    udp_reqs => 5,
    noerror => 1,
    dropped => 4,
)};
ok(!$@) or diag $@;

# A valid question, but truncate the packet before qname has ended
my $test5_ok = make_query("\x03ggg\x03zzz\x00");
my $test5_bad = substr($test5_ok, 0, -5);
send($sock, $test5_bad, 0);
eval {_GDT->check_stats(
    udp_reqs => 6,
    noerror => 1,
    dropped => 5,
)};
ok(!$@) or diag $@;

# A valid question, but a too-short OPT RR at the end
my $test6 = make_query("\x03ggg\x00", 1);
$test6 .= "\x00\x00\x00";
send($sock, $test6, 0);
eval {_GDT->check_stats(
    udp_reqs => 7,
    noerror => 1,
    dropped => 5,
    refused => 1,
)};
ok(!$@) or diag $@;

# A valid question with a very small EDNS size in OPT
my $test6b = make_query("\x03ggg\x00", 1);
$test6b .= "\x00\x00\x29\x00\x01\x00\x00\x00\x00\x00\x00";
send($sock, $test6b, 0);
eval {_GDT->check_stats(
    udp_reqs => 8,
    noerror => 1,
    dropped => 5,
    refused => 2,
    edns => 1,
)};
ok(!$@) or diag $@;

# IXFR
my $test7 = make_query("\x07example\x03com\x00", 0, 251);
send($sock, $test7, 0);
eval {_GDT->check_stats(
    udp_reqs => 9,
    noerror => 1,
    dropped => 5,
    refused => 2,
    edns => 1,
    notimp => 1,
)};
ok(!$@) or diag $@;

close($sock);

# Test a valid query to make sure the server is still functioning
eval {_GDT->query_server(
    undef,
    Net::DNS::Packet->new('foo.example.com', 'A'),
    _GDT->mkanswer({ },
        Net::DNS::Question->new('foo.example.com', 'A'),
        [Net::DNS::rr_add('foo.example.com 86400 A 192.0.2.3')], [
            Net::DNS::rr_add('example.com 86400 NS ns1.example.com'),
            Net::DNS::rr_add('example.com 86400 NS ns2.example.com'),
        ], [
            Net::DNS::rr_add('ns1.example.com 86400 A 192.0.2.1'),
            Net::DNS::rr_add('ns2.example.com 86400 A 192.0.2.2'),
        ],
    ),
    _GDT->get_resolver(), {},
)};
ok(!$@) or diag $@;

eval {_GDT->check_stats(
    udp_reqs => 10,
    noerror => 2,
    dropped => 5,
    refused => 2,
    edns => 1,
    notimp => 1,
)};
ok(!$@) or diag $@;

_GDT->test_kill_daemon($pid);
