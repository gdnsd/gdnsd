# This tests various malformed questions that have to be hand-encoded because
# Net::DNS can't ask such silly questions, basically.

# Some of the tests that had to be moved here from other test scripts while
# working on Net::DNS 1.03-19 compatibility used to test the contents of the
# output packets as well, and now they don't.  But I did add matching recv()
# calls to all of these to confirm they receive a response packet at all, and
# we are still checking for appropriate stats increments.  Should probably
# parse the responses for better testing here!  I added notes to the recent
# additions in commentary, about the output they should parse for.

use _GDT ();
use Scalar::Util ();
use Test::More tests => 33;

my $recvbuf = '';

my $_id = 5555;
sub make_query {
    my $qname = shift;
    my $qdcount = shift || 1;
    my $ancount = shift || 0;
    my $nscount = shift || 0;
    my $arcount = shift || 0;
    my $qtype = shift || 1;
    my $qclass = shift || 1;
    my $optdata = shift || '';
    return pack("nCCnnnna*nn",
        $_id++,
        0, # flags1
        0, # flags2
        $qdcount,
        $ancount,
        $nscount,
        $arcount,
        $qname,
        $qtype,
        $qclass
    ) . $optdata;
}

sub make_tcp_query {
    my $data = make_query(@_);
    return pack("n", length($data)) . $data;
}

my $pid = _GDT->test_spawn_daemon();
my $sock = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1:' . $_GDT::DNS_PORT,
    Proto => 'udp',
    Timeout => 3,
);

# A valid query, manually
my $test2 = make_query("\x07example\x03com\x00");
send($sock, $test2, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 1,
    noerror => 1,
)};
ok(!$@) or diag $@;

# Compressed label in question name
my $test3 = make_query("\x03ggg\xC0\x01");
send($sock, $test3, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 2,
    noerror => 1,
    formerr => 1,
)};
ok(!$@) or diag $@;

# Question name illegally long
my $chrs_63 = '012345678901234567890123456789012345678901234567890123456789012';
my $test4 = make_query("\x3F$chrs_63\x3F$chrs_63\x3F$chrs_63\x3F$chrs_63\x3F$chrs_63\x00");
send($sock, $test4, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 3,
    noerror => 1,
    formerr => 2,
)};
ok(!$@) or diag $@;

# A valid question, but truncate the packet before qclass has ended
my $test5_ok = make_query("\x03ggg\x00");
my $test5_bad = substr($test5_ok, 0, -1);
send($sock, $test5_bad, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 4,
    noerror => 1,
    formerr => 3,
)};
ok(!$@) or diag $@;

# A valid question, but truncate the packet before qtype has ended
my $test6_ok = make_query("\x03ggg\x00");
my $test6_bad = substr($test6_ok, 0, -3);
send($sock, $test6_bad, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 5,
    noerror => 1,
    formerr => 4,
)};
ok(!$@) or diag $@;

# A valid question, but truncate the packet before qname has ended
my $test7_ok = make_query("\x03ggg\x03zzz\x00");
my $test7_bad = substr($test7_ok, 0, -5);
send($sock, $test7_bad, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 6,
    noerror => 1,
    formerr => 5,
)};
ok(!$@) or diag $@;

# A valid question, but a too-short OPT RR at the end
my $test8 = make_query("\x03ggg\x00", 1, 0, 0, 1);
$test8 .= "\x00\x00\x00";
send($sock, $test8, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 7,
    noerror => 1,
    formerr => 6,
)};
ok(!$@) or diag $@;

# A valid question with a very small EDNS size in OPT
my $test9 = make_query("\x03ggg\x00", 1, 0, 0, 1);
$test9 .= "\x00\x00\x29\x00\x01\x00\x00\x00\x00\x00\x00";
send($sock, $test9, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 8,
    noerror => 1,
    formerr => 6,
    refused => 1,
    edns => 1,
)};
ok(!$@) or diag $@;

# IXFR
my $test10 = make_query("\x07example\x03com\x00", 1, 0, 0, 0, 251);
send($sock, $test10, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 9,
    noerror => 1,
    formerr => 6,
    refused => 1,
    edns => 1,
    notimp => 1,
)};
ok(!$@) or diag $@;

# CLASS=HS
my $test11 = make_query("\x07example\x03com\x00", 1, 0, 0, 0, 1, 4);
send($sock, $test11, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 10,
    noerror => 1,
    formerr => 6,
    refused => 2,
    edns => 1,
    notimp => 1,
)};
ok(!$@) or diag $@;

# QCLASS=ANY, works just like IN
my $test12 = make_query("\x07example\x03com\x00", 1, 0, 0, 0, 1, 255);
send($sock, $test12, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 11,
    noerror => 2,
    formerr => 6,
    refused => 2,
    edns => 1,
    notimp => 1,
)};
ok(!$@) or diag $@;

# QDCOUNT=2, but only 1 query present in packet
my $test13 = make_query("\x07example\x03com\x00", 2);
send($sock, $test13, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 12,
    noerror => 2,
    formerr => 7,
    refused => 2,
    edns => 1,
    notimp => 1,
)};
ok(!$@) or diag $@;

# QDCOUNT=2, second question truncates mid-label
my $test14 = make_query("\x07example\x03com\x00", 2);
$test14 .= "\x07abc";
send($sock, $test14, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 13,
    noerror => 2,
    formerr => 8,
    refused => 2,
    edns => 1,
    notimp => 1,
)};
ok(!$@) or diag $@;

# QDCOUNT=2, second question truncates in type/class
my $test15 = make_query("\x07example\x03com\x00", 2);
$test15 .= "\x07example\x00\x01";
send($sock, $test15, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 14,
    noerror => 2,
    formerr => 9,
    refused => 2,
    edns => 1,
    notimp => 1,
)};
ok(!$@) or diag $@;

# QDCOUNT=2, second question illegally-long name
my $test16 = make_query("\x07example\x03com\x00", 2);
$test16 .= "\x3f012345678901234567890123456789012345678901234567890123456789012"; # 63-byte label
$test16 .= "\x3f012345678901234567890123456789012345678901234567890123456789012"; # 63-byte label
$test16 .= "\x3f012345678901234567890123456789012345678901234567890123456789012"; # 63-byte label
$test16 .= "\x3f012345678901234567890123456789012345678901234567890123456789012"; # 63-byte label (now illegal)
$test16 .= "\x00\x00\x00\x00\x00"; # terminal label, type, class
send($sock, $test16, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 15,
    noerror => 2,
    formerr => 10,
    refused => 2,
    edns => 1,
    notimp => 1,
)};
ok(!$@) or diag $@;

# Duplicate OPT record
my $test17 = make_query("\x07example\x03com\x00", 1, 0, 0, 2);
$test17 .= "\x00\x00\x29\x00\x01\x00\x00\x00\x00\x00\x00";
$test17 .= "\x00\x00\x29\x00\x01\x00\x00\x00\x00\x00\x00";
send($sock, $test17, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 16,
    noerror => 2,
    formerr => 11,
    refused => 2,
    edns => 2,
    notimp => 1,
)};
ok(!$@) or diag $@;

# Normal question, answer-section record has a partial compression pointer that
# dangles off the packet
my $test18 = make_query("\x07example\x03com\x00", 1, 1);
$test18 .= "\x07example\xC0";
send($sock, $test18, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 17,
    noerror => 2,
    formerr => 12,
    refused => 2,
    edns => 2,
    notimp => 1,
)};
ok(!$@) or diag $@;

# Normal question, auth-section record is one byte short of having a complete
# rdlen field
my $test19 = make_query("\x07example\x03com\x00", 1, 0, 1);
$test19 .= "\xC0\x0C\x00\x01\x00\x01\x00\x00\x00\x01\x00";
#           ^compqn ^type   ^class  ^ttl            ^rdlen
send($sock, $test19, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 18,
    noerror => 2,
    formerr => 13,
    refused => 2,
    edns => 2,
    notimp => 1,
)};
ok(!$@) or diag $@;

# Normal question, auth-section record is one byte short on actual rdata
my $test20 = make_query("\x07example\x03com\x00", 1, 0, 1);
$test20 .= "\xC0\x0C\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\x01\x02\x02";
#           ^compqn ^type   ^class  ^ttl            ^rdlen  ^rdata
send($sock, $test20, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 19,
    noerror => 2,
    formerr => 14,
    refused => 2,
    edns => 2,
    notimp => 1,
)};
ok(!$@) or diag $@;

# OPT RR with version=1
my $test21 = make_query("\x07example\x03com\x00", 1, 0, 0, 1);
$test21 .= "\x00\x00\x29\x02\x00\x00\x01\x00\x00\x00\x00";
send($sock, $test21, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 20,
    noerror => 2,
    formerr => 14,
    refused => 2,
    edns => 3,
    notimp => 1,
    badvers => 1,
)};
ok(!$@) or diag $@;
# resp check: 1/0/0/1, aa=>0, rcode=>badvers, matches question

# OPT RR w/ rdlen that goes past end of packet...
my $test22 = make_query("\x07example\x03com\x00", 1, 0, 0, 1);
$test22 .= "\x00\x00\x29\x02\x00\x00\x00\x00\x00\x00\x01";
send($sock, $test22, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 21,
    noerror => 2,
    formerr => 15,
    refused => 2,
    edns => 4,
    notimp => 1,
    badvers => 1,
)};
ok(!$@) or diag $@;
# resp check: 1/0/0/1, aa=>0, rcode=>formerr, matches question

# OPT RR w/ rdata too short to parse as optcode+optlen
my $test23 = make_query("\x07example\x03com\x00", 1, 0, 0, 1);
$test23 .= "\x00\x00\x29\x02\x00\x00\x00\x00\x00\x00\x03\x78\x78\x78";
send($sock, $test23, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 22,
    noerror => 2,
    formerr => 16,
    refused => 2,
    edns => 5,
    notimp => 1,
    badvers => 1,
)};
ok(!$@) or diag $@;
# resp check: 1/0/0/1, aa=>0, rcode=>formerr, matches question

# OPT RR w/ valid rdlen, valid optcode, but optlen overrun
my $test24 = make_query("\x07example\x03com\x00", 1, 0, 0, 1);
$test24 .= "\x00\x00\x29\x02\x00\x00\x00\x00\x00\x00\x05\x55\x55\x00\x02\x01";
send($sock, $test24, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 23,
    noerror => 2,
    formerr => 17,
    refused => 2,
    edns => 6,
    notimp => 1,
    badvers => 1,
)};
ok(!$@) or diag $@;
# resp check: 1/0/0/1, aa=>0, rcode=>formerr, matches question

# OPT RR followed by some other additional record:
my $test25 = make_query("\x03foo\x07example\x03com\x00", 1, 0, 0, 2);
$test25 .= "\x00\x00\x29\x02\x00\x00\x00\x00\x00\x00\x00"; # OPT RR
$test25 .= "\x07example\x00\x00\x01\x00\x01\x00\x00\x00\xFF\x00\x04\x01\x02\x03\x04";
#          ^ "example. 255 IN A 1.2.3.4"
send($sock, $test25, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 24,
    noerror => 3,
    formerr => 17,
    refused => 2,
    edns => 7,
    notimp => 1,
    badvers => 1,
)};
ok(!$@) or diag $@;
# resp check: 1/0/0/1, aa=>1, rcode=>noerror, matches question, has response A-record 'foo.example.com 86400 A 192.0.2.3'

# OPT RR *after* some other additional record:
my $test26 = make_query("\x03foo\x07example\x03com\x00", 1, 0, 0, 2);
$test26 .= "\x07example\x00\x00\x01\x00\x01\x00\x00\x00\xFF\x00\x04\x01\x02\x03\x04";
#          ^ "example. 255 IN A 1.2.3.4"
$test26 .= "\x00\x00\x29\x02\x00\x00\x00\x00\x00\x00\x00"; # OPT RR
send($sock, $test26, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 25,
    noerror => 4,
    formerr => 17,
    refused => 2,
    edns => 8,
    notimp => 1,
    badvers => 1,
)};
ok(!$@) or diag $@;
# resp check: 1/0/0/1, aa=>1, rcode=>noerror, matches question, has response A-record 'foo.example.com 86400 A 192.0.2.3'

# Valid OPT RR, which contains 2x cookies, with a normal REFUSED query
my $test27 = make_query("\x03foo\x00", 1, 0, 0, 1);
$test27 .= "\x00\x00\x29\x02\x00\x00\x00\x00\x00\x00\x18"; # OPT RR w/ rdlen=24
$test27 .= "\x00\x0A\x00\x08\x01\x23\x45\x67\x89\xAB\xCD\xEF"; # 12 byte minimal cookie option
$test27 .= "\x00\x0A\x00\x08\xFE\xDC\xBA\x98\x76\x54\x32\x10"; # 12 byte minimal cookie option
send($sock, $test27, 0);
recv($sock, $recvbuf, 4096, 0);
eval {_GDT->check_stats(
    udp_reqs => 26,
    noerror => 4,
    formerr => 17,
    refused => 3,
    edns => 9,
    notimp => 1,
    badvers => 1,
    edns_cookie_init => 1,
)};
ok(!$@) or diag $@;
# resp check: 1/0/0/1, aa=>0, rcode=>refused, matches question, EDNS Cookie output matching client cookie from *first* cookie sent

close($sock);

# T28
# TCP pipelining test.  We'll send a raw single send() with 5x minimal
# questions (REFUSED due to root name) followed by a "real" question (NOERROR)
# and then check stats etc.
my $six_tcp_piped = (make_tcp_query("\x00") x 5) . make_tcp_query("\x07example\x03com\x00");
my $tcp_sock = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1:' . $_GDT::DNS_PORT,
    Proto => 'tcp',
    Timeout => 10,
);
send($tcp_sock, $six_tcp_piped, 0);
# Let responses just buffer, who cares for now
eval {_GDT->check_stats(
    udp_reqs => 26,
    tcp_reqs => 6,
    noerror => 5,
    formerr => 17,
    refused => 8,
    edns => 9,
    notimp => 1,
    badvers => 1,
    edns_cookie_init => 1,
    tcp_conns => 1,
)};
ok(!$@) or diag $@;

# T29
# PROXYv1 + TCP pipelining test.  We'll send a raw single send() with a PROXYv1
# header and 5x minimal questions (REFUSED due to root name) followed by a
# "real" question (NOERROR) and then check stats etc.
my $six_proxy_piped = "PROXY TCP4 127.0.0.1 127.0.0.1 1234 4321\r\n"
    . (make_tcp_query("\x00") x 5) . make_tcp_query("\x07example\x03com\x00");
my $proxy_sock = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1:' . $_GDT::EXTRA_PORT,
    Proto => 'tcp',
    Timeout => 10,
);
send($proxy_sock, $six_proxy_piped, 0);
# Let responses just buffer, who cares for now
eval {_GDT->check_stats(
    udp_reqs => 26,
    tcp_reqs => 12,
    noerror => 6,
    formerr => 17,
    refused => 13,
    edns => 9,
    notimp => 1,
    badvers => 1,
    edns_cookie_init => 1,
    tcp_proxy => 1,
    tcp_proxy_fail => 0,
    tcp_conns => 2,
)};
ok(!$@) or diag $@;

# T30
# PROXYv2 + TCP pipelining test.  We'll send a raw single send() with a PROXYv2
# header and 5x minimal questions (REFUSED due to root name) followed by a
# "real" question (NOERROR) which also includes an EDNS padding option and then check stats etc.
my $six_proxy2_piped = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A" # 12 byte sig
    . "\x21\x11\x00\x0C" # PROXY TCP4 w/ 12 bytes addr data
    . "\x7F\x00\x00\x01\x7F\x00\x00\x01\x04\xD2\x10\xE1" # Same addrs/ports as v1 above
    . (make_tcp_query("\x00") x 5)
    . make_tcp_query("\x07example\x03com\x00", 1, 0, 0, 1, 1, 1,
         # OPT w/ EDNS padding + 3 pad data bytes
         "\x00\x00\x29\x02\x00\x00\x00\x00\x00\x00\x07\x00\x0C\x00\x03\x00\x00\x00");
my $proxy2_sock = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1:' . $_GDT::EXTRA_PORT,
    Proto => 'tcp',
    Timeout => 10,
);
send($proxy2_sock, $six_proxy2_piped, 0);
# Let responses just buffer, who cares for now
eval {_GDT->check_stats(
    udp_reqs => 26,
    tcp_reqs => 18,
    noerror => 7,
    formerr => 17,
    refused => 18,
    edns => 10,
    notimp => 1,
    badvers => 1,
    edns_cookie_init => 1,
    tcp_proxy => 2,
    tcp_proxy_fail => 0,
    tcp_conns => 3,
)};
ok(!$@) or diag $@;

# Half-close our side of the 3 TCP test sockets above, so we don't stall server shutdown
shutdown($tcp_sock, 1); # SHUT_WR
shutdown($proxy_sock, 1); # SHUT_WR
shutdown($proxy2_sock, 1); # SHUT_WR

# T31
# Test a valid query to make sure the server is still functioning
eval {_GDT->query_server(
    undef,
    Net::DNS::Packet->new('foo.example.com', 'A'),
    _GDT->mkanswer({ },
        Net::DNS::Question->new('foo.example.com', 'A'),
        [Net::DNS::rr_add('foo.example.com 86400 A 192.0.2.3')], [], [],
    ),
    _GDT->get_resolver(), {},
)};
ok(!$@) or diag $@;

# T32
eval {_GDT->check_stats(
    udp_reqs => 27,
    tcp_reqs => 18,
    noerror => 8,
    formerr => 17,
    refused => 18,
    edns => 10,
    notimp => 1,
    badvers => 1,
    edns_cookie_init => 1,
    tcp_proxy => 2,
    tcp_proxy_fail => 0,
    tcp_conns => 3,
)};
ok(!$@) or diag $@;

# T33
_GDT->test_kill_daemon($pid);
