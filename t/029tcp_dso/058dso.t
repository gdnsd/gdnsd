# RFC 8490 DSO testing!  Note we don't have any library support for this, so
# it's all raw packet comparisons...

use threads;
use _GDT ();
use Test::More tests => 42;
use strict;
use warnings;

sub make_udp_sock {
    return IO::Socket::INET->new(
        PeerAddr => '127.0.0.1:' . $_GDT::DNS_PORT,
        Proto => 'udp',
        Timeout => 3,
    );
}

sub make_tcp_sock {
    my $do_pad = shift || 0;
    return IO::Socket::INET->new(
        PeerAddr => '127.0.0.1:' . ($do_pad ? $_GDT::EXTRA_PORT : $_GDT::DNS_PORT),
        Proto => 'tcp',
        Timeout => 3,
    );
}

# ID number incremented after each txn
my $ID = 50505;

# Wrap a DNS packet in a TCP length prefix
sub wrap_tcp_prefix {
    my $data = shift;
    return pack("n", length($data)) . $data;
}

# Receive a TCP DNS response
sub recv_tcp {
    my $sock = shift;
    my $raw_len;
    recv($sock, $raw_len, 2, 0);
    if (defined($raw_len) && length($raw_len) == 2) {
        my $len = unpack('n', $raw_len);
        my $buf;
        recv($sock, $buf, $len, 0);
        return $raw_len . $buf;
    } else {
        return '';
    }
}

# Just a basic OPT RR with size=1024
my $basic_optrr = "\x00\x00\x29\x04\x00\x00\x00\x00\x00\x00\x00";

# When DSO isn't established, we expect gdnsd to respond with the RFC 7828 keepalive option at 37s like this:
my $rfc7828_optrr = "\x00\x00\x29\x04\x00\x00\x00\x00\x00\x00\x06\x00\x0B\x00\x02\x01\x72";

# This is tailored to the ns1 query response below, and includes EDNS padding to 468
my $padded_optrr = "\x00\x00\x29\x04\x00\x00\x00\x00\x00\x01\x98\x00\x0C\x01\x94" . ("\x00" x 404);

# This manually creates a basic "ns1.example.com A" query, and manually creates
# the expected response packet with QR+AA bits, full name compression, and the
# address 192.0.2.1, and then executes the query against the server and
# compares the answer, and then increments $ID for the next test.
# $tcp: format for TCP
# $edns_send: the raw EDNS OPT RR to include with the query
# $edns_expect: response EDNS OPT RR to expect
#   (if undefined, don't even try to receive an answer, assume the conn was dropped because we sent something illegal)
sub test_ns1_query {
    my ($sock, $tcp, $edns_send, $edns_expect) = @_;
    my $q_ns1 = pack('nCCnnnna*nna*',
        $ID, 0, 0, 1, 0, 0, 1, "\x03ns1\x07example\x03com\x00", 1, 1, $edns_send
    );
    $q_ns1 = wrap_tcp_prefix($q_ns1) if $tcp;
    send($sock, $q_ns1, 0);
    if (defined($edns_expect)) {
        my $recvbuf;
        if ($tcp) {
            $recvbuf = recv_tcp($sock);
        } else {
            recv($sock, $recvbuf, 4096, 0);
        }
        my $e_ns1 = pack('nCCnnnna*nna*nnNnNa*',
            $ID, 132, 0, 1, 1, 0, 1, "\x03ns1\x07example\x03com\x00", 1, 1,
            "\xC0\x0C", 1, 1, 86400, 4, 3221225985, $edns_expect
        );
        $e_ns1 = wrap_tcp_prefix($e_ns1) if $tcp;
        $ID++;
        return $recvbuf eq $e_ns1;
    }
    return 1;
}

sub test_dso_ka {
    my $sock = shift;
    my $send_pad = shift || 0;
    my $expect_pad = shift || 0;
    my $raw_q_ka = pack('nCCnnnn nnNN',
        $ID, 48, 0, 0, 0, 0, 0, 1, 8, 1234, 5678 # opcode=6 DSO, abitrary times
    );
    if ($send_pad) {
        $raw_q_ka .= pack('nna*', 3, 13, '0123456789abc');
    }
    my $q_ka = wrap_tcp_prefix($raw_q_ka);
    send($sock, $q_ka, 0);
    my $recvbuf = recv_tcp($sock);
    my $e_ka_raw = pack('nCCnnnn nnNN',
        $ID, 176, 0, 0, 0, 0, 0, 1, 8, 0xFFFFFFFF, 37000 # +QR-bit, and actual gdnsd values
    );
    if ($expect_pad) {
        my $pad_dlen = 468 - length($e_ka_raw) - 4;
        $e_ka_raw .= pack('nn', 3, $pad_dlen);
        $e_ka_raw .= ("\x00" x $pad_dlen);
    }
    my $e_ka = wrap_tcp_prefix($e_ka_raw);
    $ID++;
    return $recvbuf eq $e_ka;
}

my $pid = _GDT->test_spawn_daemon();

{ # T2-3
    # This connection establishes DSO immediately, so it never sees EDNS KA.
    # It also sends a padding ATLV just to check that works
    my $tcp_sock = make_tcp_sock();
    ok(test_dso_ka($tcp_sock, 1));
    ok(test_ns1_query($tcp_sock, 1, $basic_optrr, $basic_optrr));
}

# T4
eval {_GDT->check_stats(
    tcp_conns => 1,
    tcp_close_c => 1,
    tcp_reqs => 1,
    noerror => 1,
    edns => 1,
    tcp_dso_estab => 1,
    tcp_dso_typeni => 0,
    tcp_dso_protoerr => 0,
)};
ok(!$@) or diag $@;

{ # T5-8
    # This connection does a normal TCP query and receives the EDNS Keepalive
    # response, then establishes DSO, then does another EDNS query which should
    # not get the EDNS Keepalive response, because DSO is now established.
    # Afterwards, do another pointless KeepAlive just to exercise it while DSO
    # is already established.
    my $tcp_sock = make_tcp_sock();
    ok(test_ns1_query($tcp_sock, 1, $basic_optrr, $rfc7828_optrr));
    ok(test_dso_ka($tcp_sock));
    ok(test_ns1_query($tcp_sock, 1, $basic_optrr, $basic_optrr));
    ok(test_dso_ka($tcp_sock));
}

# T9
eval {_GDT->check_stats(
    tcp_conns => 2,
    tcp_close_c => 2,
    tcp_reqs => 3,
    noerror => 3,
    edns => 3,
    tcp_dso_estab => 2,
    tcp_dso_typeni => 0,
    tcp_dso_protoerr => 0,
)};
ok(!$@) or diag $@;

{ # T10-11
    # Establish DSO and then send an EDNS KA.  Causes immediate connection
    # abort with tcp_dso_protoerr, dropped, tcp_close_s_err stats
    my $tcp_sock = make_tcp_sock();
    ok(test_dso_ka($tcp_sock));
    ok(test_ns1_query($tcp_sock, 1, $rfc7828_optrr, undef));
}

# T12
eval {_GDT->check_stats(
    tcp_conns => 3,
    tcp_close_c => 2,
    tcp_close_s_err => 1,
    tcp_reqs => 4,
    noerror => 3,
    dropped => 1,
    edns => 4,
    tcp_dso_estab => 3,
    tcp_dso_typeni => 0,
    tcp_dso_protoerr => 1,
)};
ok(!$@) or diag $@;

### These next several send a single DSO message on a fresh conn, but it has
### DSO protoerr-level issues and the conn is dropped with no response:

# T13
# QID Zero with an unknown TLV type (doesn't matter) - unidirectionals not allowed from clients!
{
    my $tcp_sock = make_tcp_sock();
    my $qid_zero = wrap_tcp_prefix(pack('nCCnnnn nnNN',
        0, 48, 0, 0, 0, 0, 0, 0xFBFF, 8, 1234, 5678
    ));
    send($tcp_sock, $qid_zero, 0);
}
eval {_GDT->check_stats(
    tcp_conns => 4,
    tcp_close_c => 2,
    tcp_close_s_err => 2,
    tcp_reqs => 4,
    noerror => 3,
    dropped => 1,
    edns => 4,
    tcp_dso_estab => 3,
    tcp_dso_typeni => 0,
    tcp_dso_protoerr => 2,
)};
ok(!$@) or diag $@;

# T14
# DSO without enough data in packet for a basic primary TLV
{
    my $tcp_sock = make_tcp_sock();
    my $dso_short = wrap_tcp_prefix(pack('nCCnnnn n',
        $ID++, 48, 0, 0, 0, 0, 0, 0xFBFF # missing at least 16-bit tlv len field
    ));
    send($tcp_sock, $dso_short, 0);
}
eval {_GDT->check_stats(
    tcp_conns => 5,
    tcp_close_c => 2,
    tcp_close_s_err => 3,
    tcp_reqs => 4,
    noerror => 3,
    dropped => 1,
    edns => 4,
    tcp_dso_estab => 3,
    tcp_dso_typeni => 0,
    tcp_dso_protoerr => 3,
)};
ok(!$@) or diag $@;

# T15
# DSO Req from client with RetryDelay=0 as primary TLV
{
    my $tcp_sock = make_tcp_sock();
    my $pri_rd = wrap_tcp_prefix(pack('nCCnnnn nnn',
        $ID++, 48, 0, 0, 0, 0, 0, 2, 2, 0
    ));
    send($tcp_sock, $pri_rd, 0);
}
eval {_GDT->check_stats(
    tcp_conns => 6,
    tcp_close_c => 2,
    tcp_close_s_err => 4,
    tcp_reqs => 4,
    noerror => 3,
    dropped => 1,
    edns => 4,
    tcp_dso_estab => 3,
    tcp_dso_typeni => 0,
    tcp_dso_protoerr => 4,
)};
ok(!$@) or diag $@;

# T16
# DSO Req from client with Padding as primary TLV
{
    my $tcp_sock = make_tcp_sock();
    my $pri_pad = wrap_tcp_prefix(pack('nCCnnnn nna*',
        $ID++, 48, 0, 0, 0, 0, 0, 3, 7, 'abcdefg'
    ));
    send($tcp_sock, $pri_pad, 0);
}
eval {_GDT->check_stats(
    tcp_conns => 7,
    tcp_close_c => 2,
    tcp_close_s_err => 5,
    tcp_reqs => 4,
    noerror => 3,
    dropped => 1,
    edns => 4,
    tcp_dso_estab => 3,
    tcp_dso_typeni => 0,
    tcp_dso_protoerr => 5,
)};
ok(!$@) or diag $@;

# T17
# DSO Req with legit KA followed by an additional TLV with length issues (runs off end of packet)
{
    my $tcp_sock = make_tcp_sock();
    my $pri_pad = wrap_tcp_prefix(pack('nCCnnnn nnNNnnn',
        $ID++, 48, 0, 0, 0, 0, 0, 1, 8, 123, 456, 3, 3, 2 # final padding ATLV says 3 bytes data, but only 2 present
    ));
    send($tcp_sock, $pri_pad, 0);
}
eval {_GDT->check_stats(
    tcp_conns => 8,
    tcp_close_c => 2,
    tcp_close_s_err => 6,
    tcp_reqs => 4,
    noerror => 3,
    dropped => 1,
    edns => 4,
    tcp_dso_estab => 3,
    tcp_dso_typeni => 0,
    tcp_dso_protoerr => 6,
)};
ok(!$@) or diag $@;

# T18
# DSO Req Keepalive with length other than 8 (but does have bytes indicated)
{
    my $tcp_sock = make_tcp_sock();
    my $pri_pad = wrap_tcp_prefix(pack('nCCnnnn nnNNn',
        $ID++, 48, 0, 0, 0, 0, 0, 1, 10, 123, 456, 789
    ));
    send($tcp_sock, $pri_pad, 0);
}
eval {_GDT->check_stats(
    tcp_conns => 9,
    tcp_close_c => 2,
    tcp_close_s_err => 7,
    tcp_reqs => 4,
    noerror => 3,
    dropped => 1,
    edns => 4,
    tcp_dso_estab => 3,
    tcp_dso_typeni => 0,
    tcp_dso_protoerr => 7,
)};
ok(!$@) or diag $@;

# T19-21
# DSOTYPENI followed by DSO establishment with KA and a query
{
    my $tcp_sock = make_tcp_sock();
    my $q_ni = wrap_tcp_prefix(pack('nCCnnnn nnNN',
        $ID, 48, 0, 0, 0, 0, 0, 0xFBFF, 8, 1234, 5678
    ));
    send($tcp_sock, $q_ni, 0);
    my $recvbuf = recv_tcp($tcp_sock);
    my $e_ni = wrap_tcp_prefix(pack('nCCnnnn',
        $ID, 176, 11, 0, 0, 0, 0, # rcode=11 is DSOTYPENI
    ));
    $ID++;
    ok($recvbuf eq $e_ni);
    ok(test_dso_ka($tcp_sock));
    ok(test_ns1_query($tcp_sock, 1, $basic_optrr, $basic_optrr));
}

# T22
eval {_GDT->check_stats(
    tcp_conns => 10,
    tcp_close_c => 3,
    tcp_close_s_err => 7,
    tcp_reqs => 5,
    noerror => 4,
    dropped => 1,
    edns => 5,
    tcp_dso_estab => 4,
    tcp_dso_typeni => 1,
    tcp_dso_protoerr => 7,
)};
ok(!$@) or diag $@;

# T23-24
# DSO-over-UDP is illegal, gdnsd choses to send FORMERR in this case
# While we're here, also send EDNS KA over UDP, since it covers a related
# branch in dnspacket
{
    my $udp_sock = make_udp_sock();
    my $legit_ka = pack('nCCnnnn nnNN',
        $ID, 48, 0, 0, 0, 0, 0, 1, 8, 123, 456
    );
    send($udp_sock, $legit_ka, 0);
    my $recvbuf;
    recv($udp_sock, $recvbuf, 4096, 0);
    my $expect_formerr = pack('nCCnnnn',
        $ID, 176, 1, 0, 0, 0, 0 # rcode 1 is FORMERR
    );
    $ID++;
    ok($expect_formerr eq $recvbuf);
    ok(test_ns1_query($udp_sock, 0, $rfc7828_optrr, $basic_optrr));
}
# T25
eval {_GDT->check_stats(
    tcp_conns => 10,
    tcp_close_c => 3,
    tcp_close_s_err => 7,
    tcp_reqs => 5,
    udp_reqs => 2,
    noerror => 5,
    dropped => 1,
    edns => 6,
    formerr => 1,
    tcp_dso_estab => 4,
    tcp_dso_typeni => 1,
    tcp_dso_protoerr => 7,
)};
ok(!$@) or diag $@;

# T26
# DSO opcode with non-zero RR counts, over TCP, -> FORMERR
{
    my $tcp_sock = make_tcp_sock();
    my $dso_question = wrap_tcp_prefix(pack('nCCnnnn a*nn',
        $ID, 48, 0, 1, 0, 0, 0, "\x03zzz\x00", 1, 1 # Query-style question
    ));
    send($tcp_sock, $dso_question, 0);
    my $recvbuf = recv_tcp($tcp_sock);
    my $expect_formerr = wrap_tcp_prefix(pack('nCCnnnn',
        $ID, 176, 1, 0, 0, 0, 0 # rcode 1 is FORMERR
    ));
    $ID++;
    ok($expect_formerr eq $recvbuf);
}
# T27
eval {_GDT->check_stats(
    tcp_conns => 11,
    tcp_close_c => 4,
    tcp_close_s_err => 7,
    tcp_reqs => 6,
    udp_reqs => 2,
    noerror => 5,
    dropped => 1,
    edns => 6,
    formerr => 2,
    tcp_dso_estab => 4,
    tcp_dso_typeni => 1,
    tcp_dso_protoerr => 7,
)};
ok(!$@) or diag $@;

{ # T28-30
    # DSO KA, then DSOTYPENI, then a req, then a protocol error, all on a
    # padded connection, sending padding with the KA and checking for gdnsd's
    # pad to 468 on all responses.  Protoerr on a padded conn is another tricky
    # branch-cover case.
    my $tcp_sock = make_tcp_sock(1);
    ok(test_dso_ka($tcp_sock, 1, 1));

    my $q_ni = wrap_tcp_prefix(pack('nCCnnnn nnNN',
        $ID, 48, 0, 0, 0, 0, 0, 0xFBFF, 8, 1234, 5678
    ));
    send($tcp_sock, $q_ni, 0);
    my $recvbuf = recv_tcp($tcp_sock);
    my $e_ni = wrap_tcp_prefix(pack('nCCnnnn nna*',
        $ID, 176, 11, 0, 0, 0, 0, 3, 452, ("\x00" x 452)
    ));
    ok($e_ni eq $recvbuf);

    ok(test_ns1_query($tcp_sock, 1, $basic_optrr, $padded_optrr));

    # Send a RetryDelay request, which is illegal and the server aborts
    my $q_err = wrap_tcp_prefix(pack('nCCnnnn nnN',
        $ID, 48, 0, 0, 0, 0, 0, 2, 4, 1234
    ));
    send($tcp_sock, $q_err, 0);
    # Just to ensure the server RSTs before we close:
    my $x;
    recv($tcp_sock, $x, 4096, 0);
}
# T31
eval {_GDT->check_stats(
    tcp_conns => 12,
    tcp_close_c => 4,
    tcp_close_s_err => 8,
    tcp_reqs => 7,
    udp_reqs => 2,
    noerror => 6,
    dropped => 1,
    edns => 7,
    formerr => 2,
    tcp_dso_estab => 5,
    tcp_dso_typeni => 2,
    tcp_dso_protoerr => 8,
)};
ok(!$@) or diag $@;

#####
# Note all test numbers from here to the end are imprecise, as there's no
# gauranteeing the ordering of some of them with parallel threads.
#####

##############################################
# T32-35
# Use Perl interpreter threads to background a TCP DSO client that will look
# for the unidirectional KeepAlive=0 on daemon shutdown and validate it before
# closing immediately.

my $client_close_ka = async {
    my $tcp_sock = make_tcp_sock();
    ok(test_dso_ka($tcp_sock));
    ok(test_ns1_query($tcp_sock, 1, $basic_optrr, $basic_optrr));
    # waits here for KA inact=0 unidirectional on shutdown below
    my $recvbuf = recv_tcp($tcp_sock);
    my $e_ka = wrap_tcp_prefix(pack('nCCnnnn nnNN',
        0, 48, 0, 0, 0, 0, 0, 1, 8, 0xFFFFFFFF, 0 # KA unidirectional with inact=0
    ));
    ok($recvbuf eq $e_ka);
};
# This will stall until the thread above reaches its waiting point (after it
# has established DSO and sent its normal edns query, and is waiting with an
# open connection to receive the unidirectional KA with inact=0)
eval {_GDT->check_stats(
    tcp_conns => 13,
    tcp_close_c => 4,
    tcp_close_s_err => 8,
    tcp_reqs => 8,
    udp_reqs => 2,
    noerror => 7,
    dropped => 1,
    edns => 8,
    formerr => 2,
    tcp_dso_estab => 6,
    tcp_dso_typeni => 2,
    tcp_dso_protoerr => 8,
)};
ok(!$@) or diag $@;

#### END T32-35 threaded test ####

$ID += 10; # to avoid $ID clash between the threads

##############################################
# T36-41
# As above, but trickier.  This thread will establish DSO, make a normal query,
# wait for shutdown to send KA w/ inact=0, then send another "pending" query
# expecting a normal response, then wait around for the RetryDelay packet and
# confirm its contents before disconnecting.  This will incur a full 5 second
# stall on server shutdown, so we'll make it conditional on $SLOW_TESTS.  This
# one also uses the padded connection, so tests all of our DSO output packets
# (responses and unidrectionals) in padded form as well.

my $client_close_rd;
SKIP: {
    skip "Not running slow tests", 6 unless $ENV{'SLOW_TESTS'};

$client_close_rd = async {
    my $tcp_sock = make_tcp_sock(1);
    ok(test_dso_ka($tcp_sock, 1, 1));
    ok(test_ns1_query($tcp_sock, 1, $basic_optrr, $padded_optrr));
    # waits here for KA inact=0 unidirectional on shutdown below
    my $recvbuf = recv_tcp($tcp_sock);
    # KA unidirectional with inact=0 + pad to 468
    my $e_ka = wrap_tcp_prefix(pack('nCCnnnn nnNN nna*',
        0, 48, 0, 0, 0, 0, 0, 1, 8, 0xFFFFFFFF, 0, 3, 440, ("\x00" x 440)
    ));
    ok($recvbuf eq $e_ka);
    # Send another query during the 5s grace time
    ok(test_ns1_query($tcp_sock, 1, $basic_optrr, $padded_optrr));
    # Wait for unidirectional RD=0
    my $recvbuf2 = recv_tcp($tcp_sock);
    # RD unidirectional with delay=0 + pad to 468
    my $e_rd = wrap_tcp_prefix(pack('nCCnnnn nnN nna*',
        0, 48, 0, 0, 0, 0, 0, 2, 4, 0, 3, 444, ("\x00" x 444)
    ));
    ok($recvbuf2 eq $e_rd);
};
# This will stall until the thread above reaches its waiting point (after it
# has established DSO and sent its normal edns query, and is waiting with an
# open connection to receive the unidirectional KA with inact=0)
eval {_GDT->check_stats(
    tcp_conns => 14,
    tcp_close_c => 4,
    tcp_close_s_err => 8,
    tcp_reqs => 9,
    udp_reqs => 2,
    noerror => 8,
    dropped => 1,
    edns => 9,
    formerr => 2,
    tcp_dso_estab => 7,
    tcp_dso_typeni => 2,
    tcp_dso_protoerr => 8,
)};
ok(!$@) or diag $@;

} # end SLOW_TESTS SKIP-block

#### END T36-41 threaded test ####

# T42
_GDT->test_kill_daemon($pid);

# Join up client thread(s) executed above
$client_close_ka->join();
if ($ENV{'SLOW_TESTS'}) {
    $client_close_rd->join();
}
