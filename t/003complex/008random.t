
# Random packet torture testing.
# All of these queries should result
# in "dropped", "fmterr", etc...
# They are sent directly via UDP rather than Net::DNS,
# so specific error counts aren't reliable.  We just check
# at the end that the overall packet count in the daemon
# stats is correct, and that the "valid" counts (noerror,
# nxdomain, refused) only account for the handful of
# valid requests we make to ensure the daemon is still alive
# and well.

use _GDT ();
use FindBin ();
use File::Spec ();
use Scalar::Util ();
use Test::More tests => 4 + ($_GDT::RAND_LOOPS * 5);

# Initialize the random seed and diag() it, so that
#  failures can be reproduced and sorted out
my $rseed;
if(defined $ENV{GDNSD_TEST_RSEED}) {
    my $env_rseed = $ENV{GDNSD_TEST_RSEED};
    if(Scalar::Util::looks_like_number($env_rseed)) {
        $rseed = abs(int($env_rseed));
        die "Your GDNSD_TEST_RSEED is not a positive integer"
            unless $env_rseed == $rseed;
    }
    else {
        die "Your GDNSD_TEST_RSEED is not a number"
    }
}
else {
    $rseed = int(rand(2 ** 31));
}
diag "Random seed is '$rseed'";

sub gen_random_packet {
    my $size = shift || 1 + int(rand(512));

    my $data = '';
    for (1..$size) {
       $data .= chr(int(rand(256)));
    }

    return $data;
}

sub gen_valid_header {
    my $req_packet = Net::DNS::Packet->new('foo.example.com', 'A');
    return $req_packet->header->encode;
}

sub gen_random_packet_good_header {
    my $size = shift;
    die "size must be <= 500" if defined $size && $size > 500;
    $size = (1 + int(rand(500))) unless defined $size;
    return gen_valid_header() if !$size;
    return gen_valid_header() . gen_random_packet($size);
}

sub get_socket {
    IO::Socket::INET->new(
        PeerAddr => '127.0.0.1:' . $_GDT::DNS_PORT,
        Proto => 'udp',
        Timeout => 2,
    );
}

srand($rseed);

my $pid = _GDT->test_spawn_daemon();
eval {_GDT->check_stats( udp_reqs => 0 )}; ok(!$@) or diag $@;

my $rand_reqs = 0;
my $valid_reqs = 0;

foreach (1..$_GDT::RAND_LOOPS) {
    my $sock = get_socket();
    send($sock, gen_random_packet(1), 0);
    send($sock, gen_random_packet(2), 0);
    send($sock, gen_random_packet(3), 0);
    send($sock, gen_random_packet(4), 0);
    send($sock, gen_random_packet(5), 0);
    send($sock, gen_random_packet(6), 0);
    send($sock, gen_random_packet(7), 0);
    send($sock, gen_random_packet(8), 0);
    send($sock, gen_random_packet(9), 0);
    send($sock, gen_random_packet(10), 0);
    send($sock, gen_random_packet(11), 0);
    send($sock, gen_random_packet(12), 0);
    send($sock, gen_random_packet(13), 0);
    send($sock, gen_random_packet(14), 0);
    send($sock, gen_random_packet(15), 0);

    $rand_reqs += 15;

    eval {_GDT->check_stats(
        udp_reqs => $rand_reqs + $valid_reqs,
        noerror => $valid_reqs,
        nxdomain => 0,
        refused => 0,
    )};
    ok(!$@) or diag $@;

    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);

    $rand_reqs += 20;

    eval {_GDT->check_stats(
        udp_reqs => $rand_reqs + $valid_reqs,
        noerror => $valid_reqs,
        nxdomain => 0,
        refused => 0,
    )};
    ok(!$@) or diag $@;

    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(), 0);
    send($sock, gen_random_packet(511), 0);
    send($sock, gen_random_packet(512), 0);
    send($sock, gen_random_packet(513), 0);
    send($sock, gen_random_packet_good_header(0), 0);
    send($sock, gen_random_packet_good_header(1), 0);
    send($sock, gen_random_packet_good_header(2), 0);
    send($sock, gen_random_packet_good_header(3), 0);
    send($sock, gen_random_packet_good_header(4), 0);
    send($sock, gen_random_packet_good_header(5), 0);
    send($sock, gen_random_packet_good_header(6), 0);
    send($sock, gen_random_packet_good_header(7), 0);
    send($sock, gen_random_packet_good_header(8), 0);
    send($sock, gen_random_packet_good_header(9), 0);
    send($sock, gen_random_packet_good_header(10), 0);
    send($sock, gen_random_packet_good_header(11), 0);
    send($sock, gen_random_packet_good_header(), 0);

    $rand_reqs += 20;

    eval {_GDT->check_stats(
        udp_reqs => $rand_reqs + $valid_reqs,
        noerror => $valid_reqs,
        nxdomain => 0,
        refused => 0,
    )};
    ok(!$@) or diag $@;

    send($sock, gen_random_packet_good_header(), 0);
    send($sock, gen_random_packet_good_header(), 0);
    send($sock, gen_random_packet_good_header(), 0);
    send($sock, gen_random_packet_good_header(), 0);
    send($sock, gen_random_packet_good_header(), 0);
    send($sock, gen_random_packet_good_header(), 0);
    send($sock, gen_random_packet_good_header(), 0);
    send($sock, gen_random_packet_good_header(), 0);
    send($sock, gen_random_packet_good_header(), 0);
    send($sock, gen_random_packet_good_header(), 0);
    send($sock, gen_random_packet_good_header(), 0);
    send($sock, gen_random_packet_good_header(), 0);
    send($sock, gen_random_packet_good_header(), 0);
    send($sock, gen_random_packet_good_header(), 0);
    send($sock, gen_random_packet_good_header(), 0);
    send($sock, gen_random_packet_good_header(), 0);
    send($sock, gen_random_packet_good_header(), 0);
    close($sock);

    $rand_reqs += 17;

    eval {_GDT->check_stats(
        udp_reqs => $rand_reqs + $valid_reqs,
        noerror => $valid_reqs,
        nxdomain => 0,
        refused => 0,
    )};
    ok(!$@) or diag $@;

    eval {_GDT->query_server(
        undef,
        Net::DNS::Packet->new('foo.example.com', 'A'),
        _GDT->mkanswer({ },
            Net::DNS::Question->new('foo.example.com', 'A'),
            [Net::DNS::rr_add('foo.example.com 21600 A 192.0.2.160')], [], [],
        ),
        _GDT->get_resolver(), {},
    )};
    ok(!$@) or diag $@;

    $valid_reqs += 1;

}

eval {_GDT->check_stats(
    udp_reqs => $rand_reqs + $valid_reqs,
    noerror => $valid_reqs,
    nxdomain => 0,
    refused => 0,
)};
ok(!$@) or diag $@;

_GDT->test_kill_daemon($pid);
