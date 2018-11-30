# Random packet torture testing.
# All of these queries should result in "dropped", "fmterr", etc...
# They are sent directly via UDP rather than Net::DNS, so specific error counts
# aren't reliable.  We just check at the end that the overall packet count in
# the daemon stats is correct, and that the "valid" counts (noerror) only
# account for the handful of valid requests we make to ensure the daemon is
# still alive and well.

use _GDT ();
use Scalar::Util ();
use Test::More tests => 4 + $_GDT::RAND_LOOPS;

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
    return pack("nCCnnnn",
        12345, # id
        0, # flags1
        0, # flags2
        1, # qdcount
        0, # ancount
        0, # nscount
        0  # arcount
    );
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

    $rand_reqs += 72;

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
)};
ok(!$@) or diag $@;

_GDT->test_kill_daemon($pid);

# Save random seed to test output directory if any tests failed.
#   (we also diag the seed on every run, but with the new parallel
#   testing method it does not get displayed during a normal run)
# We cannot use is_passing() here because we need to be
#   compatible back to the 5.10.1 versions of these modules
my $failed;
map { $failed++ unless $_ } Test::More->builder->summary();
if($failed) {
    my $rsfile = "${_GDT::OUTDIR}/FAILED_RANDOM_SEED.$$";
    diag "There were failing tests; saving random seed $rseed to $rsfile";
    open(my $rsfh, ">$rsfile")
        or die "Cannot open $rsfile for writing: $!";
    print $rsfh "$rseed\n";
    close($rsfh);
}
