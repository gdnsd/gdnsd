# The primary purpose of this test is to exercise a bunch of the TCP logic and
# per-thread/connection state tracking to ensure we do not have stupid bugs or
# invalid asserts lurking, which should cause daemon aborts and/or trip
# sanitizer/QA tools during this test run.  So in that sense, this test is
# less about its own results validation and more about exercising code.
#
# The server config is minimized to make overwhelming it easier: a single
# thread configured to max out at 16-client parallelism.  We want to fire up a
# large-ish number of connections relative to that value with varying
# behaviors.  Some of them will make a legitimate request, and others will
# "misbehave" in various ways design to trip some edge cases.
#
# Because we have no control over the order these connections land or their
# timing, some of the results are unpredictable.  What should be predictable,
# though, is that the total count of received connections is right, the total
# count of legitimate requests with no error comes out right, and that the sum
# of all the various connection closing states also adds up correctly.
#
# The successful requests of the client connections that act legitimately can
# only be guaranteed (under these connection-limited conditions where the
# server is having to kill off connections to stay within limits) on Linux, or
# on BSDs which have SO_ACCEPTFILTER (most of them) and have accf_dns and/or
# accf_dataready kernel modules loaded.  Because of this, we skip the check on
# the exact count of "tcp_reqs" and "noerror" stats if initial daemon log
# output indicates SO_ACCEPTFILTER setup failure.

use _GDT ();
use Net::DNS;
use POSIX qw();
use Time::HiRes qw(usleep);
use Test::More tests => 4;

# How many client processes to spawn in parallel, each of which makes one
# connection and does one simple request or error behavior.  Since there are 10
# behaviors below, if we keep this to a multiple of 10 it makes our math much
# easier.
my $NUM_TCP = 300;

# Legitimate query for ns1.example.com A-record
my $tcp_query_ns1 = do {
    my $req = pack("nCCnnnna*nn",
        $_id++,
        0, # flags1
        0, # flags2
        1, # qdcount
        0, # $ancount
        0, # $nscount
        0, # $arcount
        "\x03ns1\x07example\x03com\x00", # qname
        1, # $qtype
        1, # $qclass
    );
    pack("n", length($req)) . $req;
};

# random sleep in the range of [x-y) ms using usleep
sub sleep_rand_ms {
    my ($min, $max) = @_;
    $min *= 1000; # convert to us
    $max *= 1000; # convert to us
    usleep($min + int(rand($max - $min)));
}

my $pid = _GDT->test_spawn_daemon();

# Basic client behavioral patterns, taking a client TCP socket as input.
# Currently there are 10 behaviors defined, and 5 of them are expected to log
# as successful "noerror" requests regardless of all the overload and
# connection killing going on.  So we expect the "tcp_reqs" and "noerror" stats
# to end up at $NUM_TCP / 2.
my @behave = (
    # 0 - legit request done quickly
    sub {
        my $sock = shift;
        my $rbuf;
        send($sock, $tcp_query_ns1, 0);
        recv($sock, $rbuf, 4096, 0);
    },
    # 1 - just sleeps for a while and never sends anything then closes
    sub {
        sleep_rand_ms(101, 1740);
    },
    # 2 - sends 1 byte and sleeps a little
    sub {
        my $sock = shift;
        send($sock, 'X', 0);
        sleep_rand_ms(37, 150);
    },
    # 3 - sends a legit-looking 2-byte len and sleeps a little
    sub {
        my $sock = shift;
        send($sock, "\x00\x40", 0); # Indicates 64 byte req to follow
        sleep_rand_ms(71, 141);
    },
    # 4 - sends a legit-looking 2-byte len and partial data and sleeps a little
    sub {
        my $sock = shift;
        # Indicates 48 byte req to follow, but only sends 16
        send($sock, "\x00\x30ABCDEF0123456789", 0);
        sleep_rand_ms(63, 123);
    },
    # 5 - legit request with small delays before recv and close.
    sub {
        my $sock = shift;
        my $rbuf;
        send($sock, $tcp_query_ns1, 0);
        sleep_rand_ms(33, 66);
        recv($sock, $rbuf, 4096, 0);
        sleep_rand_ms(33, 66);
    },
    # 6 - sends a way-oversized 2 byte len + partial data.  As soon as the
    # oversized len is seen, dnsio layer is going to dump the connection on the
    # floor without consulting dnspacket.
    sub {
        my $sock = shift;
        # Indicates 32000 byte req to follow, but only sends 10 bytes
        send($sock, "\x7D\x000123456789", 0);
        my $rbuf;
        recv($sock, $rbuf, 4096, 0); # will fail, server sends nothing and resets
    },
    # 7 - legit req, but delays before sending the req.
    sub {
        my $sock = shift;
        my $rbuf;
        sleep_rand_ms(33, 123);
        send($sock, $tcp_query_ns1, 0);
        recv($sock, $rbuf, 4096, 0);
    },
    # 8 - does a single fast legit transaction like case 0, but if SLOW_TESTS
    # is set, it will do a second recv() which will block for the socket's
    # Timeout value, which is set long enough that the server can call us
    # delinquent and close us for timeout (in the guaranteed cases near the end
    # of the run that we're not killed as the most-idle client).  Later during
    # the daemon shutdown SLOW_TESTS phase, clients of this type will exit
    # almost immediately after the initial 5 second grace window, because
    # they'll exit/close on the client side as soon as the server sends us a
    # SHUT_WR-generated FIN which causes the second recv() to return.
    sub {
        my $sock = shift;
        send($sock, $tcp_query_ns1, 0);
        recv($sock, $rbuf, 4096, 0);
        if ($ENV{'SLOW_TESTS'}) {
            recv($sock, $rbuf, 4096, 0); # blocks here for Timeout, unless server closes or RSTs
        }
    },
    # 9 - Very similar in purpose to the above, but does an explicit usleep for
    # longer than the server-side timeout rather than the recv() blockage
    # above.  This will turn out pretty similar to 8 during the main run, but
    # during the daemon shutdown testing these will have to be killed by the
    # server after both grace windows (10s) have passed, since we ignore the
    # FIN at the 5 second mark in the middle.
    sub {
        my $sock = shift;
        send($sock, $tcp_query_ns1, 0);
        recv($sock, $rbuf, 4096, 0);
        if ($ENV{'SLOW_TESTS'}) {
            sleep_rand_ms(10100, 11000);
        }
    },
);

# client workers run one of the behaviors above (their client number modulo the
# count of behaviors, so basically cycling through the behavior list above as
# we spawn them.)
sub client_worker {
    my $client_num = shift;
    my $sock = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1:' . $_GDT::DNS_PORT,
        Proto => 'tcp',
        Timeout => 30,
    );
    $behave[$client_num % scalar @behave]->($sock);
    POSIX::_exit(0); # Very important, regular exit will screw up testsuite stuff
}

# Fork a bunch of client_worker processes
foreach my $i (1..$NUM_TCP) {
    my $cpid = fork();
    if (!defined $cpid) { die "fork() failed: $!"; }
    if (!$cpid) { client_worker($i); } # child
}

my $expect_noerr = $NUM_TCP / 2;

# On BSDs, runtime availability of accept filters affects test results/reliability here:
my $noerr_checks_valid = 1;

if ($^O =~ m/bsd/i) {
    # If the dnsready accept filter is working, half the connections will never
    # arrive at gdnsd because they're blocked at the accept filter level, so
    # halve the count for stats checks below:
    if (!$_GDT::ACCF_DNS_FAIL) {
        $NUM_TCP = $NUM_TCP / 2;
    }
    # If both filters (dnsready and dataready) failed to load, the noerror
    # check won't be valid, as under these conditions the code can't guarantee
    # that clients aren't killed before their first request arrives under
    # connection overload pressure.
    if ($_GDT::ACCF_DNS_FAIL && $_GDT::ACCF_DATA_FAIL) {
        $noerr_checks_valid = 0;
    }
}

# Check stats at the end.  This mechanism will keep polling the stats output
# for a while if the values are too low, and will eventually timeout if they
# stay too low, or fail quickly if they go higher than they should be.
my $raw = eval {_GDT->check_stats(
    tcp_conns => $NUM_TCP,
    _code => sub {
        my $stats = shift;
        my $close_sum = $stats->{'tcp_close_c'}
                      + $stats->{'tcp_close_s_ok'}
                      + $stats->{'tcp_close_s_err'}
                      + $stats->{'tcp_close_s_kill'};
        if ($close_sum != $NUM_TCP) {
            my $ftype = ($close_sum < $NUM_TCP) ? 'soft' : 'hard';
            die "Close-sum mismatch (${ftype}-fail), wanted " . $NUM_TCP . ", got " . $close_sum;
        }
        if ($noerr_checks_valid && $stats->{'tcp_reqs'} != $expect_noerr || $stats->{'noerror'} != $expect_noerr) {
            die "reqs/noerror mismatch (hard-fail), wanted " . $expect_noerr . ", got " . $stats->{'tcp_reqs'} . " / " . $stats->{'noerror'};
        }
    },
)};
ok(!$@) or diag $@;

# Remove zero values from the raw stats
for (keys %$raw) { delete $raw->{$_} if !$raw->{$_} }
use Data::Dumper;
$Data::Dumper::Sortkeys = 1;
diag "Non-zero stats after " . $NUM_TCP . " connections: " . Dumper($raw);

# In the SLOW_TESTS case, fire up two child processes using behaviors 8 and 9
# above just before requesting daemon stop.  Behavior 8 will end via
# client-side close 5 seconds later when the server sends its SHUT_WR-generated
# FIN after the initial grace period, whereas behavior 9 the server will have
# to RST after the full 10 seconds as unresponsive and delinquent.
SKIP: {
    skip "Not running slow tests", 1 unless $ENV{'SLOW_TESTS'};

    foreach my $i (0, 1) {
        my $cpid = fork();
        if (!defined $cpid) { die "fork() failed: $!"; }
        if ($cpid) { push(@cpids, $cpid); } # parent
        else { client_worker(8 + $i); }
    }

    # Wait for clients above to connect before telling server to stop accept()ing
    eval {_GDT->check_stats(
        tcp_conns => $NUM_TCP + 2
    )};
    ok(!$@) or diag $@;
}

# Here we'll see the ~10s delay during shutdown waiting on the above if
# $SLOW_TESTS is set, and hopefully still a zero exit code regardless!
_GDT->test_kill_daemon($pid);
