use _GDT ();
use Net::DNS;
use Socket qw/AF_INET/;
use Socket6 qw/AF_INET6 inet_pton/;
use IO::Socket::INET6 qw//;
use Test::More tests => 2 + (2 * 10);

sub _mk_optrr_cookie {
    my $data = shift;
    my $optrr_cookie = Net::DNS::RR->new(
        type => "OPT",
        version => 0,
        name => "",
        size => 1024,
        rcode => 0,
        flags => 0,
    );
    if (defined $data) {
        $optrr_cookie->option(COOKIE => $data);
    }
    return $optrr_cookie;
}

sub hexstr { return pack('H*', shift); }

# Note "test_dns" has cookie hacks because they're hard to test otherwise.
# 1) When comparing cookie data from OPT RR in "addtl", it first wipes down all
#    bytes after the first 8 (client cookie) to zero, so that they compare
#    against all-zeros successfully for the basic packet comparison.  The total
#    byte length must still match and the first 8 bytes must match.
# 2) The actual full value (all data from server cookie option response) is
#    retrievable via _GDT->get_last_server_cookie(), for higher-level
#    use in the test script.
#
# Also, keep in mind that ipv4 vs ipv6 is a major factor here: 'test_dns'
# normally tests both sequentially, and cookie hashes include client IPs in
# their inputs, therefore all useful cookie tests that check/reuse data will
# have to stick to a single protocol via the "v4_only" or "v6_only" arguments.
# The loop below iterates the same set of stateful tests twice, once for each
# protocol.

my $pid = _GDT->test_spawn_daemon();

foreach my $proto (qw/v4_only v6_only/) {
    # client cookie only in request, gets us a valid server cookie and hits _init stat
    _GDT->test_dns(
        $proto => 1,
        qname => 'ns1.example.com',
        q_optrr => _mk_optrr_cookie(hexstr('0123456789ABCDEF')),
        answer => 'ns1.example.com 86400 A 192.0.2.42',
        addtl => _mk_optrr_cookie(hexstr('0123456789ABCDEF0000000000000000')),
        stats => [qw/udp_reqs noerror edns edns_cookie_init/],
    );

    # save the server cookie given to us above
    my $save_good = _GDT->get_last_server_cookie();

    # reuse the good cookie, should get _ok stat
    _GDT->test_dns(
        $proto => 1,
        qname => 'ns1.example.com',
        q_optrr => _mk_optrr_cookie($save_good),
        answer => 'ns1.example.com 86400 A 192.0.2.42',
        addtl => _mk_optrr_cookie(hexstr('0123456789ABCDEF0000000000000000')),
        stats => [qw/udp_reqs noerror edns edns_cookie_ok/],
    );

    # set an arbitrary bad server cookie and check for the _bad stat
    _GDT->test_dns(
        $proto => 1,
        qname => 'ns1.example.com',
        q_optrr => _mk_optrr_cookie(hexstr('0123456789ABCDEF0123456789ABCDEF')),
        answer => 'ns1.example.com 86400 A 192.0.2.42',
        addtl => _mk_optrr_cookie(hexstr('0123456789ABCDEF0000000000000000')),
        stats => [qw/udp_reqs noerror edns edns_cookie_bad/],
    );

    # We should've gotten another good cookie output (maybe same as before, maybe
    # not, if testsuite races an hour mark)
    my $save_from_bad = _GDT->get_last_server_cookie();

    # The one saved above should work!
    _GDT->test_dns(
        $proto => 1,
        qname => 'ns1.example.com',
        q_optrr => _mk_optrr_cookie($save_from_bad),
        answer => 'ns1.example.com 86400 A 192.0.2.42',
        addtl => _mk_optrr_cookie(hexstr('0123456789ABCDEF0000000000000000')),
        stats => [qw/udp_reqs noerror edns edns_cookie_ok/],
    );

    # one byte short of a valid server cookie input, RFC-illegal
    _GDT->test_dns(
        $proto => 1,
        qname => 'ns1.example.com',
        q_optrr => _mk_optrr_cookie(hexstr('0123456789ABCDEF0123456789ABCD')),
        header => { aa => 0, rcode => 'FORMERR' },
        addtl => _mk_optrr_cookie(undef),
        stats => [qw/udp_reqs formerr edns edns_cookie_formerr/],
    );

    # one byte short of a valid client cookie input, RFC-illegal
    _GDT->test_dns(
        $proto => 1,
        qname => 'ns1.example.com',
        q_optrr => _mk_optrr_cookie(hexstr('0123456789ABCD')),
        header => { aa => 0, rcode => 'FORMERR' },
        addtl => _mk_optrr_cookie(undef),
        stats => [qw/udp_reqs formerr edns edns_cookie_formerr/],
    );

    # one byte over the maximum server cookie len, RFC-illegal
    _GDT->test_dns(
        $proto => 1,
        qname => 'ns1.example.com',
        q_optrr => _mk_optrr_cookie(hexstr('0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEFFF')),
        header => { aa => 0, rcode => 'FORMERR' },
        addtl => _mk_optrr_cookie(undef),
        stats => [qw/udp_reqs formerr edns edns_cookie_formerr/],
    );

    # recheck the original saved good cookie again
    _GDT->test_dns(
        $proto => 1,
        qname => 'ns1.example.com',
        q_optrr => _mk_optrr_cookie($save_good),
        answer => 'ns1.example.com 86400 A 192.0.2.42',
        addtl => _mk_optrr_cookie(hexstr('0123456789ABCDEF0000000000000000')),
        stats => [qw/udp_reqs noerror edns edns_cookie_ok/],
    );

    # The Cookie RFC also makes it legal to check cookies with QDCOUNT==0
    _GDT->test_dns(
        $proto => 1,
        qpacket => Net::DNS::Packet->new(), # no questions!
        noresq => 1,
        header => { aa => 0 },
        q_optrr => _mk_optrr_cookie($save_good),
        addtl => _mk_optrr_cookie(hexstr('0123456789ABCDEF0000000000000000')),
        stats => [qw/udp_reqs noerror edns edns_cookie_ok/],
    );

    # This is a good place to try combining several EDNS options in one query
    # Do it over TCP so we can do keepalive option response as well

    my $all_the_opts_query = _mk_optrr_cookie(hexstr('0123456789ABCDEF'));
    $all_the_opts_query->option(NSID => '');
    $all_the_opts_query->option(11 => '');
    $all_the_opts_query->option('CLIENT-SUBNET' => pack('nCCa16', 2, 128, 0, inet_pton(AF_INET6, "::")));

    my $all_the_opts_response = _mk_optrr_cookie(hexstr('0123456789ABCDEF0000000000000000'));
    $all_the_opts_response->option('CLIENT-SUBNET' => pack('nCCa16', 2, 128, 0, inet_pton(AF_INET6, "::")));
    $all_the_opts_response->option(11 => pack('n', 370));
    $all_the_opts_response->option(NSID => 'foobar');

    _GDT->test_dns(
        $proto => 1,
        resopts => { udppacketsize => 1024, usevc => 1 },
        qname => 'ns1.example.com',
        q_optrr => $all_the_opts_query,
        answer => 'ns1.example.com 86400 A 192.0.2.42',
        addtl => $all_the_opts_response,
        stats => [qw/tcp_conns tcp_reqs noerror edns edns_cookie_init edns_clientsub/],
    )
}

_GDT->test_kill_daemon($pid);
