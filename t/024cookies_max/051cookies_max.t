use _GDT ();
use Net::DNS;
use Test::More tests => 2 + (2 * 7);

# See 025cookies for general notes on cookie testing
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

my $txt_600 = 'txt600.example.com 86400 TXT "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234" "567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789" "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"';

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

    # reuse the good cookie to fetch large record over UDP, should get _ok stat
    _GDT->test_dns(
        $proto => 1,
        resopts => { usevc => 0, igntc => 1, udppacketsize => 1024, },
        qname => 'txt600.example.com', qtype => 'TXT',
        q_optrr => _mk_optrr_cookie($save_good),
        answer => $txt_600,
        addtl => _mk_optrr_cookie(hexstr('0123456789ABCDEF0000000000000000')),
        stats => [qw/udp_reqs udp_edns_big noerror edns edns_cookie_ok/],
    );

    # do it again with a bad cookie over TCP, should get the large response
    # fine in spite of the (UDP-only) limit and the bad cookie noted in stats
    my $cookie_plus_keepalive = _mk_optrr_cookie(hexstr('0123456789ABCDEF0000000000000000'));
    $cookie_plus_keepalive->option(11 => pack('n', 370));
    _GDT->test_dns(
        $proto => 1,
        resopts => { usevc => 1 },
        qname => 'txt600.example.com', qtype => 'TXT',
        q_optrr => _mk_optrr_cookie(hexstr('0123456789ABCDEF0123456789ABCDEF')),
        answer => $txt_600,
        addtl => $cookie_plus_keepalive,
        stats => [qw/tcp_conns tcp_reqs noerror edns edns_cookie_bad/],
    );

    # As above over UDP with a bad cookie, we should get TC-bitted while
    # EDNS/Cookie operations flow normally.
    _GDT->test_dns(
        $proto => 1,
        resopts => { usevc => 0, igntc => 1, udppacketsize => 4096, },
        qname => 'txt600.example.com', qtype => 'TXT',
        q_optrr => _mk_optrr_cookie(hexstr('0123456789ABCDEF0123456789ABCDEF')),
        header => { tc => 1 },
        addtl => _mk_optrr_cookie(hexstr('0123456789ABCDEF0000000000000000')),
        stats => [qw/udp_reqs noerror edns udp_edns_tc edns_cookie_bad/],
    );

    # As above again, with no cookie present in the OPT RR at all.  Should
    # still get a TC-bit.
    my $optrr_plain_1k = Net::DNS::RR->new(
        type => "OPT",
        version => 0,
        name => "",
        size => 1024,
        rcode => 0,
        flags => 0,
    );
    _GDT->test_dns(
        $proto => 1,
        resopts => { usevc => 0, igntc => 1, udppacketsize => 8192 },
        qname => 'txt600.example.com', qtype => 'TXT',
        header => { tc => 1 },
        addtl => $optrr_plain_1k,
        stats => [qw/udp_reqs noerror edns udp_edns_tc/],
    );

    # ... and again, with no EDNS at all
    _GDT->test_dns(
        $proto => 1,
        resopts => { usevc => 0, igntc => 1 },
        qname => 'txt600.example.com', qtype => 'TXT',
        header => { tc => 1 },
        stats => [qw/udp_reqs noerror udp_tc/],
    );

    # Another strange sub-case: no cookie to prevent the 600 limit, but client
    # requested less than 600 bytes anyways
    _GDT->test_dns(
        $proto => 1,
        resopts => { usevc => 0, igntc => 1, udppacketsize => 590 },
        qname => 'txt600.example.com', qtype => 'TXT',
        header => { tc => 1 },
        addtl => $optrr_plain_1k,
        stats => [qw/udp_reqs noerror edns udp_edns_tc/],
    );
}

_GDT->test_kill_daemon($pid);
