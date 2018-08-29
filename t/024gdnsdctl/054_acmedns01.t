use _GDT ();
use Net::DNS;
use Test::More tests => 2 + (2 * 29);

my $soa_neg = 'example.com 900 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900';

_GDT->test_spawn_daemon();

# Loop all the tests twice with a flush at the top, so we test
# add->flush->add->cleanup.
foreach my $i (0, 1) {
    # Flush data
    _GDT->test_run_gdnsdctl('acme-dns-01-flush');

    ## Test just the static zonefile data

    # Static data not involved with ACME, to test some branch edge-cases
    _GDT->test_dns(
        qname => 'asdf.example.com',
        answer => 'asdf.example.com 86400 A 192.0.2.44',
    );
    _GDT->test_dns(
        qname => 'xyz.example.com',
        answer => 'xyz.example.com 86400 A 192.0.2.45',
    );

    # Static data for this name:
    # ns1 A 192.0.2.42
    _GDT->test_dns(
        qname => 'ns1.example.com',
        answer => 'ns1.example.com 86400 A 192.0.2.42',
    );
    _GDT->test_dns(
        qname => '_acme-challenge.ns1.example.com', qtype => 'TXT',
        header => { rcode => 'NXDOMAIN' },
        answer => [],
        auth => $soa_neg,
        stats => [qw/nxdomain udp_reqs/],
    );

    # Static data for this name:
    # _acme-challenge.exists TXT "abcde"
    # Note static RR has TTL of 86400, but is forced to 600 because it has
    # "_acme-challenge" as its first label.
    _GDT->test_dns(
        qname => '_acme-challenge.exists.example.com', qtype => 'TXT',
        answer => '_acme-challenge.exists.example.com 600 TXT "abcde"',
    );
    _GDT->test_dns(
        qname => '_acme-challenge.exists.example.com', qtype => 'A',
        answer => [],
        auth => $soa_neg,
    );
    # tcp_conns stat only bumps on the first loop iteration here...
    my $first_tcp_stats = [qw/noerror udp_reqs udp_tc noerror tcp_reqs/];
    if (!$i) {
	push(@$first_tcp_stats, 'tcp_conns');
    }
    _GDT->test_dns(
        qname => '_acme-challenge.exists.example.com', qtype => 'ANY',
        answer => '_acme-challenge.exists.example.com 600 TXT "abcde"',
        stats => $first_tcp_stats,
    );

    # Static data for this name:
    # _acme-challenge.other A 192.0.2.43
    _GDT->test_dns(
        qname => '_acme-challenge.other.example.com', qtype => 'TXT',
        answer => [],
        auth => $soa_neg,
    );
    _GDT->test_dns(
        qname => '_acme-challenge.other.example.com', qtype => 'A',
        answer => '_acme-challenge.other.example.com 86400 A 192.0.2.43',
    );
    _GDT->test_dns(
        qname => '_acme-challenge.other.example.com', qtype => 'ANY',
        answer => '_acme-challenge.other.example.com 86400 A 192.0.2.43',
        stats => [qw/noerror udp_reqs udp_tc noerror tcp_reqs/],
    );

    # *NO* static data for this name:
    _GDT->test_dns(
        qname => '_acme-challenge.snxd.example.com', qtype => 'TXT',
        header => { rcode => 'NXDOMAIN' },
        answer => [],
        auth => $soa_neg,
        stats => [qw/nxdomain udp_reqs/],
    );
    _GDT->test_dns(
        qname => '_acme-challenge.snxd.example.com', qtype => 'A',
        header => { rcode => 'NXDOMAIN' },
        answer => [],
        auth => $soa_neg,
        stats => [qw/nxdomain udp_reqs/],
    );
    _GDT->test_dns(
        qname => '_acme-challenge.snxd.example.com', qtype => 'ANY',
        header => { rcode => 'NXDOMAIN' },
        answer => [],
        auth => $soa_neg,
        stats => [qw/noerror udp_reqs udp_tc nxdomain tcp_reqs/],
    );

    ## Inject data over all of the names above, in sets of 2 then 3, with a triple record for ns1:
    _GDT->test_run_gdnsdctl('acme-dns-01 exists.example.com 0123456789012345678901234567890123456789012 ns1.example.com A123456789012345678901234567890123456789012');
    _GDT->test_run_gdnsdctl('acme-dns-01 ns1.example.com B123456789012345678901234567890123456789012 other.example.com X123456789012345678901234567890123456789012 snxd.example.com Y123456789012345678901234567890123456789012 ns1.example.com Z123456789012345678901234567890123456789012');

    ## Re-test all the above

    # Static data not involved with ACME, to test some branch edge-cases
    _GDT->test_dns(
        qname => 'asdf.example.com',
        answer => 'asdf.example.com 86400 A 192.0.2.44',
    );
    _GDT->test_dns(
        qname => 'xyz.example.com',
        answer => 'xyz.example.com 86400 A 192.0.2.45',
    );

    # Static data for this name:
    # ns1 A 192.0.2.42
    _GDT->test_dns(
        qname => 'ns1.example.com',
        answer => 'ns1.example.com 86400 A 192.0.2.42',
    );
    _GDT->test_dns(
        qname => '_acme-challenge.ns1.example.com', qtype => 'TXT',
        answer => [
            '_acme-challenge.ns1.example.com 600 TXT "Z123456789012345678901234567890123456789012"',
            '_acme-challenge.ns1.example.com 600 TXT "B123456789012345678901234567890123456789012"',
            '_acme-challenge.ns1.example.com 600 TXT "A123456789012345678901234567890123456789012"',
        ],
    );

    # Static data for this name:
    # _acme-challenge.exists TXT "abcde"
    _GDT->test_dns(
        qname => '_acme-challenge.exists.example.com', qtype => 'TXT',
        answer => [
            '_acme-challenge.exists.example.com 600 TXT "abcde"',
            '_acme-challenge.exists.example.com 600 TXT "0123456789012345678901234567890123456789012"',
        ],
    );
    _GDT->test_dns(
        qname => '_acme-challenge.exists.example.com', qtype => 'A',
        answer => [],
        auth => $soa_neg,
    );
    _GDT->test_dns(
        qname => '_acme-challenge.exists.example.com', qtype => 'ANY',
        answer => [
            '_acme-challenge.exists.example.com 600 TXT "abcde"',
            '_acme-challenge.exists.example.com 600 TXT "0123456789012345678901234567890123456789012"',
        ],
        stats => [qw/noerror udp_reqs udp_tc noerror tcp_reqs/],
    );

    # Static data for this name:
    # _acme-challenge.other A 192.0.2.43
    _GDT->test_dns(
        qname => '_acme-challenge.other.example.com', qtype => 'TXT',
        answer => '_acme-challenge.other.example.com 600 TXT "X123456789012345678901234567890123456789012"',
    );
    _GDT->test_dns(
        qname => '_acme-challenge.other.example.com', qtype => 'A',
        answer => '_acme-challenge.other.example.com 86400 A 192.0.2.43',
    );
    _GDT->test_dns(
        qname => '_acme-challenge.other.example.com', qtype => 'ANY',
        answer => [
            '_acme-challenge.other.example.com 86400 A 192.0.2.43',
            '_acme-challenge.other.example.com 600 TXT "X123456789012345678901234567890123456789012"',
        ],
        stats => [qw/noerror udp_reqs udp_tc noerror tcp_reqs/],
    );

    # *NO* static data for this name:
    _GDT->test_dns(
        qname => '_acme-challenge.snxd.example.com', qtype => 'TXT',
        answer => '_acme-challenge.snxd.example.com 600 TXT "Y123456789012345678901234567890123456789012"',
    );
    _GDT->test_dns(
        qname => '_acme-challenge.snxd.example.com', qtype => 'A',
        answer => [],
        auth => $soa_neg,
    );
    _GDT->test_dns(
        qname => '_acme-challenge.snxd.example.com', qtype => 'ANY',
        answer => '_acme-challenge.snxd.example.com 600 TXT "Y123456789012345678901234567890123456789012"',
        stats => [qw/noerror udp_reqs udp_tc noerror tcp_reqs/],
    );
} # end for-loop

_GDT->test_run_gdnsdctl("stop");
