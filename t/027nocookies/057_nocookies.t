use _GDT ();
use Net::DNS;
use Test::More tests => 3;

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

my $pid = _GDT->test_spawn_daemon();

# Test that input cookies are basically ignored when config disables cookies
my $optrr_plain_1k = Net::DNS::RR->new(
    type => "OPT",
    version => 0,
    name => "",
    size => 1024,
    rcode => 0,
    flags => 0,
);
_GDT->test_dns(
    qname => 'ns1.example.com',
    q_optrr => _mk_optrr_cookie(hexstr('0123456789ABCDEF')),
    answer => 'ns1.example.com 86400 A 192.0.2.42',
    addtl => $optrr_plain_1k,
    stats => [qw/udp_reqs noerror edns/],
);

_GDT->test_kill_daemon($pid);
