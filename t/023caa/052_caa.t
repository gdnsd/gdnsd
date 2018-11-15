use _GDT ();
use Test::More tests => 3;

my $pid = _GDT->test_spawn_daemon();

my $optrr_req_nsid = Net::DNS::RR->new(
    type => "OPT",
    version => 0,
    name => "",
    size => 32000,
    rcode => 0,
    flags => 0,
);
$optrr_req_nsid->option(NSID => '');

my $optrr_nsid = Net::DNS::RR->new(
    type => "OPT",
    version => 0,
    name => "",
    size => 1024,
    rcode => 0,
    flags => 0,
);
$optrr_nsid->option(NSID => pack('H*', '6578616D706C65'));

_GDT->test_dns(
    qname => 'example.com', qtype => 'TYPE257',
    q_optrr => $optrr_req_nsid,
    answer => [
        'example.com 86400 TYPE257 \# 21 00 05 6973737565 63612E6578616D706C652E6E6574',
        'example.com 86400 TYPE257 \# 12 80 03 746273 556E6B6E6F776E',
        'example.com 86400 TYPE257 \# 37 00 05 6973737565 63612E6578616D706C652E6F72673B206163636F756E743D323330313233',
        'example.com 86400 TYPE257 \# 36 00 09 697373756577696C64 63612D666F6F2E6578616D706C652E6F72673B2078797A7A79',
        'example.com 86400 TYPE257 \# 34 00 05 696F646566 6D61696C746F3A7365637572697479406578616D706C652E636F6D',
        'example.com 86400 TYPE257 \# 32 00 05 696F646566 687474703A2F2F696F6465662E6578616D706C652E636F6D2F',
    ],
    addtl => $optrr_nsid,
    stats => [qw/udp_reqs noerror edns/],
);

_GDT->test_kill_daemon($pid);
