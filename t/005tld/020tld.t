# Basic dynamic resource tests

use _GDT ();
use Net::DNS;
use Test::More tests => 6;

my $optrr_req_nsid = Net::DNS::RR->new(
    type => "OPT",
    version => 0,
    name => "",
    size => 1024,
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

my $optrr_nonsid = Net::DNS::RR->new(
    type => "OPT",
    version => 0,
    name => "",
    size => 1024,
    rcode => 0,
    flags => 0,
);

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'com', qtype => 'A',
    answer => 'com 43200 A 192.0.2.3',
);

_GDT->test_dns(
    qname => 'www.com', qtype => 'A',
    q_optrr => $optrr_req_nsid,
    answer => 'www.com 43200 A 192.0.2.4',
    addtl => $optrr_nsid,
    stats => [qw/udp_reqs noerror edns/],
);

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 0, udppacketsize => 32000 },
    qname => 'www.com', qtype => 'A',
    answer => 'www.com 43200 A 192.0.2.4',
    addtl => $optrr_nonsid,
    stats => [qw/udp_reqs noerror edns/],
);

# This test covers using an SOA record
#  that isn't the first rrset stored in a node.
_GDT->test_dns(
    qname => 'foo.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'com 900 SOA ns1.com hostmaster.com 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_kill_daemon($pid);
