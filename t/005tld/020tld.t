# Basic dynamic resource tests

use _GDT ();
use Net::DNS;
use Test::More tests => 5;

my $optrr_nsid = Net::DNS::RR->new(
    type => "OPT",
    ednsversion => 0,
    name => "",
    class => 1024,
    extendedrcode => 0,
    ednsflags => 0,
    optioncode => 3,
    optiondata => pack('H*', '6578616D706C65'),
);

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'com', qtype => 'A',
    answer => 'com 43200 A 192.0.2.3',
);

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 0, udppacketsize => 32000 },
    qname => 'www.com', qtype => 'A',
    answer => 'www.com 43200 A 192.0.2.4',
    addtl => $optrr_nsid,
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
