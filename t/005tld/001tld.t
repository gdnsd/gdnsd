
# Basic dynamic resource tests

use _GDT ();
use FindBin ();
use File::Spec ();
use Net::DNS;
use Test::More tests => 5;

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'com', qtype => 'A',
    answer => 'com 43200 A 192.0.2.3',
);

_GDT->test_dns(
    qname => 'www.com', qtype => 'A',
    answer => 'www.com 43200 A 192.0.2.4',
);

# This test covers using an SOA record
#  that isn't the first rrset stored in a node.
_GDT->test_dns(
    qname => 'foo.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'com 43200 SOA ns1.com hostmaster.com 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_kill_daemon($pid);
