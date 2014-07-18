
# And these are some simple error checks against the same data as
#  001noerr.t.  Just basic NOERROR+0answers, NXDOMAIN, REFUSED, etc.

use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 15;

my $neg_soa = 'example.com 900 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900';

my $pid = _GDT->test_spawn_daemon();

# A noerror response with no data.  "www" is
#  a leaf node in the database which has data,
#  but not NS data.
_GDT->test_dns(
    qname => 'www.example.com', qtype => 'NS',
    auth => $neg_soa,
);

# Noerror but no data, as in the first test, but these
#  are interior names (some name underneath them
#  has data, but they have no data at all).
_GDT->test_dns(
    qname => 'goober.example.com', qtype => 'A',
    auth => $neg_soa,
);

_GDT->test_dns(
    qname => 'y.z.example.com', qtype => 'A',
    auth => $neg_soa,
);

# several nxdomains
_GDT->test_dns(
    qname => 'foo.www.example.com', qtype => 'NS',
    header => { rcode => 'NXDOMAIN' },
    auth => $neg_soa,
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'foo.bar.www.example.com', qtype => 'NS',
    header => { rcode => 'NXDOMAIN' },
    auth => $neg_soa,
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'nxd.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => $neg_soa,
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'z.nxd.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => $neg_soa,
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'x.y.z.nxd.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => $neg_soa,
    stats => [qw/udp_reqs nxdomain/],
);

# The rest here are all out of our authority, so they're all refused
_GDT->test_dns(
    qname => 'example.org', qtype => 'A',
    header => { rcode => 'REFUSED', aa => 0 },
    stats => [qw/udp_reqs refused/],
);

_GDT->test_dns(
    qname => 'foo.example.org', qtype => 'A',
    header => { rcode => 'REFUSED', aa => 0 },
    stats => [qw/udp_reqs refused/],
);

_GDT->test_dns(
    qname => 'x.y.z.foo.example.org', qtype => 'A',
    header => { rcode => 'REFUSED', aa => 0 },
    stats => [qw/udp_reqs refused/],
);

_GDT->test_dns(
    qname => 'com', qtype => 'A',
    header => { rcode => 'REFUSED', aa => 0 },
    stats => [qw/udp_reqs refused/],
);

_GDT->test_dns(
    qname => '.', qtype => 'A',
    header => { rcode => 'REFUSED', aa => 0 },
    stats => [qw/udp_reqs refused/],
);

_GDT->test_kill_daemon($pid);
