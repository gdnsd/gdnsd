# Basic dynamic resource tests

use _GDT ();
use Net::DNS;
use Test::More tests => 10;

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => '.', qtype => 'A',
    answer => [
        '. 86400 A 192.0.2.3',
        '. 86400 A 192.0.2.33',
    ],
);

_GDT->test_dns(
    qname => '.', qtype => 'AAAA',
    answer => [
        '. 86400 AAAA ::192.0.2.3',
        '. 86400 AAAA ::192.0.2.33',
    ],
);

_GDT->test_dns(
    qname => 'www', qtype => 'A',
    answer => 'www 86400 A 192.0.2.4',
);

_GDT->test_dns(
    qname => '.', qtype => 'ANY',
    answer => '. 3600 HINFO "RFC8482" ""',
);

# A .com delegation
_GDT->test_dns(
    qname => 'www.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'com 86400 NS ns1.com',
        'com 86400 NS ns2.com',
    ],
    addtl => [
        'ns1.com 86400 IN A 192.0.2.5',
        'ns2.com 86400 IN A 192.0.2.6',
    ],
);

# Test explicit root SOA, then also a negative-SOA at the root of the DNS
my $soa = '. 900 SOA ns1. dns-admin. 1 7200 1800 259200 900';
_GDT->test_dns(
    qname => '.', qtype => 'SOA',
    answer => $soa,
);
_GDT->test_dns(
    qname => 'this.is.nxdomain.',
    header => { rcode => 'NXDOMAIN' },
    auth => $soa,
    stats => [qw/udp_reqs nxdomain/],
);

# The first two NS here are roughly analogous to how the real rootservers'
# config works, where the root NS records must be glue within some delegated
# subzone (root-servers.com), and we must return their addresses as glue
_GDT->test_dns(
    qname => '.', qtype => 'NS',
    header => { aa => 1 },
    answer => [
        '. 86400 NS ns1.root-servers.com',
        '. 86400 NS ns2.root-servers.com',
        '. 86400 NS ns3',
        '. 86400 NS .',
    ],
    addtl => [
        'ns1.root-servers.com 86400 IN A 192.0.2.1',
        'ns1.root-servers.com 86400 IN AAAA ::192.0.2.11',
        'ns2.root-servers.com 86400 IN A 192.0.2.2',
    ],
);

_GDT->test_kill_daemon($pid);
