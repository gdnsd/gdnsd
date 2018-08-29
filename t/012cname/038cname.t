# CNAME test, with include_optional_ns to get the auth section right...
# this is basically going through A, CNAME, and ANY queries against
#  five different classes of CNAME targets (local nonexistent,
#  local existent, delegation, delegation glue record, and external).
# CNAME and ANY responses should be identical (this was the bug that
#  triggered writing these testcases - ANY was being treated more like A).

use _GDT ();
use Test::More tests => 17;

my $neg_soa = 'example.com 900 SOA ns1.example.com hmaster.example.net 1 7200 1800 259200 900';

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'cn-nx.example.com', qtype => 'A',
    answer => 'cn-nx.example.com 21600 CNAME nx.example.com',
);

_GDT->test_dns(
    qname => 'cn-nx.example.com', qtype => 'CNAME',
    answer => 'cn-nx.example.com 21600 CNAME nx.example.com',
);

_GDT->test_dns(
    qname => 'cn-nx.example.com', qtype => 'ANY',
    answer => 'cn-nx.example.com 21600 CNAME nx.example.com',
    stats => [qw/udp_reqs udp_tc noerror tcp_conns tcp_reqs noerror/],
);

_GDT->test_dns(
    qname => 'cn-local.example.com', qtype => 'A',
    answer => 'cn-local.example.com 21600 CNAME ns1.example.com',
);

_GDT->test_dns(
    qname => 'cn-local.example.com', qtype => 'CNAME',
    answer => 'cn-local.example.com 21600 CNAME ns1.example.com',
);

_GDT->test_dns(
    qname => 'cn-local.example.com', qtype => 'ANY',
    answer => 'cn-local.example.com 21600 CNAME ns1.example.com',
    stats => [qw/udp_reqs udp_tc noerror tcp_reqs noerror/],
);

_GDT->test_dns(
    qname => 'cn-deleg.example.com', qtype => 'A',
    answer => 'cn-deleg.example.com 21600 CNAME foo.subz.example.com',
);

_GDT->test_dns(
    qname => 'cn-deleg.example.com', qtype => 'CNAME',
    answer => 'cn-deleg.example.com 21600 CNAME foo.subz.example.com',
);

_GDT->test_dns(
    qname => 'cn-deleg.example.com', qtype => 'ANY',
    answer => 'cn-deleg.example.com 21600 CNAME foo.subz.example.com',
    stats => [qw/udp_reqs udp_tc noerror tcp_reqs noerror/],
);

_GDT->test_dns(
    qname => 'cn-deleg-glue.example.com', qtype => 'A',
    answer => 'cn-deleg-glue.example.com 21600 CNAME ns1.subz.example.com',
);

_GDT->test_dns(
    qname => 'cn-deleg-glue.example.com', qtype => 'CNAME',
    answer => 'cn-deleg-glue.example.com 21600 CNAME ns1.subz.example.com',
);

_GDT->test_dns(
    qname => 'cn-deleg-glue.example.com', qtype => 'ANY',
    answer => 'cn-deleg-glue.example.com 21600 CNAME ns1.subz.example.com',
    stats => [qw/udp_reqs udp_tc noerror tcp_reqs noerror/],
);

_GDT->test_dns(
    qname => 'cn-ext.example.com', qtype => 'A',
    answer => 'cn-ext.example.com 21600 CNAME www.example.net',
);

_GDT->test_dns(
    qname => 'cn-ext.example.com', qtype => 'CNAME',
    answer => 'cn-ext.example.com 21600 CNAME www.example.net',
);

_GDT->test_dns(
    qname => 'cn-ext.example.com', qtype => 'ANY',
    answer => 'cn-ext.example.com 21600 CNAME www.example.net',
    stats => [qw/udp_reqs udp_tc noerror tcp_reqs noerror/],
);

_GDT->test_kill_daemon($pid);
