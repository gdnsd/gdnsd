# CNAME testing
# this is basically going through A, CNAME, and ANY queries against
#  five different classes of CNAME targets (local nonexistent,
#  local existent, delegation, delegation glue record, and external).
use _GDT ();
use Test::More tests => 17;

my $neg_soa = 'example.com 900 SOA ns1.example.com hmaster.example.net 1 7200 1800 259200 900';

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'cn-nx.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    answer => 'cn-nx.example.com 21600 CNAME nx.example.com',
    auth => $neg_soa,
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'cn-nx.example.com', qtype => 'CNAME',
    answer => 'cn-nx.example.com 21600 CNAME nx.example.com',
);

_GDT->test_dns(
    qname => 'cn-nx.example.com', qtype => 'ANY',
    answer => 'cn-nx.example.com 21600 CNAME nx.example.com',
);

_GDT->test_dns(
    qname => 'cn-local.example.com', qtype => 'A',
    answer => [
        'cn-local.example.com 21600 CNAME ns1.example.com',
        'ns1.example.com 21600 A 192.0.2.1',
    ],
);

_GDT->test_dns(
    qname => 'cn-local.example.com', qtype => 'CNAME',
    answer => 'cn-local.example.com 21600 CNAME ns1.example.com',
);

_GDT->test_dns(
    qname => 'cn-local.example.com', qtype => 'ANY',
    answer => 'cn-local.example.com 21600 CNAME ns1.example.com',
);

_GDT->test_dns(
    qname => 'cn-deleg.example.com', qtype => 'A',
    answer => 'cn-deleg.example.com 21600 CNAME foo.subz.example.com',
    auth => [
        'subz.example.com 21600 NS ns1.subz.example.com',
        'subz.example.com 21600 NS ns2.subz.example.com',
    ],
    addtl => [
        'ns1.subz.example.com 21600 A 192.0.2.10',
        'ns2.subz.example.com 21600 A 192.0.2.20',
    ],
);

_GDT->test_dns(
    qname => 'cn-deleg.example.com', qtype => 'CNAME',
    answer => 'cn-deleg.example.com 21600 CNAME foo.subz.example.com',
);

_GDT->test_dns(
    qname => 'cn-deleg.example.com', qtype => 'ANY',
    answer => 'cn-deleg.example.com 21600 CNAME foo.subz.example.com',
);

_GDT->test_dns(
    qname => 'cn-deleg-glue.example.com', qtype => 'A',
    answer => 'cn-deleg-glue.example.com 21600 CNAME ns1.subz.example.com',
    auth => [
        'subz.example.com 21600 NS ns1.subz.example.com',
        'subz.example.com 21600 NS ns2.subz.example.com',
    ],
    addtl => [
        'ns1.subz.example.com 21600 A 192.0.2.10',
        'ns2.subz.example.com 21600 A 192.0.2.20',
    ],
);

_GDT->test_dns(
    qname => 'cn-deleg-glue.example.com', qtype => 'CNAME',
    answer => 'cn-deleg-glue.example.com 21600 CNAME ns1.subz.example.com',
);

_GDT->test_dns(
    qname => 'cn-deleg-glue.example.com', qtype => 'ANY',
    answer => 'cn-deleg-glue.example.com 21600 CNAME ns1.subz.example.com',
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
);

_GDT->test_kill_daemon($pid);
