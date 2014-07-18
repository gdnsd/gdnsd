
# CNAME test, with include_optional_ns to get the auth section right...
# this is basically going through A, CNAME, and ANY queries against
#  five different classes of CNAME targets (local nonexistent,
#  local existent, delegation, delegation glue record, and external).
# CNAME and ANY responses should be identical (this was the bug that
#  triggered writing these testcases - ANY was being treated more like A).

use _GDT ();
use FindBin ();
use File::Spec ();
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

foreach my $qt (qw/CNAME ANY/) {
    _GDT->test_dns(
        qname => 'cn-nx.example.com', qtype => $qt,
        answer => 'cn-nx.example.com 21600 CNAME nx.example.com',
        auth => [
	    'example.com 21600 NS ns1.example.com',
	    'example.com 21600 NS ns2.example.com',
        ],
        addtl => [
            'ns1.example.com 21600 A 192.0.2.1',
            'ns2.example.com 21600 A 192.0.2.2',
        ],
    );
}

_GDT->test_dns(
    qname => 'cn-local.example.com', qtype => 'A',
    answer => [
        'cn-local.example.com 21600 CNAME ns1.example.com',
        'ns1.example.com 21600 A 192.0.2.1',
    ],
    auth => [
	'example.com 21600 NS ns1.example.com',
	'example.com 21600 NS ns2.example.com',
    ],
    addtl => [
        'ns2.example.com 21600 A 192.0.2.2',
    ],
);

foreach my $qt (qw/CNAME ANY/) {
    _GDT->test_dns(
        qname => 'cn-local.example.com', qtype => $qt,
        answer => [
            'cn-local.example.com 21600 CNAME ns1.example.com'
        ],
        auth => [
	    'example.com 21600 NS ns1.example.com',
	    'example.com 21600 NS ns2.example.com',
        ],
        addtl => [
            'ns1.example.com 21600 A 192.0.2.1',
            'ns2.example.com 21600 A 192.0.2.2',
        ],
    );
}

_GDT->test_dns(
    qname => 'cn-deleg.example.com', qtype => 'A',
    answer => [
        'cn-deleg.example.com 21600 CNAME foo.subz.example.com',
    ],
    auth => [
	'subz.example.com 21600 NS ns1.subz.example.com',
	'subz.example.com 21600 NS ns2.subz.example.com',
    ],
    addtl => [
        'ns1.subz.example.com 21600 A 192.0.2.10',
        'ns2.subz.example.com 21600 A 192.0.2.20',
    ],
);

foreach my $qt (qw/CNAME ANY/) {
    _GDT->test_dns(
        qname => 'cn-deleg.example.com', qtype => $qt,
        answer => [
            'cn-deleg.example.com 21600 CNAME foo.subz.example.com',
        ],
        auth => [
	    'example.com 21600 NS ns1.example.com',
	    'example.com 21600 NS ns2.example.com',
        ],
        addtl => [
            'ns1.example.com 21600 A 192.0.2.1',
            'ns2.example.com 21600 A 192.0.2.2',
        ],
    );
}

_GDT->test_dns(
    qname => 'cn-deleg-glue.example.com', qtype => 'A',
    answer => [
        'cn-deleg-glue.example.com 21600 CNAME ns1.subz.example.com',
    ],
    auth => [
	'subz.example.com 21600 NS ns1.subz.example.com',
	'subz.example.com 21600 NS ns2.subz.example.com',
    ],
    addtl => [
        'ns1.subz.example.com 21600 A 192.0.2.10',
        'ns2.subz.example.com 21600 A 192.0.2.20',
    ],
);

foreach my $qt (qw/CNAME ANY/) {
    _GDT->test_dns(
        qname => 'cn-deleg-glue.example.com', qtype => $qt,
        answer => [
            'cn-deleg-glue.example.com 21600 CNAME ns1.subz.example.com',
        ],
        auth => [
	    'example.com 21600 NS ns1.example.com',
	    'example.com 21600 NS ns2.example.com',
        ],
        addtl => [
            'ns1.example.com 21600 A 192.0.2.1',
            'ns2.example.com 21600 A 192.0.2.2',
        ],
    );
}

_GDT->test_dns(
    qname => 'cn-ext.example.com', qtype => 'A',
    answer => 'cn-ext.example.com 21600 CNAME www.example.net',
);

foreach my $qt (qw/CNAME ANY/) {
    _GDT->test_dns(
        qname => 'cn-ext.example.com', qtype => $qt,
        answer => 'cn-ext.example.com 21600 CNAME www.example.net',
        auth => [
	    'example.com 21600 NS ns1.example.com',
	    'example.com 21600 NS ns2.example.com',
        ],
        addtl => [
            'ns1.example.com 21600 A 192.0.2.1',
            'ns2.example.com 21600 A 192.0.2.2',
        ],
    );
}

_GDT->test_kill_daemon($pid);
