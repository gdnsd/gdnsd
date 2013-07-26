
# This tests static A/AAAA and rrset size limiting

use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 8;

my $setlimit_A = [
    'setlimit.example.com 21600 A 192.0.2.177',
    'setlimit.example.com 21600 A 192.0.2.178',
    'setlimit.example.com 21600 A 192.0.2.179',
    'setlimit.example.com 21600 A 192.0.2.180',
    'setlimit.example.com 21600 A 192.0.2.181',
    'setlimit.example.com 21600 A 192.0.2.182',
];

my $setlimit_AAAA = [
    'setlimit.example.com 21600 AAAA ::1',
    'setlimit.example.com 21600 AAAA ::2',
    'setlimit.example.com 21600 AAAA ::3',
    'setlimit.example.com 21600 AAAA ::4',
    'setlimit.example.com 21600 AAAA ::5',
    'setlimit.example.com 21600 AAAA ::6',
];

my $setlimit_under_A = [
    'setlimit-under.example.com 21600 A 192.0.2.108',
    'setlimit-under.example.com 21600 A 192.0.2.109',
    'setlimit-under.example.com 21600 A 192.0.2.110',
];

my $setlimit_under_AAAA = [
    'setlimit-under.example.com 21600 AAAA ::108',
    'setlimit-under.example.com 21600 AAAA ::109',
    'setlimit-under.example.com 21600 AAAA ::110',
];

my $setlimit_one_A = [
    'setlimit-one.example.com 21600 A 192.0.2.118',
    'setlimit-one.example.com 21600 A 192.0.2.119',
    'setlimit-one.example.com 21600 A 192.0.2.120',
];

my $setlimit_one_AAAA = [
    'setlimit-one.example.com 21600 AAAA ::118',
    'setlimit-one.example.com 21600 AAAA ::119',
    'setlimit-one.example.com 21600 AAAA ::120',
];

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'setlimit.example.com', qtype => 'A',
    answer => $setlimit_A,
    addtl => $setlimit_AAAA,
    limit_v4 => 3,
    limit_v6 => 4,
);

_GDT->test_dns(
    qname => 'setlimit.example.com', qtype => 'AAAA',
    answer => $setlimit_AAAA,
    addtl => $setlimit_A,
    limit_v4 => 3,
    limit_v6 => 4,
);

_GDT->test_dns(
    qname => 'setlimit-under.example.com', qtype => 'AAAA',
    answer => $setlimit_under_AAAA,
    addtl => $setlimit_under_A,
    limit_v4 => 5,
    limit_v6 => 6,
);

_GDT->test_dns(
    qname => 'setlimit-under.example.com', qtype => 'A',
    answer => $setlimit_under_A,
    addtl => $setlimit_under_AAAA,
    limit_v4 => 5,
    limit_v6 => 6,
);

_GDT->test_dns(
    qname => 'setlimit-one.example.com', qtype => 'A',
    answer => $setlimit_one_A,
    addtl => $setlimit_one_AAAA,
    limit_v4 => 1,
    limit_v6 => 1,
);

_GDT->test_dns(
    qname => 'setlimit-one.example.com', qtype => 'AAAA',
    answer => $setlimit_one_AAAA,
    addtl => $setlimit_one_A,
    limit_v4 => 1,
    limit_v6 => 1,
);

_GDT->test_kill_daemon($pid);
