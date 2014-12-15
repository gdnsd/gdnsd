# This tests RFC3597-related stuff

use _GDT ();
use Test::More tests => 5;

my $pid = _GDT->test_spawn_daemon();

my $t31337_1 = 'rfc3597.example.com 21600 TYPE31337 \# 10 0123456789ABCDEF0123';
my $t31337_2 = 'rfc3597.example.com 21600 TYPE31337 \# 10 3210FEDCBA9876543210';
my $sshfp_1 = 'rfc3597.example.com 21600 SSHFP 1 1 0123456789ABCDEF0123456789ABCDEF01234567';
my $sshfp_2 = 'rfc3597.example.com 21600 SSHFP 2 1 0123456789ABCDEF0123456789ABCDEF01234567';

_GDT->test_dns(
    qname => 'rfc3597.example.com', qtype => 'SSHFP',
    answer => [$sshfp_1, $sshfp_2],
);

_GDT->test_dns(
    qname => 'rfc3597.example.com', qtype => 'TYPE31337',
    answer => [$t31337_1, $t31337_2],
);

_GDT->test_dns(
    qname => 'rfc3597.example.com', qtype => 'ANY',
    answer => [$t31337_1, $t31337_2, $sshfp_1, $sshfp_2],
);

_GDT->test_kill_daemon($pid);
