# This tests NAPTR-related stuff

use _GDT ();
use Test::More tests => 7;

my $naptr_u1 = 'naptr-u.example.com 21600 NAPTR 100 10 "U" "E2U+sip" "!^.*$!sip:customer-service@example.com!i" .';
my $naptr_u2 = 'naptr-u.example.com 21600 NAPTR 102 10 "U" "E2U+email" "!^.*$!mailto:information@example.com!i" .';
my $naptr_s1 = 'naptr-s.example.com 21600 NAPTR 100 10 "S" "SIP+D2U" "" _sip._udp.example.com';
my $naptr_s2 = 'naptr-s.example.com 21600 NAPTR 102 10 "S" "SIP+D2T" "" _sip._tcp.example.com';
my $naptr_a1 = 'naptr-a.example.com 21600 NAPTR 100 10 "A" "SIP+D2U" "" naptr-udp-foo.example.com';
my $naptr_a2 = 'naptr-a.example.com 21600 NAPTR 101 10 "A" "SIP+D2U" "" naptr-udp-bar.example.com';
my $naptr_a3 = 'naptr-a.example.com 21600 NAPTR 102 10 "A" "SIP+D2T" "" naptr-tcp-foo.example.com';
my $naptr_a4 = 'naptr-a.example.com 21600 NAPTR 103 10 "A" "SIP+D2T" "" naptr-tcp-bar.example.com';
my $naptr_sx = 'naptr-sx.example.com 21600 NAPTR 100 10 "S" "+FOO:BAR" "" somewhere.example.net';
my $nsa1 = 'nsa.example.com 21600 NAPTR 100 10 "S" "foo" "" nsa.example.com';
my $nsa2 = 'nsa.example.com 21600 NAPTR 101 10 "A" "foo" "" nsa.example.com';
my $nsa3 = 'nsa.example.com 21600 SRV 10 20 30 nsa.example.com';
my $nsa4 = 'nsa.example.com 21600 A 192.0.2.185';

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'naptr-sx.example.com', qtype => 'NAPTR',
    answer => $naptr_sx,
);

_GDT->test_dns(
    qname => 'naptr-u.example.com', qtype => 'NAPTR',
    answer => [$naptr_u1, $naptr_u2],
);

_GDT->test_dns(
    qname => 'naptr-s.example.com', qtype => 'NAPTR',
    answer => [$naptr_s1, $naptr_s2],
);

_GDT->test_dns(
    qname => 'naptr-a.example.com', qtype => 'NAPTR',
    answer => [$naptr_a1, $naptr_a2, $naptr_a3, $naptr_a4],
);

_GDT->test_dns(
    qname => 'nsa.example.com', qtype => 'ANY',
    answer => 'nsa.example.com 3600 HINFO "RFC8482" ""',
);

_GDT->test_kill_daemon($pid);
