
# This tests NAPTR-related stuff

use _GDT ();
use FindBin ();
use File::Spec ();
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
#my $srv_uf = '_sip._udp.example.com 21600 SRV 10 60 5060 naptr-udp-foo.example.com';
#my $srv_ub = '_sip._udp.example.com 21600 SRV 10 20 5060 naptr-udp-bar.example.com';
#my $srv_tf = '_sip._tcp.example.com 21600 SRV 10 60 5060 naptr-tcp-foo.example.com';
#my $srv_tb = '_sip._tcp.example.com 21600 SRV 10 20 5060 naptr-tcp-bar.example.com';
my $addr_uf1 = 'naptr-udp-foo.example.com 21600 A 192.0.2.180';
my $addr_uf2 = 'naptr-udp-foo.example.com 21600 A 192.0.2.181';
my $addr_ub1 = 'naptr-udp-bar.example.com 21600 AAAA ::1';
my $addr_ub2 = 'naptr-udp-bar.example.com 21600 AAAA ::2';
my $addr_tf1 = 'naptr-tcp-foo.example.com 21600 AAAA ::3';
my $addr_tf2 = 'naptr-tcp-foo.example.com 21600 A 192.0.2.182';
my $addr_tb = 'naptr-tcp-bar.example.com 21600 A 192.0.2.183';
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
    # we dropped NAPTR->SRV additional data chasing
    #addtl => [$srv_uf, $srv_ub, $srv_tf, $srv_tb, $addr_uf1, $addr_uf2, $addr_ub1, $addr_ub2, $addr_tf1, $addr_tf2, $addr_tb],
);

_GDT->test_dns(
    qname => 'naptr-a.example.com', qtype => 'NAPTR',
    answer => [$naptr_a1, $naptr_a2, $naptr_a3, $naptr_a4],
    addtl => [$addr_uf1, $addr_uf2, $addr_ub1, $addr_ub2, $addr_tf1, $addr_tf2, $addr_tb],
);

_GDT->test_dns(
    qname => 'nsa.example.com', qtype => 'ANY',
    answer => [$nsa1, $nsa2, $nsa3, $nsa4],
);

_GDT->test_kill_daemon($pid);
