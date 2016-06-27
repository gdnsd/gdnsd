use _GDT ();
use Net::DNS;
use Test::More tests => 4;

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 1, udppacketsize => 512 },
    qname => 'any.example.com', qtype => 'ANY',
    header => { tc => 1 },
    stats => [qw/udp_reqs udp_tc noerror/],
);

_GDT->test_dns(
    resopts => { usevc => 1, igntc => 0, udppacketsize => 512 },
    qname => 'any.example.com', qtype => 'ANY',
    answer => [
        'any.example.com 86400 A 192.0.2.192',
        'any.example.com 86400 AAAA 2001:DB8::1',
        'any.example.com 86400 MX 0 ns1.example.com',
        'any.example.com 86400 TXT "example text"',
    ],
    addtl => [
        'ns1.example.com 86400 A 192.0.2.1',
    ],
    stats => [qw/tcp_reqs noerror/],
);

_GDT->test_kill_daemon($pid);
