
# This tests AAAA and related stuff

use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 19;

my $soa_auth = 'example.com 21600 SOA ns1.example.com hmaster.example.net 1 7200 1800 259200 900';

$optrr = Net::DNS::RR->new(
    type => "OPT",
    ednsversion => 0,
    name => "",
    class => 1280,
    extendedrcode => 0,
    ednsflags => 0,
);

my $bigname = q{0.0123456789.01234567890123456789012345678901234567890123456789.01234567890123456789012345678901234567890123456789.01234567890123456789012345678901234567890123456789.46glue.example.com};

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'v6basic.example.com', qtype => 'AAAA',
    answer => 'v6basic.example.com 1234 AAAA 1234:5678:90AB:CDEF:FDEC:BA09:8765:4321',
);

_GDT->test_dns(
    qname => 'v6basic.example.com', qtype => 'MX',
    auth => $soa_auth
);

_GDT->test_dns(
    qname => 'v6basic.example.com', qtype => 'A',
    auth => $soa_auth,
    addtl => 'v6basic.example.com 1234 AAAA 1234:5678:90AB:CDEF:FDEC:BA09:8765:4321',
);

_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'AAAA',
    auth => $soa_auth,
    addtl => 'ns1.example.com 21600 A 192.0.2.1',
);

_GDT->test_dns(
    qname => 'v6minmax.example.com', qtype => 'AAAA',
    answer => [
        'v6minmax.example.com 21600 AAAA FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF',
        'v6minmax.example.com 21600 AAAA 0::1',
        'v6minmax.example.com 21600 AAAA 0::0',
    ],
);

_GDT->test_dns(
    qname => '46mix.example.com', qtype => 'AAAA',
    answer => [
        '46mix.example.com 21600 AAAA ABCD::DCBA',
        '46mix.example.com 21600 AAAA DEAD::BEEF',
    ],
    addtl => [
        '46mix.example.com 21600 A 192.0.2.200',
        '46mix.example.com 21600 A 192.0.2.201',
    ],
);

_GDT->test_dns(
    qname => '46mix.example.com', qtype => 'A',
    answer => [
        '46mix.example.com 21600 A 192.0.2.200',
        '46mix.example.com 21600 A 192.0.2.201',
    ],
    addtl => [
        '46mix.example.com 21600 AAAA ABCD::DCBA',
        '46mix.example.com 21600 AAAA DEAD::BEEF',
    ],
);

_GDT->test_dns(
    qname => '46mix.example.com', qtype => 'ANY',
    answer => [
        '46mix.example.com 21600 AAAA ABCD::DCBA',
        '46mix.example.com 21600 AAAA DEAD::BEEF',
        '46mix.example.com 21600 A 192.0.2.200',
        '46mix.example.com 21600 A 192.0.2.201',
    ],
);

_GDT->test_dns(
    qname => 'www.46deleg.example.com', qtype => 'MX',
    header => { aa => 0 },
    auth => [
        '46deleg.example.com 21600 NS v6minmax.example.com',
        '46deleg.example.com 21600 NS 46mix.example.com',
        '46deleg.example.com 21600 NS v6basic.example.com',
    ],
    addtl => [
        'v6minmax.example.com 21600 AAAA FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF',
        'v6minmax.example.com 21600 AAAA 0::1',
        'v6minmax.example.com 21600 AAAA 0::0',
        '46mix.example.com 21600 AAAA ABCD::DCBA',
        '46mix.example.com 21600 AAAA DEAD::BEEF',
        '46mix.example.com 21600 A 192.0.2.200',
        '46mix.example.com 21600 A 192.0.2.201',
        'v6basic.example.com 1234 AAAA 1234:5678:90AB:CDEF:FDEC:BA09:8765:4321',
    ],
);

_GDT->test_dns(
    qname => 'www.46glue.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        '46glue.example.com 21600 NS a.46glue.example.com',
        '46glue.example.com 21600 NS b.46glue.example.com',
        '46glue.example.com 21600 NS c.46glue.example.com',
        '46glue.example.com 21600 NS d.46glue.example.com',
    ],
    addtl => [
        'a.46glue.example.com 21600 A 192.0.2.202',
        'a.46glue.example.com 21600 A 192.0.2.203',
        'b.46glue.example.com 21600 AAAA ::1',
        'b.46glue.example.com 21600 AAAA ::2',
        'b.46glue.example.com 21600 AAAA ::3',
        'c.46glue.example.com 21600 AAAA ::4',
        'c.46glue.example.com 21600 A 192.0.2.204',
        'c.46glue.example.com 21600 A 192.0.2.205',
        'd.46glue.example.com 21600 AAAA ::5',
        'd.46glue.example.com 21600 AAAA ::6',
        'd.46glue.example.com 21600 A 192.0.2.206',
    ],
);

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 1, udppacketsize => 550 },
    qname => $bigname, qtype => 'A',
    header => { aa => 0 },
    auth => [
        '46glue.example.com 21600 NS a.46glue.example.com',
        '46glue.example.com 21600 NS b.46glue.example.com',
        '46glue.example.com 21600 NS c.46glue.example.com',
        '46glue.example.com 21600 NS d.46glue.example.com',
    ],
    addtl => [
        'a.46glue.example.com 21600 A 192.0.2.202',
        'a.46glue.example.com 21600 A 192.0.2.203',
        'b.46glue.example.com 21600 AAAA ::1',
        'b.46glue.example.com 21600 AAAA ::2',
        'b.46glue.example.com 21600 AAAA ::3',
        'c.46glue.example.com 21600 AAAA ::4',
        'c.46glue.example.com 21600 A 192.0.2.204',
        'c.46glue.example.com 21600 A 192.0.2.205',
        'd.46glue.example.com 21600 AAAA ::5',
        'd.46glue.example.com 21600 AAAA ::6',
        'd.46glue.example.com 21600 A 192.0.2.206',
        $optrr,
    ],
    stats => [qw/udp_reqs edns udp_edns_big noerror/],
);

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 1, udppacketsize => 512 },
    qname => $bigname, qtype => 'A',
    header => { aa => 0, tc => 1 },
    stats => [qw/udp_reqs udp_tc noerror/],
);

_GDT->test_dns(
    qname => 'v6mx.example.com', qtype => 'MX',
    answer => 'v6mx.example.com 21600 MX 0 v6basic.example.com',
    addtl => 'v6basic.example.com 1234 AAAA 1234:5678:90AB:CDEF:FDEC:BA09:8765:4321',
);

_GDT->test_dns(
    qname => '_smtp._tcp.example.com', qtype => 'SRV',
    answer => '_smtp._tcp.example.com 21600 SRV 1 2 3 46mix.example.com',
    addtl => [
        '46mix.example.com 21600 AAAA ABCD::DCBA',
        '46mix.example.com 21600 AAAA DEAD::BEEF',
        '46mix.example.com 21600 A 192.0.2.200',
        '46mix.example.com 21600 A 192.0.2.201',
    ],
);

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 1, udppacketsize => 660 },
    qname => '012345678901234567890123456789012345678901234567890123456789.012345678901234567890123456789012345678901234567890123456789.012345678901234567890123456789012345678901234567890123456789.big64mx.example.com', qtype => 'MX',
    answer => '012345678901234567890123456789012345678901234567890123456789.012345678901234567890123456789012345678901234567890123456789.012345678901234567890123456789012345678901234567890123456789.big64mx.example.com 21600 IN MX 0 01234567890.big46.example.com',
    addtl => [
        '01234567890.big46.example.com. 21600 IN AAAA ::1',
        '01234567890.big46.example.com. 21600 IN AAAA ::0.0.0.2',
        '01234567890.big46.example.com. 21600 IN AAAA ::0.0.0.3',
        '01234567890.big46.example.com. 21600 IN AAAA ::0.0.0.4',
        '01234567890.big46.example.com. 21600 IN AAAA ::0.0.0.5',
        '01234567890.big46.example.com. 21600 IN AAAA ::0.0.0.6',
        '01234567890.big46.example.com. 21600 IN AAAA ::0.0.0.7',
        '01234567890.big46.example.com. 21600 IN AAAA ::0.0.0.8',
        '01234567890.big46.example.com. 21600 IN AAAA ::0.0.0.9',
        '01234567890.big46.example.com. 21600 IN AAAA ::0.0.0.10',
        '01234567890.big46.example.com. 21600 IN A 192.0.2.220',
        '01234567890.big46.example.com. 21600 IN A 192.0.2.221',
        '01234567890.big46.example.com. 21600 IN A 192.0.2.222',
        '01234567890.big46.example.com. 21600 IN A 192.0.2.223',
        '01234567890.big46.example.com. 21600 IN A 192.0.2.224',
        '01234567890.big46.example.com. 21600 IN A 192.0.2.225',
        '01234567890.big46.example.com. 21600 IN A 192.0.2.226',
        $optrr,
    ],
    stats => [qw/udp_reqs edns udp_edns_big noerror/],
);

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 1, udppacketsize => 657 },
    qname => '012345678901234567890123456789012345678901234567890123456789.012345678901234567890123456789012345678901234567890123456789.012345678901234567890123456789012345678901234567890123456789.big64mx.example.com', qtype => 'MX',
    answer => '012345678901234567890123456789012345678901234567890123456789.012345678901234567890123456789012345678901234567890123456789.012345678901234567890123456789012345678901234567890123456789.big64mx.example.com 21600 IN MX 0 01234567890.big46.example.com',
    addtl => [
        '01234567890.big46.example.com. 21600 IN AAAA ::1',
        '01234567890.big46.example.com. 21600 IN AAAA ::0.0.0.2',
        '01234567890.big46.example.com. 21600 IN AAAA ::0.0.0.3',
        '01234567890.big46.example.com. 21600 IN AAAA ::0.0.0.4',
        '01234567890.big46.example.com. 21600 IN AAAA ::0.0.0.5',
        '01234567890.big46.example.com. 21600 IN AAAA ::0.0.0.6',
        '01234567890.big46.example.com. 21600 IN AAAA ::0.0.0.7',
        '01234567890.big46.example.com. 21600 IN AAAA ::0.0.0.8',
        '01234567890.big46.example.com. 21600 IN AAAA ::0.0.0.9',
        '01234567890.big46.example.com. 21600 IN AAAA ::0.0.0.10',
        '01234567890.big46.example.com. 21600 IN A 192.0.2.220',
        '01234567890.big46.example.com. 21600 IN A 192.0.2.221',
        '01234567890.big46.example.com. 21600 IN A 192.0.2.222',
        '01234567890.big46.example.com. 21600 IN A 192.0.2.223',
        '01234567890.big46.example.com. 21600 IN A 192.0.2.224',
        '01234567890.big46.example.com. 21600 IN A 192.0.2.225',
        '01234567890.big46.example.com. 21600 IN A 192.0.2.226',
        $optrr,
    ],
    stats => [qw/udp_reqs edns udp_edns_big noerror/],
);

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 1, udppacketsize => 656 },
    qname => '012345678901234567890123456789012345678901234567890123456789.012345678901234567890123456789012345678901234567890123456789.012345678901234567890123456789012345678901234567890123456789.big64mx.example.com', qtype => 'MX',
    answer => '012345678901234567890123456789012345678901234567890123456789.012345678901234567890123456789012345678901234567890123456789.012345678901234567890123456789012345678901234567890123456789.big64mx.example.com 21600 IN MX 0 01234567890.big46.example.com',
    addtl => $optrr,
    stats => [qw/udp_reqs edns noerror/],
);

_GDT->test_kill_daemon($pid);
