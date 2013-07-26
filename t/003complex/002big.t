
# Oversized data sets, truncation, tcp, edns0, etc...

use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 14;

my $pid = _GDT->test_spawn_daemon();

$optrr = Net::DNS::RR->new(
    type => "OPT",
    ednsversion => 0,
    name => "",
    class => 1280,
    extendedrcode => 0,
    ednsflags => 0,
);

my $big_answers = [
    'big.example.com 21600 MX 0 asdf.example.com',
    'big.example.com 21600 MX 1 asdff.example.com',
    'big.example.com 21600 MX 2 asdfff.example.com',
    'big.example.com 21600 MX 3 asdffff.example.com',
    'big.example.com 21600 MX 4 asdfffff.example.com',
    'big.example.com 21600 MX 5 asdffffff.example.com',
    'big.example.com 21600 MX 6 asdfffffff.example.com',
    'big.example.com 21600 MX 7 asdffffffff.example.com',
    'big.example.com 21600 MX 8 asdfffffffff.example.com',
    'big.example.com 21600 MX 9 asdffffffffff.example.com',
    'big.example.com 21600 MX 10 asdfffffffffff.example.com',
    'big.example.com 21600 MX 11 asdffffffffffff.example.com',
    'big.example.com 21600 MX 12 asdfffffffffffff.example.com',
    'big.example.com 21600 MX 13 asdffffffffffffff.example.com',
    'big.example.com 21600 MX 14 asdfffffffffffffff.example.com',
    'big.example.com 21600 MX 15 asdffffffffffffffff.example.com',
    'big.example.com 21600 MX 16 asdfffffffffffffffff.example.com',
    'big.example.com 21600 MX 17 asdffffffffffffffffff.example.com',
    'big.example.com 21600 MX 18 asdfffffffffffffffffff.example.com',
    'big.example.com 21600 MX 19 asdffffffffffffffffffff.example.com',
    'big.example.com 21600 MX 20 asdfffffffffffffffffffff.example.com',
];

my $big_additional = [
    'asdf.example.com 21600 A 192.0.2.70',
    'asdff.example.com 21600 A 192.0.2.69',
    'asdfff.example.com 21600 A 192.0.2.68',
    'asdffff.example.com 21600 A 192.0.2.67',
    'asdfffff.example.com 21600 A 192.0.2.66',
    'asdffffff.example.com 21600 A 192.0.2.65',
    'asdfffffff.example.com 21600 A 192.0.2.64',
    'asdffffffff.example.com 21600 A 192.0.2.63',
    'asdfffffffff.example.com 21600 A 192.0.2.62',
    'asdffffffffff.example.com 21600 A 192.0.2.61',
    'asdfffffffffff.example.com 21600 A 192.0.2.60',
    'asdffffffffffff.example.com 21600 A 192.0.2.59',
    'asdfffffffffffff.example.com 21600 A 192.0.2.58',
    'asdffffffffffffff.example.com 21600 A 192.0.2.57',
    'asdfffffffffffffff.example.com 21600 A 192.0.2.56',
    'asdffffffffffffffff.example.com 21600 A 192.0.2.55',
    'asdfffffffffffffffff.example.com 21600 A 192.0.2.54',
    'asdffffffffffffffffff.example.com 21600 A 192.0.2.53',
    'asdfffffffffffffffffff.example.com 21600 A 192.0.2.52',
    'asdffffffffffffffffffff.example.com 21600 A 192.0.2.51',
    'asdfffffffffffffffffffff.example.com 21600 A 192.0.2.50',
];

my $vbig_answers = [
    'vbig.example.com 21600 MX 0 vasdf.example.com',
    'vbig.example.com 21600 MX 1 vasdff.example.com',
    'vbig.example.com 21600 MX 2 vasdfff.example.com',
    'vbig.example.com 21600 MX 3 vasdffff.example.com',
    'vbig.example.com 21600 MX 4 vasdfffff.example.com',
    'vbig.example.com 21600 MX 5 vasdffffff.example.com',
    'vbig.example.com 21600 MX 6 vasdfffffff.example.com',
    'vbig.example.com 21600 MX 7 vasdffffffff.example.com',
    'vbig.example.com 21600 MX 8 vasdfffffffff.example.com',
    'vbig.example.com 21600 MX 9 vasdffffffffff.example.com',
    'vbig.example.com 21600 MX 10 vasdfffffffffff.example.com',
    'vbig.example.com 21600 MX 11 vasdffffffffffff.example.com',
    'vbig.example.com 21600 MX 12 vasdfffffffffffff.example.com',
    'vbig.example.com 21600 MX 13 vasdffffffffffffff.example.com',
    'vbig.example.com 21600 MX 14 vasdfffffffffffffff.example.com',
    'vbig.example.com 21600 MX 15 vasdffffffffffffffff.example.com',
    'vbig.example.com 21600 MX 16 vasdfffffffffffffffff.example.com',
    'vbig.example.com 21600 MX 17 vasdffffffffffffffffff.example.com',
    'vbig.example.com 21600 MX 18 vasdfffffffffffffffffff.example.com',
    'vbig.example.com 21600 MX 19 vasdffffffffffffffffffff.example.com',
    'vbig.example.com 21600 MX 20 vasdfffffffffffffffffffff.example.com',
    'vbig.example.com 21600 MX 21 vasdffffffffffffffffffffff.example.com',
    'vbig.example.com 21600 MX 22 vasdfffffffffffffffffffffff.example.com',
    'vbig.example.com 21600 MX 23 vasdffffffffffffffffffffffff.example.com',
    'vbig.example.com 21600 MX 24 vasdfffffffffffffffffffffffff.example.com',
    'vbig.example.com 21600 MX 25 vasdffffffffffffffffffffffffff.example.com',
    'vbig.example.com 21600 MX 26 vasdfffffffffffffffffffffffffff.example.com',
    'vbig.example.com 21600 MX 27 vasdffffffffffffffffffffffffffff.example.com',
    'vbig.example.com 21600 MX 28 vasdfffffffffffffffffffffffffffff.example.com',
    'vbig.example.com 21600 MX 29 vasdffffffffffffffffffffffffffffff.example.com',
    'vbig.example.com 21600 MX 30 vasdfffffffffffffffffffffffffffffff.example.com',
];

my $vbig_additional = [
    'vasdf.example.com 21600 A 192.0.2.130',
    'vasdff.example.com 21600 A 192.0.2.129',
    'vasdfff.example.com 21600 A 192.0.2.128',
    'vasdffff.example.com 21600 A 192.0.2.127',
    'vasdfffff.example.com 21600 A 192.0.2.126',
    'vasdffffff.example.com 21600 A 192.0.2.125',
    'vasdfffffff.example.com 21600 A 192.0.2.124',
    'vasdffffffff.example.com 21600 A 192.0.2.123',
    'vasdfffffffff.example.com 21600 A 192.0.2.122',
    'vasdffffffffff.example.com 21600 A 192.0.2.121',
    'vasdfffffffffff.example.com 21600 A 192.0.2.120',
    'vasdffffffffffff.example.com 21600 A 192.0.2.119',
    'vasdfffffffffffff.example.com 21600 A 192.0.2.118',
    'vasdffffffffffffff.example.com 21600 A 192.0.2.117',
    'vasdfffffffffffffff.example.com 21600 A 192.0.2.116',
    'vasdffffffffffffffff.example.com 21600 A 192.0.2.115',
    'vasdfffffffffffffffff.example.com 21600 A 192.0.2.114',
    'vasdffffffffffffffffff.example.com 21600 A 192.0.2.113',
    'vasdfffffffffffffffffff.example.com 21600 A 192.0.2.112',
    'vasdffffffffffffffffffff.example.com 21600 A 192.0.2.111',
    'vasdfffffffffffffffffffff.example.com 21600 A 192.0.2.110',
    'vasdffffffffffffffffffffff.example.com 21600 A 192.0.2.109',
    'vasdfffffffffffffffffffffff.example.com 21600 A 192.0.2.108',
    'vasdffffffffffffffffffffffff.example.com 21600 A 192.0.2.107',
    'vasdfffffffffffffffffffffffff.example.com 21600 A 192.0.2.106',
    'vasdffffffffffffffffffffffffff.example.com 21600 A 192.0.2.105',
    'vasdfffffffffffffffffffffffffff.example.com 21600 A 192.0.2.104',
    'vasdffffffffffffffffffffffffffff.example.com 21600 A 192.0.2.103',
    'vasdfffffffffffffffffffffffffffff.example.com 21600 A 192.0.2.102',
    'vasdffffffffffffffffffffffffffffff.example.com 21600 A 192.0.2.101',
    'vasdfffffffffffffffffffffffffffffff.example.com 21600 A 192.0.2.100',
];

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 1, udppacketsize => 512 },
    qname => 'big.example.com', qtype => 'MX',
    header => { tc => 1 },
    stats => [qw/udp_reqs udp_tc noerror/],
);

_GDT->test_dns(
    resopts => { usevc => 1, igntc => 0, udppacketsize => 512 },
    qname => 'big.example.com', qtype => 'MX',
    answer => $big_answers,
    addtl => $big_additional,
    stats => [qw/tcp_reqs noerror/],
);

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 0, udppacketsize => 512 },
    qname => 'big.example.com', qtype => 'MX',
    answer => $big_answers,
    addtl => $big_additional,
    stats => [qw/udp_reqs udp_tc tcp_reqs noerror noerror/],
);

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 1, udppacketsize => 1200 },
    qname => 'big.example.com', qtype => 'MX',
    answer => $big_answers,
    addtl => [@$big_additional, $optrr],
    stats => [qw/udp_reqs edns udp_edns_big noerror/],
);

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 1, udppacketsize => 600 },
    qname => 'big.example.com', qtype => 'MX',
    header => { tc => 1 },
    addtl => $optrr,
    stats => [qw/udp_reqs edns udp_edns_tc noerror/],
);

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 0, udppacketsize => 600 },
    qname => 'big.example.com', qtype => 'MX',
    answer => $big_answers,
    addtl => [@$big_additional, $optrr],
    stats => [qw/udp_reqs udp_edns_tc tcp_reqs edns edns noerror noerror/],
);

# Now all of the above again, but for vbig:
_GDT->test_dns(
    resopts => { usevc => 0, igntc => 1, udppacketsize => 512 },
    qname => 'vbig.example.com', qtype => 'MX',
    header => { tc => 1 },
    stats => [qw/udp_reqs udp_tc noerror/],
);

_GDT->test_dns(
    resopts => { usevc => 1, igntc => 0, udppacketsize => 512 },
    qname => 'vbig.example.com', qtype => 'MX',
    answer => $vbig_answers,
    addtl => $vbig_additional,
    stats => [qw/tcp_reqs noerror/],
);

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 0, udppacketsize => 512 },
    qname => 'vbig.example.com', qtype => 'MX',
    answer => $vbig_answers,
    addtl => $vbig_additional,
    stats => [qw/udp_reqs udp_tc tcp_reqs noerror noerror/],
);

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 1, udppacketsize => 2560 },
    qname => 'vbig.example.com', qtype => 'MX',
    answer => $vbig_answers,
    addtl => [@$vbig_additional, $optrr],
    stats => [qw/udp_reqs edns udp_edns_big noerror/],
);

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 1, udppacketsize => 900 },
    qname => 'vbig.example.com', qtype => 'MX',
    header => { tc => 1 },
    addtl => $optrr,
    stats => [qw/udp_reqs edns udp_edns_tc noerror/],
);

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 0, udppacketsize => 900 },
    qname => 'vbig.example.com', qtype => 'MX',
    answer => $vbig_answers,
    addtl => [@$vbig_additional, $optrr],
    stats => [qw/udp_reqs udp_edns_tc tcp_reqs edns edns noerror noerror/],
);

_GDT->test_kill_daemon($pid);
