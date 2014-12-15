use _GDT ();
use Net::DNS;
use Test::More tests => 12;

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'example.com', qtype => 'SOA',
    answer => 'example.com 86400 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900',
);

_GDT->test_dns(
    qname => 'www.example.com', qtype => 'A',
    answer => 'www.example.com 86400 A 192.0.2.3',
);

_GDT->test_dns(
    qname => 'sub.example.com', qtype => 'A',
    answer => 'sub.example.com 86400 A 192.0.2.100',
);

_GDT->test_dns(
    qname => 'xxx.sub.example.com', qtype => 'A',
    answer => 'xxx.sub.example.com 86400 A 192.0.2.101',
);

_GDT->test_dns(
    qname => 'www.xxx.sub.example.com', qtype => 'A',
    answer => 'www.xxx.sub.example.com 86400 A 192.0.2.102',
);

_GDT->test_dns(
    qname => 'ftp.servers.example.com', qtype => 'A',
    answer => 'ftp.servers.example.com 86400 A 192.0.2.4',
);

_GDT->test_dns(
    qname => 'ftp2.servers.example.com', qtype => 'A',
    answer => 'ftp2.servers.example.com 86400 A 192.0.2.151',
);

_GDT->test_dns(
    qname => 'www.sub2.example.com', qtype => 'A',
    answer => 'www.sub2.example.com 86400 A 192.0.2.200',
);

_GDT->test_dns(
    qname => 'a.ss2.foxes.sub2.example.com', qtype => 'A',
    answer => 'a.ss2.foxes.sub2.example.com 86400 A 192.0.2.240',
);

_GDT->test_dns(
    qname => 'a.b.example.com', qtype => 'A',
    answer => 'a.b.example.com 86400 A 192.0.2.241',
);

_GDT->test_kill_daemon($pid);
