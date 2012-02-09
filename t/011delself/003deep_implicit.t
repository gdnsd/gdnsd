
use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 10;

my $pid = _GDT->test_spawn_daemon(File::Spec->catfile($FindBin::Bin, '003gdnsd.conf'));

_GDT->test_dns(
    qname => 'nx.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'example.com 86400 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'www.example.com', qtype => 'A',
    answer => 'www.example.com 86400 A 192.0.2.2',
    auth => 'example.com 86400 NS ns1.example.com',
    addtl => 'ns1.example.com 86400 A 192.0.2.1',
);

_GDT->test_dns(
    qname => 'subzweb.example.com', qtype => 'A',
    answer => [
        'subzweb.example.com 86400 CNAME www.deeper.subz.example.com',
        'www.deeper.subz.example.com 86400 A 192.0.2.4',
    ],
    auth => 'deeper.subz.example.com 86400 NS ns1.deeper.subz.example.com',
    addtl => 'ns1.deeper.subz.example.com 86400 A 192.0.2.3',
);

_GDT->test_dns(
    qname => 'subzmx.example.com', qtype => 'MX',
    answer => 'subzmx.example.com 86400 MX 0 mail.deeper.subz.example.com',
    auth => 'example.com 86400 NS ns1.example.com',
    addtl => [
        'mail.deeper.subz.example.com 86400 A 192.0.2.5',
        'ns1.example.com 86400 A 192.0.2.1',
    ],
);

_GDT->test_dns(
    qname => 'nx.deeper.subz.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'deeper.subz.example.com 86400 SOA ns1.deeper.subz.example.com hostmaster.deeper.subz.example.com 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'www.deeper.subz.example.com', qtype => 'A',
    answer => 'www.deeper.subz.example.com 86400 A 192.0.2.4',
    auth => 'deeper.subz.example.com 86400 NS ns1.deeper.subz.example.com',
    addtl => 'ns1.deeper.subz.example.com 86400 A 192.0.2.3',
);

_GDT->test_dns(
    qname => 'foo.deeper.subz.example.com', qtype => 'MX',
    answer => 'foo.deeper.subz.example.com 86400 MX 0 www.example.com',
    auth => 'deeper.subz.example.com 86400 NS ns1.deeper.subz.example.com',
    addtl => 'ns1.deeper.subz.example.com 86400 A 192.0.2.3',
);

_GDT->test_dns(
    qname => 'bar.deeper.subz.example.com', qtype => 'A',
    answer => 'bar.deeper.subz.example.com 86400 CNAME www.example.com',
);

_GDT->test_kill_daemon($pid);
