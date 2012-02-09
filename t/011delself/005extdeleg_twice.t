
use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 14;

my $pid = _GDT->test_spawn_daemon(File::Spec->catfile($FindBin::Bin, '005gdnsd.conf'));

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
    qname => 'del.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => 'del.example.com 86400 NS ns1.del.example.com',
    addtl => 'ns1.del.example.com 86400 A 192.0.2.3',
);

_GDT->test_dns(
    qname => 'bar.del.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => 'del.example.com 86400 NS ns1.del.example.com',
    addtl => 'ns1.del.example.com 86400 A 192.0.2.3',
);

_GDT->test_dns(
    qname => 'www.foo.del.example.com', qtype => 'A',
    answer => 'www.foo.del.example.com 86400 A 192.0.2.5',
    auth => 'foo.del.example.com 86400 NS ns1.foo.del.example.com',
    addtl => 'ns1.foo.del.example.com 86400 A 192.0.2.4',
);

_GDT->test_dns(
    qname => 'xxx.foo.del.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'foo.del.example.com 86400 SOA ns1.foo.del.example.com hostmaster.foo.del.example.com 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'del.foo.del.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => 'del.foo.del.example.com 86400 NS ns1.del.foo.del.example.com',
    addtl => 'ns1.del.foo.del.example.com 86400 A 192.0.2.6',
);

_GDT->test_dns(
    qname => 'bar.del.foo.del.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => 'del.foo.del.example.com 86400 NS ns1.del.foo.del.example.com',
    addtl => 'ns1.del.foo.del.example.com 86400 A 192.0.2.6',
);

_GDT->test_dns(
    qname => 'www.foo.del.foo.del.example.com', qtype => 'A',
    answer => 'www.foo.del.foo.del.example.com 86400 A 192.0.2.8',
    auth => 'foo.del.foo.del.example.com 86400 NS ns1.foo.del.foo.del.example.com',
    addtl => 'ns1.foo.del.foo.del.example.com 86400 A 192.0.2.7',
);

_GDT->test_dns(
    qname => 'xxx.foo.del.foo.del.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'foo.del.foo.del.example.com 86400 SOA ns1.foo.del.foo.del.example.com hostmaster.foo.del.foo.del.example.com 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'subzweb.example.com', qtype => 'A',
    answer => [
        'subzweb.example.com 86400 CNAME www.foo.del.foo.del.example.com',
        'www.foo.del.foo.del.example.com 86400 A 192.0.2.8',
    ],
    auth => 'foo.del.foo.del.example.com 86400 NS ns1.foo.del.foo.del.example.com',
    addtl => 'ns1.foo.del.foo.del.example.com 86400 A 192.0.2.7',
);

_GDT->test_dns(
    qname => 'subzmx.example.com', qtype => 'MX',
    answer => 'subzmx.example.com 86400 MX 0 mail.foo.del.foo.del.example.com',
    auth => 'example.com 86400 NS ns1.example.com',
    addtl => [
        'mail.foo.del.foo.del.example.com 86400 A 192.0.2.9',
        'ns1.example.com 86400 A 192.0.2.1',
    ],
);


_GDT->test_kill_daemon($pid);
