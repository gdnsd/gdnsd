use _GDT ();
use Net::DNS;
use Test::More tests => 2 + (15 * 2);

my $pid = _GDT->test_spawn_daemon();

# Create a symlink in the output zones directory, to exercise loading the
# same data twice via symlink with different zone names and entirely-relative
# contents (plus shared includes), and then ask the daemon to reload zones
my $zones_output_dir = $_GDT::OUTDIR . "/etc/zones";
symlink("${zones_output_dir}/example.com", "${zones_output_dir}/example.org");
_GDT->daemon_reload_zones();

foreach my $tld (qw/com org/) {
    _GDT->test_dns(
        qname => "example.${tld}", qtype => "SOA",
        answer => "example.${tld} 900 SOA ns1.example.${tld} hostmaster.example.${tld} 1 7200 1800 259200 900",
    );

    _GDT->test_dns(
        qname => "www.example.${tld}", qtype => 'A',
        answer => "www.example.${tld} 86400 A 192.0.2.3",
    );

    _GDT->test_dns(
        qname => "sub.example.${tld}", qtype => 'A',
        answer => "sub.example.${tld} 86400 A 192.0.2.100",
    );

    _GDT->test_dns(
        qname => "xxx.sub.example.${tld}", qtype => 'A',
        answer => "xxx.sub.example.${tld} 86400 A 192.0.2.101",
    );

    _GDT->test_dns(
        qname => "www.xxx.sub.example.${tld}", qtype => 'A',
        answer => "www.xxx.sub.example.${tld} 86400 A 192.0.2.102",
    );

    _GDT->test_dns(
        qname => "ftp.servers.example.${tld}", qtype => 'A',
        answer => "ftp.servers.example.${tld} 86400 A 192.0.2.4",
    );

    _GDT->test_dns(
        qname => "ftp2.servers.example.${tld}", qtype => 'A',
        answer => "ftp2.servers.example.${tld} 86400 A 192.0.2.151",
    );

    _GDT->test_dns(
        qname => "www.sub2.example.${tld}", qtype => 'A',
        answer => "www.sub2.example.${tld} 86400 A 192.0.2.200",
    );

    _GDT->test_dns(
        qname => "a.ss2.foxes.sub2.example.${tld}", qtype => 'A',
        answer => "a.ss2.foxes.sub2.example.${tld} 86400 A 192.0.2.240",
    );

    _GDT->test_dns(
        qname => "a.b.example.${tld}", qtype => 'A',
        answer => "a.b.example.${tld} 86400 A 192.0.2.241",
    );

    _GDT->test_dns(
        qname => "zlevel-cf.example.${tld}", qtype => 'CNAME',
        answer => "zlevel-cf.example.${tld} 86400 CNAME example.${tld}",
    );

    _GDT->test_dns(
        qname => "zlevel.example.${tld}", qtype => 'A',
        answer => "zlevel.example.${tld} 86400 A 192.0.2.42",
    );

    _GDT->test_dns(
        qname => "blah.example.${tld}", qtype => 'A',
        answer => "blah.example.${tld} 86400 A 192.0.2.43",
    );

    _GDT->test_dns(
        qname => "bleh.foo.zlevel.example.${tld}", qtype => 'A',
        answer => "bleh.foo.zlevel.example.${tld} 86400 A 192.0.2.44",
    );

    _GDT->test_dns(
        qname => "bluh.foo.zlevel.example.${tld}", qtype => 'A',
        answer => "bluh.foo.zlevel.example.${tld} 86400 A 192.0.2.45",
    );
}

_GDT->test_kill_daemon($pid);
