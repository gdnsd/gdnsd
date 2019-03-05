use _GDT ();
use Net::DNS;
use Test::More tests => 16;

# all of the gdnsdctl "FAIL" tests are commented-out below due to
# general issues around how we do coverage testing and fatal
# conditions, which needs a broader solution.

my $s = '-s 127.0.0.1:' . $_GDT::EXTRA_PORT;

my $pid = _GDT->test_spawn_daemon('etc_chal');

_GDT->test_dns(
    qname => 'ns1.example.com',
    answer => 'ns1.example.com 86400 A 192.0.2.42',
);

_GDT->test_run_gdnsdctl("$s status");
_GDT->test_dns(
    qname => 'ns1.example.com',
    answer => 'ns1.example.com 86400 A 192.0.2.42',
);

#_GDT->test_run_gdnsdctl("$s replace", 'FAIL');
_GDT->test_dns(
    qname => 'ns1.example.com',
    answer => 'ns1.example.com 86400 A 192.0.2.42',
);

#_GDT->test_run_gdnsdctl("$s reload-zones", 'FAIL');
_GDT->test_dns(
    qname => 'ns1.example.com',
    answer => 'ns1.example.com 86400 A 192.0.2.42',
);

_GDT->test_run_gdnsdctl("$s stats");
_GDT->test_dns(
    qname => 'ns1.example.com',
    answer => 'ns1.example.com 86400 A 192.0.2.42',
);

#_GDT->test_run_gdnsdctl("$s stop", 'FAIL');
_GDT->test_dns(
    qname => 'ns1.example.com',
    answer => 'ns1.example.com 86400 A 192.0.2.42',
);

_GDT->test_run_gdnsdctl("$s acme-dns-01 example.com 0123456789012345678901234567890123456789012");
_GDT->test_dns(
    qname => 'ns1.example.com',
    answer => 'ns1.example.com 86400 A 192.0.2.42',
);

_GDT->test_run_gdnsdctl("$s acme-dns-01-flush");
_GDT->test_dns(
    qname => 'ns1.example.com',
    answer => 'ns1.example.com 86400 A 192.0.2.42',
);

_GDT->test_run_gdnsdctl("$s states");
_GDT->test_dns(
    qname => 'ns1.example.com',
    answer => 'ns1.example.com 86400 A 192.0.2.42',
);

_GDT->test_kill_daemon($pid);
