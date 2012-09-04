
# Basic operational and test infrastructure check, just add then delete one zone

use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 8;

my $pid = _GDT->test_spawn_daemon(File::Spec->catfile($FindBin::Bin, 'gdnsd.conf'));

# example.com exists from the start
_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.1',
);

# example.org does not
_GDT->test_dns(
    qname => 'example.org', qtype => 'A',
    header => { rcode => 'REFUSED', aa => 0 },
    stats => [qw/udp_reqs refused/],
);

# create example.org, sighup, wait on log message, query it
_GDT->insert_altzone('example.org', 'example.org');
_GDT->send_sighup();
_GDT->test_log_output('Zone example.org.: source rfc1035:example.org with serial 1 loaded as authoritative');
_GDT->test_dns(
    qname => 'ns1.example.org', qtype => 'A',
    answer => 'ns1.example.org 86400 A 192.0.2.3',
);

# delete example.org, sighup, wait on log message, query it
_GDT->delete_altzone('example.org');
_GDT->send_sighup();
_GDT->test_log_output('Zone example.org.: authoritative source rfc1035:example.org with serial 1 removed (zone no longer exists)');
_GDT->test_dns(
    qname => 'example.org', qtype => 'A',
    header => { rcode => 'REFUSED', aa => 0 },
    stats => [qw/udp_reqs refused/],
);

_GDT->test_kill_daemon($pid);
