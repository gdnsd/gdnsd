# Duplicates and serial-number sorting...

use _GDT ();
use Test::More tests => 13;

$ENV{USE_ZONES_AUTO} = 1;
my $pid = _GDT->test_spawn_daemon();

# example.com #1 exists from the start
_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.1',
);

# insert 3rd variant of example.com as EXAMPLE.COM
_GDT->insert_altzone('example.com-3', '\069xample.com');
_GDT->send_sigusr1_unless_inotify();
_GDT->test_log_output('Zone example.com.: source rfc1035:\069xample.com with serial 3 loaded as authoritative (supersedes extant source rfc1035:example.com with serial 1)');
_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.13',
);

# insert 2rd variant of example.com as Example.Com
#  (since serial is lower, will have no effect on query...)
_GDT->insert_altzone('example.com-2', 'example.\067om');
_GDT->send_sigusr1_unless_inotify();
_GDT->test_log_output('Zone example.com.: source rfc1035:example.\067om with serial 2 loaded (but is hidden by extant source rfc1035:\069xample.com with serial 3)');
_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.13',
);

# Delete #3, exposing #2
_GDT->delete_altzone('\069xample.com');
_GDT->send_sigusr1_unless_inotify();
_GDT->test_log_output('Zone example.com.: authoritative source rfc1035:\069xample.com with serial 3 removed (extant source rfc1035:example.\067om with serial 2 promoted to authoritative)');
_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.12',
);

# Delete #2, exposing #1
_GDT->delete_altzone('example.\067om');
_GDT->send_sigusr1_unless_inotify();
_GDT->test_log_output('Zone example.com.: authoritative source rfc1035:example.\067om with serial 2 removed (extant source rfc1035:example.com with serial 1 promoted to authoritative)');
_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.1',
);

# Delete #1, nothing left
_GDT->delete_altzone('example.com');
_GDT->send_sigusr1_unless_inotify();
_GDT->test_log_output('Zone example.com.: authoritative source rfc1035:example.com with serial 1 removed (zone no longer exists)');
_GDT->test_dns(
    qname => 'example.com', qtype => 'A',
    header => { rcode => 'REFUSED', aa => 0 },
    stats => [qw/udp_reqs refused/],
);

_GDT->test_kill_daemon($pid);
