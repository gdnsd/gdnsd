# Test what happens when a zonefile fails to load at runtime

use _GDT ();
use Test::More tests => 12;

$ENV{USE_ZONES_AUTO} = 1;
my $pid = _GDT->test_spawn_daemon();

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

# create example.org with bad data, sigusr1?, wait on log message, query it
_GDT->insert_altzone('example.org-bad', 'example.org');
_GDT->send_sigusr1_unless_inotify();
_GDT->test_log_output('rfc1035: Zone example.org.: Zonefile parse error');
_GDT->test_dns(
    qname => 'example.org', qtype => 'A',
    header => { rcode => 'REFUSED', aa => 0 },
    stats => [qw/udp_reqs refused/],
);

## create example.org, sigusr1?, wait on log message, query it
_GDT->insert_altzone('example.org', 'example.org');
_GDT->send_sigusr1_unless_inotify();
_GDT->test_log_output('Zone example.org.: source rfc1035:example.org with serial 1 loaded as authoritative');
_GDT->test_dns(
    qname => 'ns1.example.org', qtype => 'A',
    answer => 'ns1.example.org 86400 A 192.0.2.3',
);

# create example.org with bad data, sigusr1?, wait on log message, query it
_GDT->insert_altzone('example.org-bad', 'example.org');
_GDT->send_sigusr1_unless_inotify();
_GDT->test_log_output('rfc1035: Zone example.org.: Zonefile parse error');
# this time runtime keeps the last-valid data
_GDT->test_dns(
    qname => 'ns1.example.org', qtype => 'A',
    answer => 'ns1.example.org 86400 A 192.0.2.3',
);

# create example.org with bad data, sigusr1?, wait on log message, query it
_GDT->insert_altzone('example.org-ooz', 'example.org');
_GDT->send_sigusr1_unless_inotify();
_GDT->test_log_output('rfc1035: Zone example.org.: Zonefile parse error');
# this time runtime keeps the last-valid data
_GDT->test_dns(
    qname => 'ns1.example.org', qtype => 'A',
    answer => 'ns1.example.org 86400 A 192.0.2.3',
);

_GDT->test_kill_daemon($pid);
