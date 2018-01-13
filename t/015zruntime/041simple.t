# Basic operational and test infrastructure check, just add/delete/mod checks
#   without involving complexities like subzones and duplicates.

use _GDT ();
use Test::More tests => 10;

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

# create example.org, reload zones, query it
_GDT->insert_altzone('example.org', 'example.org');
_GDT->daemon_reload_zones();
_GDT->test_dns(
    qname => 'ns1.example.org', qtype => 'A',
    answer => 'ns1.example.org 86400 A 192.0.2.3',
);

# re-check example.com still sane
_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.1',
);

# update example.com, reload zones, query it
_GDT->insert_altzone('example.com-2', 'example.com');
_GDT->daemon_reload_zones();
_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.12',
);

# delete example.org, reload zones, query it
_GDT->delete_altzone('example.org');
_GDT->daemon_reload_zones();
_GDT->test_dns(
    qname => 'example.org', qtype => 'A',
    header => { rcode => 'REFUSED', aa => 0 },
    stats => [qw/udp_reqs refused/],
);

# re-create example.org with new data, reload zones, query it
_GDT->insert_altzone('example.org-2', 'example.org');
_GDT->daemon_reload_zones();
_GDT->test_dns(
    qname => 'ns1.example.org', qtype => 'A',
    answer => 'ns1.example.org 86400 A 192.0.2.32',
);
# new one also has a reflect plugin result
_GDT->test_dns(
    qname => 'www.example.org', qtype => 'A',
    answer => 'www.example.org 5 A 127.0.0.1',
    v4_only => 1
);

_GDT->test_kill_daemon($pid);
