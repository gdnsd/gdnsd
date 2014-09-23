
# Subzones...

use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 31;

# slow-start on slow-fs for change detection accuracy
delete $ENV{GDNSD_TESTSUITE_NO_ZONEFILE_MODS};

my $pid = _GDT->test_spawn_daemon();

# example.com #1 exists from the start
_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.1',
);

# add (hidden) subzone s1
_GDT->insert_altzone('s1.example.com', 's1.example.com');
_GDT->send_sigusr1_unless_inotify();
_GDT->test_log_output('Zone s1.example.com.: source rfc1035:s1.example.com with serial 1 loaded as authoritative');
_GDT->test_log_output('Zone s1.example.com. was added as a hidden subzone of extant parent example.com.');
_GDT->test_dns(
    qname => 'ns1.s1.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'example.com 900 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);

# add (hidden) subzone s3.s2
_GDT->insert_altzone('s3.s2.example.com', 's3.s2.example.com');
_GDT->send_sigusr1_unless_inotify();
_GDT->test_log_output('Zone s3.s2.example.com.: source rfc1035:s3.s2.example.com with serial 1 loaded as authoritative');
_GDT->test_log_output('Zone s3.s2.example.com. was added as a hidden subzone of extant parent example.com.');
_GDT->test_dns(
    qname => 'ns1.s3.s2.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'example.com 900 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);

# add (hidden) subzone s2
_GDT->insert_altzone('s2.example.com', 's2.example.com');
_GDT->send_sigusr1_unless_inotify();
_GDT->test_log_output('Zone s2.example.com.: source rfc1035:s2.example.com with serial 1 loaded as authoritative');
_GDT->test_log_output('Zone s2.example.com. was added as a hidden subzone of extant parent example.com.');
_GDT->test_dns(
    qname => 'ns1.s2.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'example.com 900 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);

# drop original example.com
_GDT->delete_altzone('example.com');
_GDT->send_sigusr1_unless_inotify();
_GDT->test_log_output('Zone example.com.: authoritative source rfc1035:example.com with serial 1 removed (zone no longer exists)');
_GDT->test_log_output([
    'Zone s2.example.com.: subzone unhidden due to removal of parent zone example.com.',
    'Zone s1.example.com.: subzone unhidden due to removal of parent zone example.com.',
]);

# now s1/s2 are visible
_GDT->test_dns(
    qname => 'ns1.s1.example.com', qtype => 'A',
    answer => 'ns1.s1.example.com 86400 A 192.0.2.71',
);
_GDT->test_dns(
    qname => 'ns1.s2.example.com', qtype => 'A',
    answer => 'ns1.s2.example.com 86400 A 192.0.2.72',
);

# example.com is not
_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    header => { rcode => 'REFUSED', aa => 0 },
    stats => [qw/udp_reqs refused/],
);

# s3.s2 is still hidden, but SOA now comes from s2
_GDT->test_dns(
    qname => 'ns1.s3.s2.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 's2.example.com 900 SOA ns1.s2.example.com hostmaster.s2.example.com 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);

# put example.com back in place, re-hide...
_GDT->insert_altzone('example.com', 'example.com');
_GDT->send_sigusr1_unless_inotify();
_GDT->test_log_output('Zone example.com.: source rfc1035:example.com with serial 1 loaded as authoritative');
_GDT->test_log_output([
    'Zone s1.example.com.: is now a hidden subzone of new parent zone example.com.',
    'Zone s2.example.com.: is now a hidden subzone of new parent zone example.com.',
]);

# example.com is back
_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.1',
);

# s1+s2+s3 all same NXDOMAIN w/ example.com SOA
_GDT->test_dns(
    qname => 'ns1.s1.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'example.com 900 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);
_GDT->test_dns(
    qname => 'ns1.s2.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'example.com 900 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);
_GDT->test_dns(
    qname => 'ns1.s3.s2.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'example.com 900 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);

# now drop s2
_GDT->delete_altzone('s2.example.com');
_GDT->send_sigusr1_unless_inotify();
_GDT->test_log_output('Zone s2.example.com.: authoritative source rfc1035:s2.example.com with serial 1 removed (zone no longer exists)');

# drop example.com again
_GDT->delete_altzone('example.com');
_GDT->send_sigusr1_unless_inotify();
_GDT->test_log_output('Zone example.com.: authoritative source rfc1035:example.com with serial 1 removed (zone no longer exists)');
_GDT->test_log_output([
    'Zone s3.s2.example.com.: subzone unhidden due to removal of parent zone example.com.',
    'Zone s1.example.com.: subzone unhidden due to removal of parent zone example.com.',
]);

# Now only s1 and s3.2 exist, and both should lookup correctly
_GDT->test_dns(
    qname => 'ns1.s1.example.com', qtype => 'A',
    answer => 'ns1.s1.example.com 86400 A 192.0.2.71',
);
_GDT->test_dns(
    qname => 'ns1.s3.s2.example.com', qtype => 'A',
    answer => 'ns1.s3.s2.example.com 86400 A 192.0.2.73',
);

# but s2 and example.com should be REFUSED now
_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    header => { rcode => 'REFUSED', aa => 0 },
    stats => [qw/udp_reqs refused/],
);
_GDT->test_dns(
    qname => 'ns1.s2.example.com', qtype => 'A',
    header => { rcode => 'REFUSED', aa => 0 },
    stats => [qw/udp_reqs refused/],
);

_GDT->test_kill_daemon($pid);
