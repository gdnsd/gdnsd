#
# This tests that the test infrastructure basically works,
#  and that we can spawn a gdnsd instance with an absolutely
#  minimal configuration and get it to succesfully answer the
#  easiest query imaginable.
#
#  There is a lot more verbosity in this test than will be
#  required in the later ones, to test basic assumptions.
#

use Test::More tests => 4;
BEGIN { use_ok("_GDT") or diag("Test suite broken (no _GDT)"); }

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'ns1.example.com',
    answer => 'ns1.example.com 86400 A 192.0.2.42',
);

_GDT->test_kill_daemon($pid);
