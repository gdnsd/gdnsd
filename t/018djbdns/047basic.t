use _GDT ();
use Test::More tests => 3;

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'foo.example.com', qtype => 'A',
    answer => 'foo.example.com 86400 A 192.0.2.100',
);

_GDT->test_kill_daemon($pid);
