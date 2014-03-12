
use _GDT ();
use FindBin ();
use File::Spec ();
use Net::DNS;
use Test::More tests => 4;

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'm.example.com', qtype => 'A',
    answer => 'm.example.com 50 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'd.example.com', qtype => 'A',
    answer => 'd.example.com 41 A 192.0.2.1',
);

_GDT->test_kill_daemon($pid);
