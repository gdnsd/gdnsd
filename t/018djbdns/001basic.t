
use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 3;

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'foo.example.com', qtype => 'A',
    answer => 'foo.example.com 86400 A 192.0.2.100',
    auth => [
        'example.com 86400 NS a.ns.example.com',
        'example.com 86400 NS b.ns.example.com',
    ],
    addtl => [
        'a.ns.example.com 86400 A 192.0.2.1',
        'b.ns.example.com 86400 A 192.0.2.2',
    ],
);

_GDT->test_kill_daemon($pid);
