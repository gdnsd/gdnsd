# The point here is to exercise the ztree code a little
#   better re: hash table growth/collisions, etc.
use _GDT ();
use Test::More tests => 102;

my $pid = _GDT->test_spawn_daemon();

foreach my $n (0..99) {
    my $dom = sprintf('%02i.example.com', $n);
    _GDT->test_dns(
        qname => $dom, qtype => 'A',
        answer => "$dom 86400 A 0.0.0.$n",
    );
}

_GDT->test_kill_daemon($pid);
