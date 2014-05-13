
use _GDT ();
use FindBin ();
use File::Spec ();
use Net::DNS;
use Test::More tests => 5;

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    qname => 'r1.example.com', qtype => 'A',
    answer => 'r1.example.com 42 A 127.0.0.1',
);

_GDT->write_statefile('admin_state', qq{
    127.*/up => DOWN/33\n
});

_GDT->test_log_output(q{admin_state: state of '127.0.0.1/up' forced from UP/MAX to DOWN/33(FORCED)});

_GDT->test_dns(
    qname => 'r1.example.com', qtype => 'A',
    answer => 'r1.example.com 33 A 192.0.2.1',
);

_GDT->test_kill_daemon($pid);
