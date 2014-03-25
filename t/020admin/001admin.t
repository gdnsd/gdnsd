
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

my $state_fn = $_GDT::OUTDIR . "/var/admin_state";
my $state_fn_tmp = $state_fn . ".tmp";
open(my $state_tmpfile, ">$state_fn_tmp")
    or die "Cannot open state file '$state_fn_tmp' for writing: $!";
print $state_tmpfile "127.*/up => DOWN/33\n";
close($state_tmpfile);
rename($state_fn_tmp, $state_fn);

_GDT->test_log_output(q{admin_state: state of '127.0.0.1/up' forced from UP/MAX to DOWN/33(FORCED)});

_GDT->test_dns(
    qname => 'r1.example.com', qtype => 'A',
    answer => 'r1.example.com 33 A 192.0.2.1',
);

_GDT->test_kill_daemon($pid);
