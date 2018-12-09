use _GDT ();
use Net::DNS;
use Test::More tests => 7;

_GDT->test_spawn_daemon_setup();

my $ext_statedir = $_GDT::OUTDIR . "/var/lib/gdnsd/extfile";
mkdir($ext_statedir)
    or die "mkdir('$_') failed: $!";

_GDT->write_statefile('extfile/extf_m', qq{
    127.0.0.1 => up
    192.0.2.1 => down
});

_GDT->write_statefile('extfile/extf_d', qq{
    127.0.0.1 => down/42
    192.0.2.1 => up/41
});

my $pid = _GDT->test_spawn_daemon_execute();

_GDT->test_dns(
    qname => 'm.example.com', qtype => 'A',
    answer => 'm.example.com 50 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'd.example.com', qtype => 'A',
    answer => 'd.example.com 41 A 192.0.2.1',
);

_GDT->write_statefile('extfile/extf_d', qq{
    127.0.0.1 => up/66
    192.0.2.1 => down/77
});

_GDT->test_log_output(q{plugin_extfile: Service type 'extf_d': loaded new data});

_GDT->test_dns(
    qname => 'd.example.com', qtype => 'A',
    answer => 'd.example.com 66 A 127.0.0.1',
);

_GDT->test_kill_daemon($pid);
