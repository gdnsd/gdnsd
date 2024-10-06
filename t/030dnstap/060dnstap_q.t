#
# This tests dnstap only queries logging
#

use Data::Dumper qw(Dumper);
use Test::More tests => 5;

my $USEDNSTAP = $ENV{USE_DNSTAP};
print "USE_DNSTAP = $USEDNSTAP \n";
if($USEDNSTAP ne "yes") {
    ok(1);
    ok(1);
    ok(1);
    ok(1);
    print "dnstap not enabled, test skipped";
    exit;
}

my $out_dir = $ENV{TESTOUT_DIR};
print "test out dir = $out_dir \n";

my $child_pid = fork();

if(!$child_pid){
    print "Hello from child \n";
    exec("dnstap -u $out_dir/060capture.tap > $out_dir/060capture.out; rm -f $out_dir/060capture.*");
} else {
    print "Hello from parent $child_pid \n";

    BEGIN { use_ok("_GDT") or diag("Test suite broken (no _GDT)"); }

    my $pid = _GDT->test_spawn_daemon('etc_q');

    _GDT->test_dns(
        qname => 'ns1.example.com',
        answer => 'ns1.example.com 86400 A 192.0.2.42',
    );

    _GDT->test_kill_daemon($pid);

    my $dnstap_output = `cat $out_dir/060capture.out`;
    
    my @expected = ("AQ 127.0.0.1 UDP 33b \"ns1.example.com.\" IN A",
                    "AQ ::1 UDP 33b \"ns1.example.com.\" IN A");

    if(_GDT->match_dnstap_output($dnstap_output, \@expected) == 1){
        ok(1);
    } else {
        ok(0);
    }

    my $dnstap_pid = `ps -o pid= --ppid $child_pid`;
    print("dnstap pid = $dnstap_pid");
    exec("kill -9 $dnstap_pid");
}
