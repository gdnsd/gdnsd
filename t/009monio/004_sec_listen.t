
# Basic dynamic resource tests

use _GDT ();
use FindBin ();
use File::Spec ();
use File::Temp qw/tmpnam/;
use Test::More tests => 8;

# We use dns_port_2 as a custom http listener
#  for something to monitor
my $http_port = $_GDT::EXTRA_PORT;
my $state_file = tmpnam();
my $server_script = File::Spec->catfile($FindBin::Bin, 'server.pl');
my $http_pid = fork();
if(!defined $http_pid) { diag "Fork failed: $!"; BAIL_OUT($!); }
if(!$http_pid) { # child, execute test http server
    exec($^X, $server_script, $http_port, $state_file);
}

# Avoid racing the test http server
while(!-f $state_file) {
    select(undef, undef, undef, 0.1); # 100ms
}

unlink($state_file);

my $pid = _GDT->test_spawn_daemon('etc002');

_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.254',
);

_GDT->test_dns(
    qname => 'dyn.example.com', qtype => 'A',
    answer => 'dyn.example.com 60 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'mdyn.example.com', qtype => 'A',
    answer => 'mdyn.example.com 60 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'addtl.example.com', qtype => 'MX',
    answer => 'addtl.example.com 86400 MX 0 dyn.example.com',
    addtl => 'dyn.example.com 60 A 127.0.0.1',
);

_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.254',
);

_GDT->test_kill_daemon($pid);
_GDT->test_kill_daemon($http_pid);

END { kill(9, $http_pid) if($http_pid && kill(0, $http_pid)) }
