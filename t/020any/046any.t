use _GDT ();
use Net::DNS;
use Test::More tests => 4;

my $pid = _GDT->test_spawn_daemon();

_GDT->test_dns(
    resopts => { usevc => 0, igntc => 1 },
    qname => 'any.example.com', qtype => 'ANY',
    answer => 'any.example.com 3600 HINFO "RFC8482" ""',
);

_GDT->test_dns(
    resopts => { usevc => 1, igntc => 0 },
    qname => 'any.example.com', qtype => 'ANY',
    answer => 'any.example.com 3600 HINFO "RFC8482" ""',
    stats => [qw/tcp_reqs tcp_conns noerror/],
);

_GDT->test_kill_daemon($pid);
