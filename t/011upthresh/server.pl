use HTTP::Daemon;
use HTTP::Status;

my ($portnum, $statef) = @ARGV;

$SIG{PIPE} = 'IGNORE';

my $d = eval { HTTP::Daemon->new(
    LocalAddr => '0.0.0.0',
    LocalPort => $portnum,
    ReuseAddr => 1,
) };
if(!$d || $@) {
    die "Cannot start HTTP::Daemon at address 0.0.0.0:${portnum}: $@"
}

open(my $statefh, '>', $statef);
print $statefh "$$\n";
close($statefh);

while (my $c = $d->accept) {
    while (my $r = $c->get_request) {
        if ($r->method eq 'GET') {
            $c->send_basic_header();
            $c->send_crlf();
            $c->send_crlf();
        }
        else {
            $c->send_error(RC_FORBIDDEN)
        }
    }
    $c->close;
    undef($c);
}
