
# Test domainname bytes other than the usual [-a-z0-9]

use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 4;

my $pid = _GDT->test_spawn_daemon();

# DNS's case and compression stuff sucks...
_GDT->test_dns(
    qname => 'FoO.eXaMpLe.CoM', qtype => 'A',
    answer => 'FoO.eXaMpLe.CoM 21600 A 192.0.2.160',
);

# In this case, the case is mixed up in the zonefile, not the query
_GDT->test_dns(
    qname => 'mixed.example.com', qtype => 'MX',
    answer => 'mixed.example.com 21600 MX 0 maxttl.example.com',
    addtl => 'maxttl.example.com 2147483647 A 192.0.2.199',
);

_GDT->test_kill_daemon($pid);
