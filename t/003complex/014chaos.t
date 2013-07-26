
# test chaos_response option

use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 5;

my $pid = _GDT->test_spawn_daemon();

my $chaos1 = Net::DNS::Packet->new();
$chaos1->push('question', Net::DNS::Question->new('example.com', 'TXT', 'CH'));
_GDT->test_dns(
    qpacket => $chaos1,
    header => { aa => 0 },
    answer => 'example.com CH TXT "some random string"',
);

my $chaos2 = Net::DNS::Packet->new();
$chaos2->push('question', Net::DNS::Question->new('.', 'A', 'CH'));
_GDT->test_dns(
    qpacket => $chaos2,
    header => { aa => 0 },
    answer => '. CH TXT "some random string"',
);

my $chaos3 = Net::DNS::Packet->new();
$chaos3->push('question', Net::DNS::Question->new('abc.def.ghi.jkl.mno.pqr', 'PTR', 'CH'));
_GDT->test_dns(
    qpacket => $chaos3,
    header => { aa => 0 },
    answer => 'abc.def.ghi.jkl.mno.pqr CH TXT "some random string"',
);

_GDT->test_kill_daemon($pid);
