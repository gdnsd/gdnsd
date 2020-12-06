# Compression torture testing.
# This tests depends on exact packet sizes, so
# it will need to be updated if our compression
# algorithm (as in, the order we scan packets for
# compression targets, etc) changes in order to
# get better compression.
#
# This case was hand-analyzed to make sure it makes sense.

use _GDT ();
use Test::More tests => 4;

my $_MX = 'foo.compression-torture.foo.Example.com 21600 MX';

# Compression targets numbered from zero above each new name.
# The trailing #N shows which previous target is compressed-against
# from that point onwards.
# The query name is added as 5 targets at the start:
#           0   1                   2   3       4
#          "foo.compression-torture.foo.Example.com"
my $compt_mxset = [
    #                   5   6   7   8   #3
    "${_MX} 0           foo.foo.foo.fox.Example.com",
    #                               #8
    "${_MX} 1                       fox.Example.com",
    #                   9   10  11  #2
    "${_MX} 2           bar.foo.foo.foo.Example.com",
    #                           12  #2
    "${_MX} 3                   fox.foo.Example.com",
    #                   13  14   15  16  #3
    "${_MX} 4           foo.fooo.foo.fo.Example.com",
    #                           #7
    "${_MX} 5                   foo.fox.Example.com",
    #                   17  #10
    "${_MX} 6           fox.foo.foo.foo.Example.com",
    #                       #10
    "${_MX} 7               foo.foo.foo.Example.com",
    #                   18  19  #11
    "${_MX} 8           foo.fox.foo.foo.Example.com",
    #                   20  #10
    "${_MX} 9           foo.foo.foo.foo.Example.com",
    #                   21  22  23  24  #3
    "${_MX} 10          foo.foo.foo.bar.Example.com",
    #                           #11
    "${_MX} 11                  foo.foo.Example.com",
    #                   25 26  27  28   #3
    "${_MX} 12          fo.foo.foo.fooo.Example.com",
    #                               #2
    "${_MX} 13                      foo.Example.com",
    #          29   30  31  32  33  34  35      36
    "${_MX} 14 asdf.xyz.foo.foo.fox.foo.example.org",
    #                   37  38  39  #2
    "${_MX} 15          foo.foo.bar.foo.Example.com",
    #                   40   41  #15
    "${_MX} 16          fooo.foo.foo.fo.Example.com",
    #                       42  #12
    "${_MX} 17              foo.fox.foo.Example.com",
    #                   43  44  45   #16
    "${_MX} 18          foo.foo.fooo.fo.Example.com",
    #                   46  #42
    "${_MX} 19          foo.foo.fox.foo.Example.com",
];

my $optrr = Net::DNS::RR->new(
    type => "OPT",
    version => 0,
    name => "",
    size => 1024,
    rcode => 0,
    flags => 0,
);

my $pid = _GDT->test_spawn_daemon();

my $size = _GDT->test_dns(
    resopts => { usevc => 0, igntc => 1, udppacketsize => 1024 },
    qname => 'foo.compression-torture.foo.Example.com', qtype => 'MX',
    answer => $compt_mxset,
    addtl => $optrr,
    stats => [qw/udp_reqs edns udp_edns_big noerror/],
);
is($size, 562, "Packet size as expected");

_GDT->test_kill_daemon($pid);
