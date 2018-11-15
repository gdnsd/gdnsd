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

my $_MX = 'foo.compression-torture.foo.example.com 21600 MX';

# compression targets numbered from zero above each new name, and become 'X'
# after we run out of our 16 compression target slots, representing missed
# opportunities to create further compression targets to optimize further names
# against.  The trailing #N shows which previous target is compressed-against
# from that point onwards.  The query name is added as 5 targets at the start:
#           0   1                   2   3       4
#          "foo.compression-torture.foo.example.com"
my $compt_mxset = [
    #                   5   6   7   8   #3
    "${_MX} 0           foo.foo.foo.fox.example.com",
    #                               #8
    "${_MX} 1                       fox.example.com",
    #                   9   10  11  #2
    "${_MX} 2           bar.foo.foo.foo.example.com",
    #                           12  #2
    "${_MX} 3                   fox.foo.example.com",
    #                   13  14   15  X  #3
    "${_MX} 4           foo.fooo.foo.fo.example.com",
    #                           #7
    "${_MX} 5                   foo.fox.example.com",
    #                   X   #10
    "${_MX} 6           fox.foo.foo.foo.example.com",
    #                       #10
    "${_MX} 7               foo.foo.foo.example.com",
    #                   X   X   #11
    "${_MX} 8           foo.fox.foo.foo.example.com",
    #                   X   #10
    "${_MX} 9           foo.foo.foo.foo.example.com",
    #                   X   X   X   X   #3
    "${_MX} 10          foo.foo.foo.bar.example.com",
    #                           #11
    "${_MX} 11                  foo.foo.example.com",
    #                   X  X   X   X    #3
    "${_MX} 12          fo.foo.foo.fooo.example.com",
    #                               #2
    "${_MX} 13                      foo.example.com",
    #          X    X   X   X   X   X   X       X
    "${_MX} 14 asdf.xyz.foo.foo.fox.foo.example.org",
    #                   X   X   X   #2
    "${_MX} 15          foo.foo.bar.foo.example.com",
    #                   X    X   #15
    "${_MX} 16          fooo.foo.foo.fo.example.com",
    #                       X   #12
    "${_MX} 17              foo.fox.foo.example.com",

    # These next two names should, in a perfectly-optimal response, compress
    # more than they do.  However, we ran out of compression target count
    # before we could record the longer names above they could've matched with

    # Could've been:    X   X   X    #16 (from MX 4 above)
    # But instead:      X   X   X    X  #3
    "${_MX} 18          foo.foo.fooo.fo.example.com",
    # Could've been:    X   #42 (from MX 17 above)
    # But instead:      X   X   #12
    "${_MX} 19          foo.foo.fox.foo.example.com",
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
    qname => 'foo.compression-torture.foo.example.com', qtype => 'MX',
    answer => $compt_mxset,
    addtl => $optrr,
    stats => [qw/udp_reqs edns udp_edns_big noerror/],
);
is($size, 569, "Packet size as expected");

_GDT->test_kill_daemon($pid);
