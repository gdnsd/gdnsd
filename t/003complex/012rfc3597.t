
#    Copyright © 2010 Brandon L Black <blblack@gmail.com>
#
#    This file is part of gdnsd.
#
#    gdnsd is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    gdnsd is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with gdnsd.  If not, see <http://www.gnu.org/licenses/>.
#

# This tests RFC3597-related stuff

use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 5;

my $pid = _GDT->test_spawn_daemon(File::Spec->catfile($FindBin::Bin, 'gdnsd.conf'));

my $t31337_1 = 'rfc3597.example.com 21600 TYPE31337 \# 10 0123456789ABCDEF0123';
my $t31337_2 = 'rfc3597.example.com 21600 TYPE31337 \# 10 3210FEDCBA9876543210';
my $sshfp_1 = 'rfc3597.example.com 21600 SSHFP 1 1 0123456789ABCDEF0123456789ABCDEF01234567';
my $sshfp_2 = 'rfc3597.example.com 21600 SSHFP 2 1 0123456789ABCDEF0123456789ABCDEF01234567';

_GDT->test_dns(
    qname => 'rfc3597.example.com', qtype => 'SSHFP',
    answer => [$sshfp_1, $sshfp_2],
);

_GDT->test_dns(
    qname => 'rfc3597.example.com', qtype => 'TYPE31337',
    answer => [$t31337_1, $t31337_2],
);

_GDT->test_dns(
    qname => 'rfc3597.example.com', qtype => 'ANY',
    answer => [$t31337_1, $t31337_2, $sshfp_1, $sshfp_2],
);

_GDT->test_kill_daemon($pid);
