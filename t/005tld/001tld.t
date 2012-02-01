
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

# Basic dynamic resource tests

use _GDT ();
use FindBin ();
use File::Spec ();
use Net::DNS;
use Test::More tests => 5;

my $pid = _GDT->test_spawn_daemon(File::Spec->catfile($FindBin::Bin, 'gdnsd.conf'));

_GDT->test_dns(
    qname => 'com', qtype => 'A',
    answer => 'com 43200 A 192.0.2.3',
);

_GDT->test_dns(
    qname => 'www.com', qtype => 'A',
    answer => 'www.com 43200 A 192.0.2.4',
);

# This test covers using an SOA record
#  that isn't the first rrset stored in a node.
_GDT->test_dns(
    qname => 'foo.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'com 43200 SOA ns1.com hostmaster.com 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_kill_daemon($pid);
