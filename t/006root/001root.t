
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
    qname => '.', qtype => 'A',
    answer => '. 86400 A 192.0.2.3',
);

_GDT->test_dns(
    qname => 'www', qtype => 'A',
    answer => 'www 86400 A 192.0.2.4',
);

# A .com delegation
_GDT->test_dns(
    qname => 'www.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'com 86400 NS ns1.com',
        'com 86400 NS ns2.com',
    ],
    addtl => [
        'ns1.com 86400 IN A 192.0.2.5',
        'ns2.com 86400 IN A 192.0.2.6',
    ],
);

_GDT->test_kill_daemon($pid);
