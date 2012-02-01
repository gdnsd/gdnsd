
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
use Test::More tests => 8;

my $pid = _GDT->test_spawn_daemon(File::Spec->catfile($FindBin::Bin, 'gdnsd002.conf'));

_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.254',
);

_GDT->test_dns(
    qname => 'dyn.example.com', qtype => 'A',
    answer => 'dyn.example.com 60 A 192.0.2.1',
);

_GDT->test_dns(
    qname => 'mdyn.example.com', qtype => 'A',
    answer => [
        'mdyn.example.com 60 A 127.0.0.1',
        'mdyn.example.com 60 A 192.0.2.1',
    ]
);

_GDT->test_dns(
    qname => 'mdyn-one.example.com', qtype => 'A',
    answer => [
        'mdyn-one.example.com 60 A 127.0.0.1',
        'mdyn-one.example.com 60 A 192.0.2.1',
    ],
    limit_v4 => 1
);

_GDT->test_dns(
    qname => 'addtl.example.com', qtype => 'MX',
    answer => 'addtl.example.com 86400 MX 0 dyn.example.com',
    addtl => 'dyn.example.com 60 A 192.0.2.1',
);

_GDT->test_dns(
    qname => 'ns1.example.com', qtype => 'A',
    answer => 'ns1.example.com 86400 A 192.0.2.254',
);

_GDT->test_kill_daemon($pid);
