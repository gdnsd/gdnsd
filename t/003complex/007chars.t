
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

# Test domainname bytes other than the usual [-a-z0-9]

use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 4;

my $pid = _GDT->test_spawn_daemon(File::Spec->catfile($FindBin::Bin, 'gdnsd.conf'));

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
