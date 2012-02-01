
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

# This tests a zone with all of the constructs
#  which are only legal with strict_data = false

use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 10;

my $pid = _GDT->test_spawn_daemon(File::Spec->catfile($FindBin::Bin, 'gdnsd.conf'));

my $soa = 'example.com 86400 SOA foo.example.com hostmaster.example.com 1 7200 1800 259200 604800';

_GDT->test_dns(
    qname => 'abc.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    answer => 'abc.example.com 86400 CNAME foo.example.com',
    auth => $soa,
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'bcd.example.com', qtype => 'A',
    answer => 'bcd.example.com 86400 CNAME bob.example.com',
    auth => $soa,
);

_GDT->test_dns(
    qname => '123.example.com', qtype => 'PTR',
    answer => '123.example.com 86400 PTR foo.example.com',
);

_GDT->test_dns(
    qname => 'cde.example.com', qtype => 'MX',
    answer => 'cde.example.com 86400 MX 0 bob.example.com',
);

_GDT->test_dns(
    qname => 'def.example.com', qtype => 'SRV',
    answer => 'def.example.com 86400 SRV 5 500 80 foo.example.com',
);

_GDT->test_dns(
    qname => 'efg.example.com', qtype => 'NAPTR',
    answer => 'efg.example.com 86400 NAPTR 1 2 "***" "foo" "bar" foo.example.com',
);

_GDT->test_dns(
    qname => 'foobar.subz.example.com', qtype => 'A',
    header => { aa => 0 },
    auth  => 'subz.example.com 86400 NS ns.subz.example.com',
    addtl => 'ns.subz.example.com 300 A 192.0.2.3',
);

_GDT->test_dns(
    qname => 'mxcn.example.com', qtype => 'MX',
    answer => 'mxcn.example.com 86400 MX 0 ns1cn.example.com',
);

_GDT->test_kill_daemon($pid);
