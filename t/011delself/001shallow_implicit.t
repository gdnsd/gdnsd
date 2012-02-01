
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

use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 10;

my $pid = _GDT->test_spawn_daemon(File::Spec->catfile($FindBin::Bin, '001gdnsd.conf'));

_GDT->test_dns(
    qname => 'nx.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'example.com 86400 SOA ns1.example.com hostmaster.example.com 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'www.example.com', qtype => 'A',
    answer => 'www.example.com 86400 A 192.0.2.2',
    auth => 'example.com 86400 NS ns1.example.com',
    addtl => 'ns1.example.com 86400 A 192.0.2.1',
);

_GDT->test_dns(
    qname => 'subzweb.example.com', qtype => 'A',
    answer => [
        'subzweb.example.com 86400 CNAME www.subz.example.com',
        'www.subz.example.com 86400 A 192.0.2.4',
    ],
    auth => 'subz.example.com 86400 NS ns1.subz.example.com',
    addtl => 'ns1.subz.example.com 86400 A 192.0.2.3',
);

_GDT->test_dns(
    qname => 'subzmx.example.com', qtype => 'MX',
    answer => 'subzmx.example.com 86400 MX 0 mail.subz.example.com',
    auth => 'example.com 86400 NS ns1.example.com',
    addtl => [
        'mail.subz.example.com 86400 A 192.0.2.5',
        'ns1.example.com 86400 A 192.0.2.1',
    ],
);

_GDT->test_dns(
    qname => 'nx.subz.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'subz.example.com 86400 SOA ns1.subz.example.com hostmaster.subz.example.com 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'www.subz.example.com', qtype => 'A',
    answer => 'www.subz.example.com 86400 A 192.0.2.4',
    auth => 'subz.example.com 86400 NS ns1.subz.example.com',
    addtl => 'ns1.subz.example.com 86400 A 192.0.2.3',
);

_GDT->test_dns(
    qname => 'foo.subz.example.com', qtype => 'MX',
    answer => 'foo.subz.example.com 86400 MX 0 www.example.com',
    auth => 'subz.example.com 86400 NS ns1.subz.example.com',
    addtl => 'ns1.subz.example.com 86400 A 192.0.2.3',
);

_GDT->test_dns(
    qname => 'bar.subz.example.com', qtype => 'A',
    answer => 'bar.subz.example.com 86400 CNAME www.example.com',
);

_GDT->test_kill_daemon($pid);
