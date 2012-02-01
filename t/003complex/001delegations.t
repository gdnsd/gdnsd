
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

# This tests various forms of subzone delegation

use _GDT ();
use FindBin ();
use File::Spec ();
use Test::More tests => 26;

my $pid = _GDT->test_spawn_daemon(File::Spec->catfile($FindBin::Bin, 'gdnsd.conf'));

_GDT->test_dns(
    qname => 'subeasy.example.com', qtype => 'NS',
    header => { aa => 0 },
    auth => [
        'subeasy.example.com 21600 NS subeasyns1.example.com',
        'subeasy.example.com 21600 NS subeasyns2.example.com',
    ],
    addtl => [
        'subeasyns1.example.com 21600 A 192.0.2.3',
        'subeasyns2.example.com 21600 A 192.0.2.4',
    ]
);

_GDT->test_dns(
    qname => 'subeasy.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subeasy.example.com 21600 NS subeasyns1.example.com',
        'subeasy.example.com 21600 NS subeasyns2.example.com',
    ],
    addtl => [
        'subeasyns1.example.com 21600 A 192.0.2.3',
        'subeasyns2.example.com 21600 A 192.0.2.4',
    ]
);

_GDT->test_dns(
    qname => 'foo.subeasy.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subeasy.example.com 21600 NS subeasyns1.example.com',
        'subeasy.example.com 21600 NS subeasyns2.example.com',
    ],
    addtl => [
        'subeasyns1.example.com 21600 A 192.0.2.3',
        'subeasyns2.example.com 21600 A 192.0.2.4',
    ]
);

_GDT->test_dns(
    qname => 'subhard.example.com', qtype => 'NS',
    header => { aa => 0 },
    auth => [
        'subhard.example.com 21600 NS ns1.subhard.example.com',
        'subhard.example.com 21600 NS ns2.subhard.example.com',
    ],
    addtl => [
        'ns1.subhard.example.com 21600 A 192.0.2.5',
        'ns1.subhard.example.com 21600 A 192.0.2.55',
        'ns2.subhard.example.com 21600 A 192.0.2.6',
    ]
);

_GDT->test_dns(
    qname => 'subhard.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subhard.example.com 21600 NS ns1.subhard.example.com',
        'subhard.example.com 21600 NS ns2.subhard.example.com',
    ],
    addtl => [
        'ns1.subhard.example.com 21600 A 192.0.2.5',
        'ns1.subhard.example.com 21600 A 192.0.2.55',
        'ns2.subhard.example.com 21600 A 192.0.2.6',
    ]
);

_GDT->test_dns(
    qname => 'foo.subhard.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subhard.example.com 21600 NS ns1.subhard.example.com',
        'subhard.example.com 21600 NS ns2.subhard.example.com',
    ],
    addtl => [
        'ns1.subhard.example.com 21600 A 192.0.2.5',
        'ns1.subhard.example.com 21600 A 192.0.2.55',
        'ns2.subhard.example.com 21600 A 192.0.2.6',
    ]
);

_GDT->test_dns(
    qname => 'subext.example.com', qtype => 'NS',
    header => { aa => 0 },
    auth => [
        'subext.example.com 21600 NS ns-subext1.example.net',
        'subext.example.com 21600 NS ns-subext2.example.net',
    ],
);

_GDT->test_dns(
    qname => 'subext.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subext.example.com 21600 NS ns-subext1.example.net',
        'subext.example.com 21600 NS ns-subext2.example.net',
    ],
);

_GDT->test_dns(
    qname => 'foo.subext.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subext.example.com 21600 NS ns-subext1.example.net',
        'subext.example.com 21600 NS ns-subext2.example.net',
    ],
);

_GDT->test_dns(
    qname => 'subsemiext.example.com', qtype => 'NS',
    header => { aa => 0 },
    auth => [
        'subsemiext.example.com 21600 NS ns1.example.org',
        'subsemiext.example.com 21600 NS ns2.example.org',
    ],
    addtl => [
        'ns1.example.org 43200 A 192.0.2.200',
        'ns2.example.org 43200 A 192.0.2.201',
    ],
);

_GDT->test_dns(
    qname => 'subsemiext.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subsemiext.example.com 21600 NS ns1.example.org',
        'subsemiext.example.com 21600 NS ns2.example.org',
    ],
    addtl => [
        'ns1.example.org 43200 A 192.0.2.200',
        'ns2.example.org 43200 A 192.0.2.201',
    ],
);

_GDT->test_dns(
    qname => 'foo.subsemiext.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subsemiext.example.com 21600 NS ns1.example.org',
        'subsemiext.example.com 21600 NS ns2.example.org',
    ],
    addtl => [
        'ns1.example.org 43200 A 192.0.2.200',
        'ns2.example.org 43200 A 192.0.2.201',
    ],
);

_GDT->test_dns(
    qname => 'subfubar.example.com', qtype => 'NS',
    header => { aa => 0 },
    auth => [
        'subfubar.example.com 21600 NS subeasyns1.example.com',
        'subfubar.example.com 21600 NS ns1.subfubar.example.com',
        'subfubar.example.com 21600 NS ns-subfubar1.example.net',
        'subfubar.example.com 21600 NS ns1.example.org',
    ],
    addtl => [
        'ns1.subfubar.example.com 21600 A 192.0.2.9',
        'subeasyns1.example.com 21600 A 192.0.2.3',
        'ns1.example.org 43200 A 192.0.2.200',
    ],
);

_GDT->test_dns(
    qname => 'subfubar.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subfubar.example.com 21600 NS subeasyns1.example.com',
        'subfubar.example.com 21600 NS ns1.subfubar.example.com',
        'subfubar.example.com 21600 NS ns-subfubar1.example.net',
        'subfubar.example.com 21600 NS ns1.example.org',
    ],
    addtl => [
        'ns1.subfubar.example.com 21600 A 192.0.2.9',
        'subeasyns1.example.com 21600 A 192.0.2.3',
        'ns1.example.org 43200 A 192.0.2.200',
    ],
);

_GDT->test_dns(
    qname => 'foo.subfubar.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subfubar.example.com 21600 NS subeasyns1.example.com',
        'subfubar.example.com 21600 NS ns1.subfubar.example.com',
        'subfubar.example.com 21600 NS ns-subfubar1.example.net',
        'subfubar.example.com 21600 NS ns1.example.org',
    ],
    addtl => [
        'ns1.subfubar.example.com 21600 A 192.0.2.9',
        'subeasyns1.example.com 21600 A 192.0.2.3',
        'ns1.example.org 43200 A 192.0.2.200',
    ],
);

_GDT->test_dns(
    qname => 'subfubar.x.y.z.example.com', qtype => 'NS',
    header => { aa => 0 },
    auth => [
        'subfubar.x.y.z.example.com 21600 NS subeasyns1.example.com',
        'subfubar.x.y.z.example.com 21600 NS ns1.subfubar.x.y.z.example.com',
        'subfubar.x.y.z.example.com 21600 NS ns-subfubarxyz1.example.net',
        'subfubar.x.y.z.example.com 21600 NS ns1.example.org',
    ],
    addtl => [
        'ns1.subfubar.x.y.z.example.com 21600 A 192.0.2.11',
        'subeasyns1.example.com 21600 A 192.0.2.3',
        'ns1.example.org 43200 A 192.0.2.200',
    ],
);

_GDT->test_dns(
    qname => 'subfubar.x.y.z.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subfubar.x.y.z.example.com 21600 NS subeasyns1.example.com',
        'subfubar.x.y.z.example.com 21600 NS ns1.subfubar.x.y.z.example.com',
        'subfubar.x.y.z.example.com 21600 NS ns-subfubarxyz1.example.net',
        'subfubar.x.y.z.example.com 21600 NS ns1.example.org',
    ],
    addtl => [
        'ns1.subfubar.x.y.z.example.com 21600 A 192.0.2.11',
        'subeasyns1.example.com 21600 A 192.0.2.3',
        'ns1.example.org 43200 A 192.0.2.200',
    ],
);

_GDT->test_dns(
    qname => 'foo.subfubar.x.y.z.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subfubar.x.y.z.example.com 21600 NS subeasyns1.example.com',
        'subfubar.x.y.z.example.com 21600 NS ns1.subfubar.x.y.z.example.com',
        'subfubar.x.y.z.example.com 21600 NS ns-subfubarxyz1.example.net',
        'subfubar.x.y.z.example.com 21600 NS ns1.example.org',
    ],
    addtl => [
        'ns1.subfubar.x.y.z.example.com 21600 A 192.0.2.11',
        'subeasyns1.example.com 21600 A 192.0.2.3',
        'ns1.example.org 43200 A 192.0.2.200',
    ],
);

_GDT->test_dns(
    qname => 'x.y.z.example.com', qtype => 'A',
    auth => 'example.com 21600 SOA ns1.example.com hmaster.example.net 1 7200 1800 259200 900',
);

_GDT->test_dns(
    qname => 'foo.y.z.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'example.com 21600 SOA ns1.example.com hmaster.example.net 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'foo.x.y.z.example.com', qtype => 'A',
    header => { rcode => 'NXDOMAIN' },
    auth => 'example.com 21600 SOA ns1.example.com hmaster.example.net 1 7200 1800 259200 900',
    stats => [qw/udp_reqs nxdomain/],
);

_GDT->test_dns(
    qname => 'foo.subselfglue.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => 'subselfglue.example.com 21600 NS subselfglue.example.com',
    addtl => 'subselfglue.example.com 21600 A 192.0.2.12',
);

_GDT->test_dns(
    qname => 'www.subooz.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'subooz.example.com 21600 NS ns1.example.net',
        'subooz.example.com 21600 NS ns2.example.net',
    ],
    addtl => [
        'ns1.example.net 21600 A 192.0.2.77',
        'ns2.example.net 21600 A 192.0.2.78',
    ],
);

_GDT->test_dns(
    qname => 'www.submixooz.example.com', qtype => 'A',
    header => { aa => 0 },
    auth => [
        'submixooz.example.com 21600 NS ns1.example.net',
        'submixooz.example.com 21600 NS ns1.submixooz.example.com',
    ],
    addtl => [
        'ns1.example.net 21600 A 192.0.2.77',
        'ns1.submixooz.example.com 21600 A 192.0.2.79',
    ],
);

_GDT->test_kill_daemon($pid);
