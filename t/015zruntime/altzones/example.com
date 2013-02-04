@ SOA ns1 hostmaster 1 7200 1800 259200 900
@ NS ns1
@ NS ns2
ns1 A 192.0.2.1
ns2 A 192.0.2.2
