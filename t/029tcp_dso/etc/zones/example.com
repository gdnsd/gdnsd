@	SOA ns1 hmaster 1 7200 1800 259200 900
@	ns	ns1
@	ns	ns2
ns1	A	192.0.2.1
ns2	A	192.0.2.2
