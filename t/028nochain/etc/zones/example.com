@	SOA ns1 hm 1 1 1 1 1
@	NS ns1
ns1	A	192.0.2.1
cn2	CNAME	cn1
cn1	CNAME	ns1
