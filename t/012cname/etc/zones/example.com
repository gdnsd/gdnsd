@	SOA ns1 hmaster.example.net. (
	1      ; serial
	7200   ; refresh
	1800   ; retry
	259200 ; expire
        900    ; ncache
)

@		NS	ns1
@		NS	ns2
ns1		A	192.0.2.1
ns2		A	192.0.2.2

subz		NS	ns1.subz
subz		NS	ns2.subz
ns1.subz	A	192.0.2.10
ns2.subz	A	192.0.2.20

cn-nx		CNAME	nx
cn-local	CNAME	ns1
cn-deleg	CNAME	foo.subz
cn-deleg-glue	CNAME	ns1.subz
cn-ext		CNAME	www.example.net.
