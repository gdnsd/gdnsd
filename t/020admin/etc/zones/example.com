@	SOA ns1 hostmaster (
	1      ; serial
	7200   ; refresh
	1800   ; retry
	259200 ; expire
        900    ; ncache
)

@		NS	ns1
@		NS	ns2
ns1		A	192.0.2.253
ns2		A	192.0.2.254

$TTL 42
r1	DYNA	simplefo!r1
r2	DYNA	simplefo!r2
m1	DYNC	metafo!m1
m1cname	A	192.0.2.42
ra	DYNA	simplefo!ra
