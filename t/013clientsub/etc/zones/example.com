@	SOA ns1 hostmaster (
	1      ; serial
	7200   ; refresh
	1800   ; retry
	259200 ; expire
        900    ; ncache
)

@		NS	ns1
ns1		A	192.0.2.42

static		A	192.0.2.1
mx		MX	0 reflect-best

$TTL 60
reflect-dns	DYNA	reflect!dns
reflect-edns	DYNA	reflect!edns
reflect-best	DYNA	reflect!best
reflect-both	DYNA	reflect!both
