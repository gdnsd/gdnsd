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

$TTL 77
m	DYNA	simplefo!res_extf_m
d	DYNA	simplefo!res_extf_d
