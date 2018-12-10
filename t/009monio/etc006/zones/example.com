@	SOA ns1 hostmaster (
	1      ; serial
	7200   ; refresh
	1800   ; retry
	259200 ; expire
        900    ; ncache
)

@		NS	ns1
ns1		A	192.0.2.254

addtl		MX	0 dyn
dyn	120	DYNA	simplefo!dyn_xmpl
mdyn	120	DYNA	multifo!multi_xmpl
