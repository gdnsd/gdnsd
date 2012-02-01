
@	SOA ns1 hostmaster (
	1      ; serial
	7200   ; refresh
	30M    ; retry
	3D     ; expire
        900    ; ncache
)

@	NS	ns1
ns1 	A	192.0.2.1
www	A	192.0.2.2
subzweb	CNAME	subz
subzmx	MX	0	subz
subz	NS	subz
subz	A	192.0.2.3
