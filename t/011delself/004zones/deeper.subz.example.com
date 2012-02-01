
@	SOA ns1 hostmaster (
	1      ; serial
	7200   ; refresh
	30M    ; retry
	3D     ; expire
        900    ; ncache
)

@	NS	ns1
ns1 	A	192.0.2.3
www	A	192.0.2.4
mail	A	192.0.2.5
foo	MX	0	www.example.com.
bar	CNAME	www.example.com.
baz	MX	0	www.subz.example.com.
quux	CNAME	www.subz.example.com.
