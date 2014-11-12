@	SOA foo hostmaster (
	1      ; serial
	7200   ; refresh
	30M    ; retry
	3D     ; expire
        1W     ; ncache
)

@	NS	ns1
ns1 	A	192.0.2.1
joe.bob	A	192.0.2.2

abc	CNAME	foo
bcd	CNAME	bob
123	PTR	foo
cde	MX	0 bob
def	SRV	5 500 80 foo
efg	NAPTR	1 2 "***" "foo" "bar" foo

subz	NS	ns.subz
ns.subz	300	A	192.0.2.3
unused.subz	300	A	192.0.2.4

mxcn	MX	0 ns1cn
ns1cn	CNAME	ns1
