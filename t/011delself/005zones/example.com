
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
del	NS	ns1.del
ns1.del	A	192.0.2.3

subzweb CNAME   www.foo.del.foo.del
subzmx  MX      0       mail.foo.del.foo.del

