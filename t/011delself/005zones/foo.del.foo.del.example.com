
@	SOA ns1 hostmaster (
	1      ; serial
	7200   ; refresh
	30M    ; retry
	3D     ; expire
        900    ; ncache
)

@	NS	ns1
ns1 	A	192.0.2.7
www	A	192.0.2.8
mail	A	192.0.2.9
