@	SOA ns1 hostmaster (
	1      ; serial
	7200   ; refresh
	1800   ; retry
	259200 ; expire
	900    ; ncache
)

	NS	ns1
ns1	A	192.0.2.42
