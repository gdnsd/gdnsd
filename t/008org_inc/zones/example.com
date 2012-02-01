@	SOA ns1 hostmaster (
	1      ; serial
	7200   ; refresh
	1800   ; retry
	259200 ; expire
        900    ; ncache
)

@	NS	ns1
@	ns	ns2.ns1
ns1	A	192.0.2.1
$origin ns1
ns2	a	192.0.2.2

$origin example.com.
www	a	192.0.2.3
$include sub sub
$origin servers
ftp	a	192.0.2.4
$include sub2

