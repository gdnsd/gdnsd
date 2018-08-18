@	SOA ns1 hostmaster (
	1      ; serial
	7200   ; refresh
	1800   ; retry
	259200 ; expire
        900    ; ncache
)

@	NS	ns1
@	ns	ns2.ns1
$include incl/ns1 ns1
www	a	192.0.2.3
$include incl/sub sub
$origin servers
ftp	a	192.0.2.4
ftp2	A	192.0.2.151
$ORIGIN sub2.@Z
www	A	192.0.2.200
$ORIGIN foxes
$origin ss2
a	a	192.0.2.240
$ORIGIN b.@F
a	a	192.0.2.241
$include incl/zlevel @Z
