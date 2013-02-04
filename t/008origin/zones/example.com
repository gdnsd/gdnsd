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
$origin sub
@	A	192.0.2.100
$origin xxx
@	A	192.0.2.101
www	A	192.0.2.102
$origin example.com.
$origin servers
ftp	a	192.0.2.4
ftp2	A	192.0.2.151
$ORIGIN sub2.example.com.
www	A	192.0.2.200
$ORIGIN foxes
$origin ss2
a	a	192.0.2.240
$ORIGIN b.example.com.
a	a	192.0.2.241
