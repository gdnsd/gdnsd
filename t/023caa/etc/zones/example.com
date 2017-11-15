@	SOA ns1 hostmaster (
	1      ; serial
	7200   ; refresh
	1800   ; retry
	259200 ; expire
	900    ; ncache
)

	NS	ns1

	CAA 0 issue "ca.example.net"
	CAA 128 tbs "Unknown"
	CAA 0 issue "ca.example.org; account=230123"
	CAA 0 issuewild "ca-foo.example.org; xyzzy"
	CAA 0 iodef "mailto:security@example.com"
	CAA 0 iodef "http://iodef.example.com/"

ns1	A	192.0.2.42
