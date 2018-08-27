@	SOA ns1 hostmaster (
	1      ; serial
	7200   ; refresh
	1800   ; retry
	259200 ; expire
	900    ; ncache
)

	NS	ns1
ns1	A	192.0.2.42

asdf 	A	192.0.2.44
xyz 	A	192.0.2.45

; not a valid challenge payload, but tests fall-through scenarios
_acme-challenge.exists TXT "abcde"

; for checking ANY-queries and general matching
_acme-challenge.other A 192.0.2.43
