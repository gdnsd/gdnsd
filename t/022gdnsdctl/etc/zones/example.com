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

; These aren't used directly in tests, but by exercising other RR types
; we increase coverage in ltree_destroy() in case of any bugs in the zone
; destruction there:

asdf1 AAAA ::1
asdf2 NAPTR 123 456 "asdf" "xyz" "foo" bleh.example.net.
asdf3 MX 123 mailserver.example.net.
asfd4 PTR example.net.
asdf5 SRV 123 456 789 svc.example.net.
asdf6 TYPE31337 \# 10 3210FEDCBA 9876543210
asdf7 A 192.0.2.1
      A 192.0.2.2
      A 192.0.2.3
      A 192.0.2.4
      A 192.0.2.5
      A 192.0.2.6
      A 192.0.2.7
      A 192.0.2.8
      A 192.0.2.9
      A 192.0.2.10
