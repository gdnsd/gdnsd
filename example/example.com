
; gdnsd zonefiles are basically RFC1035 compatible

@	SOA ns1 hostmaster (
	1      ; serial
	7200   ; refresh
	1800   ; retry
	259200 ; expire
        900    ; ncache
)

@	NS	ns1	; blank lines (empty or all whitespace) are ignored
ns1	A	192.0.2.1 ; and single-line comments can end any line,
www	A	192.0.2.2 ; as you can see here

; For more information, see "man gdnsd.zonefile"

www	MX	10 mail
mail	A	192.0.2.3

