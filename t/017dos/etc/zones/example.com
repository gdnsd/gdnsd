; This file intentionally has dos-style line endings,
;   which must be preserved!

  ; You can start a one-line comment anywhere reasonable

; blank for the SOA is intended here, to test that it
;  uses the origin instead of causing a problem..

	SOA ns1 hostmaster (
	1      ; serial
	7200   ; refresh
	30M    ; retry
	3D     ; expire
        900    ; ncache
)

www	3600	A	192.0.2.1 ; (that includes the
www	1H	A	192.0.2.2 ; ends of lines,
www	3600	A	192.0.2.3 ; obviously)
@	1111	PTR	foo.example.org.
@	3600	MX	42 ns1.example.com.
@	3600	MX	44 foo
@	IN 86400 NS	ns1
	86400	NS	ns2
	IN NS	ns3.goober
	86400 IN NS	ns4.goober
foo	515	A	192.0.2.4

alias	CNAME	www

ns1	 	A 	 192.0.2.5
ns2 A 192.0.2.6

ns3.goober	A	192.0.2.7
ns4.goober	A	192.0.2.8

_http._tcp	2W	srv	5 500 80 www

@	TXT	"foo bar baz" "asdf 123 123 foo"
@	SPF	"real spf record" "goes here"
x.y.z	TXT	"\010\000\0259 some complicated stuff here \"\"\"\\"	"asdf""xyz
"

_spf	SPF+	"How convenient"

9.2.0.192	PTR	foo
		PTR	ns2 ; namerepeat by using blank left-hand-side name
