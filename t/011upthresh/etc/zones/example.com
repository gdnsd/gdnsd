@	SOA ns1 hostmaster (
	1      ; serial
	7200   ; refresh
	1800   ; retry
	259200 ; expire
        900    ; ncache
)

@		NS	ns1
ns1		A	192.0.2.254

m4d   DYNA multifo!multi_4dead
m3dn  DYNA multifo!multi_3dead_normal
m3dl  DYNA multifo!multi_3dead_lowthresh
wlow  DYNA weighted!w_low
wnorm DYNA weighted!w_norm
mmih  DYNA metafo!meta_multi_ignore_health
