
# Conditionally use zscan_rfc1035_lm.c instead of zscan_rfc1035.c if
#  --enable-lowmem was passed to configure.
if LOWMEM
ZSCAN_RFC1035_C = zscan_rfc1035_lm.c
else
ZSCAN_RFC1035_C = zscan_rfc1035.c
endif

SUBDIRS = libgdnsd
AM_CPPFLAGS = -I$(srcdir)/libgdnsd -I$(builddir)/libgdnsd

# How to build gdnsd
sbin_PROGRAMS = gdnsd
gdnsd_SOURCES = main.c conf.c zsrc_djb.c zsrc_djb.h zsrc_rfc1035.c zsrc_rfc1035.h ztree.c ztree.h $(ZSCAN_RFC1035_C) ltarena.c ltree.c dnspacket.c dnsio_udp.c dnsio_tcp.c statio.c monio.c conf.h dnsio_tcp.h dnsio_udp.h dnspacket.h dnswire.h ltarena.h ltree.h statio.h monio.h gdnsd.h zscan_rfc1035.h
gdnsd_LDADD = libgdnsd/libgdnsd.la $(QSBRLIBS) $(CAPLIBS)

zscan_rfc1035.c:	zscan_rfc1035.rl
	$(AM_V_GEN)$(RAGEL) -G2 -o $(srcdir)/zscan_rfc1035.c $(srcdir)/zscan_rfc1035.rl

zscan_rfc1035_lm.c:	zscan_rfc1035.rl
	$(AM_V_GEN)$(RAGEL) -T0 -o $(srcdir)/zscan_rfc1035_lm.c $(srcdir)/zscan_rfc1035.rl

MAINTAINERCLEANFILES = $(srcdir)/zscan_rfc1035.c $(srcdir)/zscan_rfc1035_lm.c
EXTRA_DIST = $(srcdir)/zscan_rfc1035.rl

PODS_5 = gdnsd.config.pod gdnsd.zonefile.pod
PODS_8 = gdnsd.pod
include $(top_srcdir)/docs.am
