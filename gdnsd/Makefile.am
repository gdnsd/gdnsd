
SUBDIRS = libgdnsd
AM_CPPFLAGS = -I$(srcdir)/libgdnsd -I$(builddir)/libgdnsd

# How to build gdnsd
sbin_PROGRAMS = gdnsd
gdnsd_SOURCES = main.c conf.c zsrc_djb.c zsrc_djb.h zsrc_rfc1035.c zsrc_rfc1035.h ztree.c ztree.h zscan_rfc1035.c ltarena.c ltree.c dnspacket.c dnsio_udp.c dnsio_tcp.c statio.c monio.c conf.h dnsio_tcp.h dnsio_udp.h dnspacket.h dnswire.h ltarena.h ltree.h statio.h monio.h zscan_rfc1035.h
gdnsd_LDADD = libgdnsd/libgdnsd.la $(LIBGDNSD_LIBS) $(CAPLIBS)

zscan_rfc1035.c:	zscan_rfc1035.rl
	$(AM_V_GEN)$(RAGEL) -G2 -o $(srcdir)/zscan_rfc1035.c $(srcdir)/zscan_rfc1035.rl

MAINTAINERCLEANFILES = $(srcdir)/zscan_rfc1035.c
EXTRA_DIST = $(srcdir)/zscan_rfc1035.rl

PODS_5 = gdnsd.config.pod gdnsd.zonefile.pod
PODS_8 = gdnsd.pod
include $(top_srcdir)/docs.am
