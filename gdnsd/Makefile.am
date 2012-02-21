
# Conditionally use zscan_lm.c instead of zscan.c if
#  --enable-lowmem was passed to configure.
if LOWMEM
ZSCAN_C = zscan_lm.c
else
ZSCAN_C = zscan.c
endif

SUBDIRS = libgdnsd
AM_CPPFLAGS = -I$(srcdir)/libgdnsd -I$(builddir)/libgdnsd

# How to build gdnsd
sbin_PROGRAMS = gdnsd
gdnsd_SOURCES = main.c conf.c $(ZSCAN_C) ltarena.c ltree.c dnspacket.c dnsio_udp.c dnsio_tcp.c statio.c monio.c conf.h dnsio_tcp.h dnsio_udp.h dnspacket.h dnswire.h ltarena.h ltree.h statio.h monio.h gdnsd.h
gdnsd_LDADD = libgdnsd/libgdnsd.la $(CAPLIBS)

zscan.c:	zscan.rl
	$(AM_V_GEN)$(RAGEL) -G2 -o $(srcdir)/zscan.c $(srcdir)/zscan.rl

zscan_lm.c:	zscan.rl
	$(AM_V_GEN)$(RAGEL) -T0 -o $(srcdir)/zscan_lm.c $(srcdir)/zscan.rl

MAINTAINERCLEANFILES = $(srcdir)/zscan.c $(srcdir)/zscan_lm.c
EXTRA_DIST = $(srcdir)/zscan.rl

PODS_5 = gdnsd.config.pod gdnsd.zonefile.pod
PODS_8 = gdnsd.pod
include $(top_srcdir)/docs.am
