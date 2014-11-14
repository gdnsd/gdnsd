AM_CPPFLAGS = -I$(top_srcdir)/libgdnsd

sbin_PROGRAMS = gdnsd
gdnsd_SOURCES = main.c conf.c zsrc_djb.c zsrc_djb.h zscan_djb.c zscan_djb.h zsrc_rfc1035.c zsrc_rfc1035.h ztree.c ztree.h ltarena.c ltree.c dnspacket.c dnsio_udp.c dnsio_tcp.c socks.c statio.c main.h conf.h dnsio_tcp.h dnsio_udp.h socks.h dnspacket.h dnswire.h ltarena.h ltree.h statio.h zscan_rfc1035.h
nodist_gdnsd_SOURCES = zscan_rfc1035.c
gdnsd_LDADD = $(top_builddir)/libgdnsd/libgdnsd.la $(LIBGDNSD_LIBS)
gdnsd_CFLAGS = $(CFLAGS_PIE)
gdnsd_LDFLAGS = $(LDFLAGS_PIE)

zscan_rfc1035.c:	zscan_rfc1035.rl
	$(AM_V_GEN)$(RAGEL) -G2 -o $@ $<

CLEANFILES = zscan_rfc1035.c
EXTRA_DIST = zscan_rfc1035.rl
