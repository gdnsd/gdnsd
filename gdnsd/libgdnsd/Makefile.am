
pkglib_LTLIBRARIES = libgdnsd.la
AM_LIBTOOLFLAGS = --silent

xHEADERS_DIST_NOINST = gdnsd-plugapi-priv.h gdnsd-misc-priv.h gdnsd-net-priv.h
xHEADERS_DIST = gdnsd-vscf.h gdnsd-dname.h gdnsd-log.h gdnsd-compiler.h gdnsd-monio.h gdnsd-satom.h gdnsd-net.h gdnsd-plugapi.h gdnsd-plugin.h gdnsd-misc.h

libgdnsd_la_SOURCES = dname.c net.c log.c monio.c vscf.c misc.c plugapi.c libdmn/dmn_daemon.c libdmn/dmn_log.c libdmn/dmn_secure.c evwrap.c evwrap_ch.h $(xHEADERS_DIST) $(xHEADERS_DIST_NOINST)
nodist_libgdnsd_la_SOURCES = gdnsd-ev.h gdnsd-dmn.h

libgdnsd_la_CPPFLAGS = -I$(srcdir)/libev
libgdnsd_la_LDFLAGS  = -shared -avoid-version
libgdnsd_la_LIBADD   = $(NETLIBS) $(EVLIBS)

libgdnsd_la_includedir = $(includedir)
dist_libgdnsd_la_include_HEADERS = $(xHEADERS_DIST)
nodist_libgdnsd_la_include_HEADERS = gdnsd-ev.h gdnsd-dmn.h

BUILT_SOURCES = gdnsd-ev.h gdnsd-dmn.h

CLEANFILES = $(builddir)/gdnsd-ev.h $(builddir)/gdnsd-dmn.h
MAINTAINERCLEANFILES = $(srcdir)/vscf.c

vscf.c:		vscf.rl
	$(AM_V_GEN)$(RAGEL) -T0 -o $(srcdir)/vscf.c $(srcdir)/vscf.rl

gdnsd-ev.h:	libev/ev.h
	$(AM_V_GEN)cp $(srcdir)/libev/ev.h $(builddir)/gdnsd-ev.h

gdnsd-dmn.h:	libdmn/dmn.h
	$(AM_V_GEN)cp $(srcdir)/libdmn/dmn.h $(builddir)/gdnsd-dmn.h

EXTRA_DIST = $(srcdir)/vscf.rl $(srcdir)/libev/* $(srcdir)/libdmn/*

PODS_3 = gdnsd-plugin-api.pod
include $(top_srcdir)/docs.am
