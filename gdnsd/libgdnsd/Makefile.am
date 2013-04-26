
pkglib_LTLIBRARIES = libgdnsd.la
AM_LIBTOOLFLAGS = --silent

xHEADERS_BUILT = gdnsd/dmn.h
xHEADERS_DIST_NOINST = gdnsd/plugapi-priv.h gdnsd/misc-priv.h gdnsd/net-priv.h gdnsd/prcu-priv.h gdnsd/paths-priv.h
xHEADERS_DIST = gdnsd/vscf.h gdnsd/dname.h gdnsd/log.h gdnsd/compiler.h gdnsd/mon.h gdnsd/stats.h gdnsd/net.h gdnsd/plugapi.h gdnsd/plugin.h gdnsd/misc.h gdnsd/paths.h

libgdnsd_la_SOURCES = prcu.c dname.c net.c log.c mon.c vscf.c misc.c paths.c plugapi.c libdmn/dmn_daemon.c libdmn/dmn_log.c libdmn/dmn_secure.c libdmn/dmn_net.c $(xHEADERS_DIST) $(xHEADERS_DIST_NOINST)
nodist_libgdnsd_la_SOURCES = $(xHEADERS_BUILT)

libgdnsd_la_LDFLAGS  = -shared -avoid-version
libgdnsd_la_LIBADD   = $(LIBGDNSD_LIBS)

libgdnsd_la_pkgincludedir = $(pkgincludedir)
dist_libgdnsd_la_pkginclude_HEADERS = $(xHEADERS_DIST)
nodist_libgdnsd_la_pkginclude_HEADERS = $(xHEADERS_BUILT)

BUILT_SOURCES = $(xHEADERS_BUILT)

CLEANFILES = $(builddir)/gdnsd/dmn.h
MAINTAINERCLEANFILES = $(srcdir)/vscf.c

vscf.c:		vscf.rl
	$(AM_V_GEN)$(RAGEL) -T0 -o $(srcdir)/vscf.c $(srcdir)/vscf.rl

gdnsd/dmn.h:	libdmn/dmn.h
	@test -d $(builddir)/gdnsd || mkdir $(builddir)/gdnsd
	$(AM_V_GEN)cp $(srcdir)/libdmn/dmn.h $(builddir)/gdnsd/dmn.h

EXTRA_DIST = $(srcdir)/vscf.rl $(srcdir)/libdmn/*

PODS_3 = gdnsd-plugin-api.pod
include $(top_srcdir)/docs.am
