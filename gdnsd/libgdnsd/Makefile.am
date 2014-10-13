pkglib_LTLIBRARIES = libgdnsd.la
AM_LIBTOOLFLAGS = --silent
AM_CPPFLAGS = -I$(builddir)

SUBDIRS = libdmn

xHEADERS_BUILT = gdnsd/dmn.h
xHEADERS_DIST_NOINST = gdnsd/plugapi-priv.h gdnsd/misc-priv.h gdnsd/net-priv.h gdnsd/prcu-priv.h gdnsd/paths-priv.h gdnsd/mon-priv.h
xHEADERS_DIST = gdnsd/vscf.h gdnsd/dname.h gdnsd/log.h gdnsd/compiler.h gdnsd/mon.h gdnsd/stats.h gdnsd/net.h gdnsd/plugapi.h gdnsd/plugin.h gdnsd/misc.h gdnsd/paths.h gdnsd/alloc.h

libgdnsd_la_SOURCES = prcu.c dname.c net.c log.c mon.c vscf.c misc.c paths.c plugapi.c alloc.c $(xHEADERS_DIST) $(xHEADERS_DIST_NOINST)
nodist_libgdnsd_la_SOURCES = $(xHEADERS_BUILT)

libgdnsd_la_LDFLAGS = -shared -avoid-version -export-symbols-regex '^(gdnsd|vscf|dmn)_'
libgdnsd_la_LIBADD  = $(LIBGDNSD_LIBS) libdmn/libdmn.la

libgdnsd_la_pkgincludedir = $(pkgincludedir)
dist_libgdnsd_la_pkginclude_HEADERS = $(xHEADERS_DIST)
nodist_libgdnsd_la_pkginclude_HEADERS = $(xHEADERS_BUILT)

cfg-dirs.h:	Makefile
	$(AM_V_GEN)echo '#define GDNSD_DEFPATH_CONFIG "$(GDNSD_DEFPATH_CONFIG)"' >$@
	@echo '#define GDNSD_DEFPATH_RUN "$(GDNSD_DEFPATH_RUN)"' >>$@
	@echo '#define GDNSD_DEFPATH_STATE "$(GDNSD_DEFPATH_STATE)"' >>$@
	@echo '#define GDNSD_DEFPATH_LIB "$(GDNSD_DEFPATH_LIB)"' >>$@
	@echo '#define GDNSD_DEFPATH_LIBEXEC "$(GDNSD_DEFPATH_LIBEXEC)"' >>$@

BUILT_SOURCES = $(xHEADERS_BUILT) cfg-dirs.h
CLEANFILES = $(builddir)/gdnsd/dmn.h cfg-dirs.h
MAINTAINERCLEANFILES = $(srcdir)/vscf.c

vscf.c:		vscf.rl
	$(AM_V_GEN)$(RAGEL) -T0 -o $(srcdir)/vscf.c $(srcdir)/vscf.rl

gdnsd/dmn.h:	libdmn/dmn.h
	@test -d $(builddir)/gdnsd || mkdir $(builddir)/gdnsd
	$(AM_V_GEN)cp $(srcdir)/libdmn/dmn.h $(builddir)/gdnsd/dmn.h

EXTRA_DIST = $(srcdir)/vscf.rl
