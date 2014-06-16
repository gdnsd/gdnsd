
AM_CPPFLAGS = -I$(top_builddir)/gdnsd/libgdnsd -I$(top_srcdir)/gdnsd/libgdnsd
AM_LIBTOOLFLAGS = --silent

SUBDIRS = . t

noinst_LTLIBRARIES = libgdmaps.la
libgdmaps_la_LIBADD = $(MATH_LIB)
libgdmaps_la_SOURCES = \
	gdmaps.c \
	gdmaps.h \
	dcinfo.c \
	dcinfo.h \
	dclists.c \
	dclists.h \
	dcmap.c \
	dcmap.h \
	nlist.c \
	nlist.h \
	ntree.c \
	ntree.h \
	nets.c \
	nets.h \
	gdgeoip.c \
	gdgeoip.h \
	fips104.c \
	fips104.h

check-download:
	@$(MAKE) $(AM_MAKEFLAGS) -C t check-download
