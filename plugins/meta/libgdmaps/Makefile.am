
AM_CPPFLAGS = -I$(top_builddir)/gdnsd/libgdnsd -I$(top_srcdir)/gdnsd/libgdnsd
AM_LIBTOOLFLAGS = --silent

SUBDIRS = . t

noinst_LTLIBRARIES = libgdmaps.la
libgdmaps_la_SOURCES = gdmaps.c gdmaps.h fips104.c fips104.h

check-download:
	@echo Making check-download in t
	@cd t && $(MAKE) $(AM_MAKEFLAGS) check-download

