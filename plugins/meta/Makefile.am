AM_CPPFLAGS = -I$(top_builddir)/gdnsd/libgdnsd -I$(top_srcdir)/gdnsd/libgdnsd -I$(srcdir)/libgdmaps
AM_LIBTOOLFLAGS = --silent

SUBDIRS = libgdmaps

pkglib_LTLIBRARIES = plugin_geoip.la plugin_metafo.la
plugin_geoip_la_SOURCES  = geoip.c
plugin_geoip_la_LDFLAGS  = -avoid-version -module
plugin_geoip_la_LIBADD   = libgdmaps/libgdmaps.la

plugin_metafo_la_SOURCES  = metafo.c
plugin_metafo_la_LDFLAGS  = -avoid-version -module

EXTRA_DIST = meta_core.c

bin_PROGRAMS = gdnsd_geoip_test
gdnsd_geoip_test_SOURCES = gdnsd_geoip_test.c
gdnsd_geoip_test_CFLAGS  = $(CFLAGS_PIE)
gdnsd_geoip_test_LDADD   = libgdmaps/libgdmaps.la $(top_builddir)/gdnsd/libgdnsd/libgdnsd.la $(LIBGDNSD_LIBS)

check-download:
	@$(MAKE) $(AM_MAKEFLAGS) -C libgdmaps check-download
