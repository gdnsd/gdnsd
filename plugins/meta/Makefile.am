
AM_CPPFLAGS = -I$(top_builddir)/gdnsd/libgdnsd -I$(top_srcdir)/gdnsd/libgdnsd -I$(srcdir)/libgdmaps
AM_LIBTOOLFLAGS = --silent

SUBDIRS = libgdmaps

pkglib_LTLIBRARIES = plugin_geoip.la plugin_metafo.la
plugin_geoip_la_SOURCES  = geoip.c
plugin_geoip_la_LDFLAGS  = -avoid-version -module -export-symbols-regex ^plugin_geoip_
plugin_geoip_la_LIBADD   = libgdmaps/libgdmaps.la -lm

plugin_metafo_la_SOURCES  = metafo.c
plugin_metafo_la_LDFLAGS  = -avoid-version -module -export-symbols-regex ^plugin_metafo_

EXTRA_DIST = meta_core.c

check-download:
	@echo Making check-download in libgdmaps
	@cd libgdmaps && $(MAKE) $(AM_MAKEFLAGS) check-download

PODS_8 = gdnsd-plugin-metafo.pod gdnsd-plugin-geoip.pod
include $(top_srcdir)/docs.am
