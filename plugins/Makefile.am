AM_CPPFLAGS = -I$(top_srcdir)/libgdnsd
AM_LIBTOOLFLAGS = --silent

EXTRA_DIST = meta_core.c

pkglib_LTLIBRARIES = \
	plugin_http_status.la \
	plugin_multifo.la \
	plugin_null.la \
	plugin_reflect.la \
	plugin_simplefo.la \
	plugin_static.la \
	plugin_tcp_connect.la \
        plugin_weighted.la \
	plugin_extfile.la \
        plugin_extmon.la \
        plugin_metafo.la \
        plugin_geoip.la

bin_PROGRAMS = gdnsd_geoip_test
noinst_LTLIBRARIES = libextmon_comms.la
pkglibexec_PROGRAMS = gdnsd_extmon_helper

plugin_http_status_la_SOURCES = http_status.c
plugin_http_status_la_LDFLAGS = -avoid-version -module

plugin_multifo_la_SOURCES = multifo.c
plugin_multifo_la_LDFLAGS = -avoid-version -module

plugin_null_la_SOURCES = null.c
plugin_null_la_LDFLAGS = -avoid-version -module

plugin_reflect_la_SOURCES = reflect.c
plugin_reflect_la_LDFLAGS = -avoid-version -module

plugin_simplefo_la_SOURCES = simplefo.c
plugin_simplefo_la_LDFLAGS = -avoid-version -module

plugin_static_la_SOURCES = static.c
plugin_static_la_LDFLAGS = -avoid-version -module

plugin_tcp_connect_la_SOURCES = tcp_connect.c
plugin_tcp_connect_la_LDFLAGS = -avoid-version -module

plugin_weighted_la_SOURCES  = weighted.c
plugin_weighted_la_LDFLAGS  = -avoid-version -module

plugin_extfile_la_SOURCES  = extfile.c
plugin_extfile_la_LDFLAGS  = -avoid-version -module

libextmon_comms_la_SOURCES = extmon_comms.c extmon_comms.h

plugin_extmon_la_SOURCES  = extmon.c extmon_comms.h
plugin_extmon_la_LDFLAGS  = -avoid-version -module
plugin_extmon_la_LIBADD   = libextmon_comms.la

gdnsd_extmon_helper_SOURCES = extmon_helper.c extmon_comms.h
gdnsd_extmon_helper_LDADD   = libextmon_comms.la $(top_builddir)/libgdnsd/libgdnsd.la $(LIBGDNSD_LIBS)
gdnsd_extmon_helper_CFLAGS  = $(CFLAGS_PIE)
gdnsd_extmon_helper_LDFLAGS = $(LDFLAGS_PIE)

plugin_metafo_la_SOURCES  = metafo.c
plugin_metafo_la_LDFLAGS  = -avoid-version -module

plugin_geoip_la_SOURCES  = geoip.c
plugin_geoip_la_CPPFLAGS = -I$(top_srcdir)/libgdmaps $(AM_CPPFLAGS)
plugin_geoip_la_LDFLAGS  = -avoid-version -module
plugin_geoip_la_LIBADD   = $(top_builddir)/libgdmaps/libgdmaps.la

gdnsd_geoip_test_SOURCES  = gdnsd_geoip_test.c
gdnsd_geoip_test_CPPFLAGS = -I$(top_srcdir)/libgdmaps $(AM_CPPFLAGS)
gdnsd_geoip_test_CFLAGS   = $(CFLAGS_PIE)
gdnsd_geoip_test_LDADD    = $(top_builddir)/libgdmaps/libgdmaps.la $(top_builddir)/libgdnsd/libgdnsd.la $(LIBGDNSD_LIBS)
