
AM_CPPFLAGS = -I$(top_builddir)/gdnsd/libgdnsd -I$(top_srcdir)/gdnsd/libgdnsd
AM_LIBTOOLFLAGS = --silent

pkglib_LTLIBRARIES = plugin_weighted.la
plugin_weighted_la_SOURCES  = weighted.c
plugin_weighted_la_LDFLAGS  = -avoid-version -module
plugin_weighted_la_LIBADD   = $(MATH_LIB)

PODS_8 = gdnsd-plugin-weighted.pod
include $(top_srcdir)/docs.am
