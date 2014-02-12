
AM_LDFLAGS = -avoid-version -module
AM_CPPFLAGS = -I$(top_srcdir)/gdnsd/libgdnsd -I$(top_builddir)/gdnsd/libgdnsd
AM_LIBTOOLFLAGS = --silent

pkglib_LTLIBRARIES = plugin_null.la plugin_reflect.la plugin_static.la plugin_simplefo.la plugin_multifo.la plugin_http_status.la plugin_tcp_connect.la

plugin_null_la_SOURCES = null.c
plugin_reflect_la_SOURCES = reflect.c
plugin_static_la_SOURCES = static.c
plugin_simplefo_la_SOURCES = simplefo.c
plugin_multifo_la_SOURCES = multifo.c
plugin_multifo_la_LIBADD = $(MATH_LIB)
plugin_http_status_la_SOURCES = http_status.c
plugin_tcp_connect_la_SOURCES = tcp_connect.c

PODS_8 = gdnsd-plugin-simplefo.pod gdnsd-plugin-multifo.pod
include $(top_srcdir)/docs.am
