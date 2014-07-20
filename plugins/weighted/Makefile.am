AM_CPPFLAGS = -I$(top_builddir)/gdnsd/libgdnsd -I$(top_srcdir)/gdnsd/libgdnsd
AM_LIBTOOLFLAGS = --silent

pkglib_LTLIBRARIES = plugin_weighted.la
plugin_weighted_la_SOURCES  = weighted.c
plugin_weighted_la_LDFLAGS  = -avoid-version -module -export-symbols-regex ^plugin_weighted_
plugin_weighted_la_LIBADD   = $(MATH_LIB)
