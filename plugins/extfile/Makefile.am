AM_CPPFLAGS = -I$(top_builddir)/gdnsd/libgdnsd -I$(top_srcdir)/gdnsd/libgdnsd
AM_LIBTOOLFLAGS = --silent

pkglib_LTLIBRARIES = plugin_extfile.la
plugin_extfile_la_SOURCES  = extfile.c
plugin_extfile_la_LDFLAGS  = -avoid-version -module -export-symbols-regex ^plugin_extfile_
