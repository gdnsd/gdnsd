AM_CPPFLAGS = -I$(top_builddir)/gdnsd/libgdnsd -I$(top_srcdir)/gdnsd/libgdnsd
AM_LIBTOOLFLAGS = --silent

noinst_LTLIBRARIES = libextmon_comms.la
libextmon_comms_la_SOURCES = extmon_comms.c extmon_comms.h

pkglib_LTLIBRARIES = plugin_extmon.la
plugin_extmon_la_SOURCES  = extmon.c extmon_comms.h
plugin_extmon_la_LDFLAGS  = -avoid-version -module -export-symbols-regex ^plugin_extmon_
plugin_extmon_la_LIBADD  = libextmon_comms.la

pkglibexec_PROGRAMS = gdnsd_extmon_helper
gdnsd_extmon_helper_SOURCES = extmon_helper.c extmon_comms.h
gdnsd_extmon_helper_LDADD = libextmon_comms.la $(top_builddir)/gdnsd/libgdnsd/libgdnsd.la $(LIBGDNSD_LIBS)
