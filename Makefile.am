#=====================================
# truly global things
#=====================================

# Where we keep m4 files for aclocal
ACLOCAL_AMFLAGS = -I m4

# Common header path for libgdnsd's public gdnsd/*.h
AM_CPPFLAGS = -I$(srcdir)/include

# Subdirectories to recurse into
#  ("." first so testsuite stuff always after main stuff)
SUBDIRS = . t

# Alias "make test" -> "make check"
.PHONY: test
test: check

# If using ccache, tell it to re-cpp on cache misses, otherwise it trips up
#   the compiler's idea of what came from "system headers" for warnings
#   purposes, generating tons of warnings-spam.
export CCACHE_CPP2 = 1

# ask gmake to delete corrupted partial build outputs
.DELETE_ON_ERROR:

#=====================================
# base defs for += in further sections
#=====================================

bin_PROGRAMS =
sbin_PROGRAMS =
pkglibexec_PROGRAMS =
pkglib_LTLIBRARIES =
noinst_LTLIBRARIES =
noinst_SCRIPTS =
dist_doc_DATA =
man_MANS =

EXTRA_DIST =
CLEANFILES =
DISTCLEANFILES =
MAINTAINERCLEANFILES =
DISTCHECK_CONFIGURE_FLAGS =

ALL_LOCAL_DEPS =
CHECK_LOCAL_DEPS =
INSTALL_EXEC_HOOK_DEPS =

#=====================================
# repo root
#=====================================

dist_doc_DATA += README.md INSTALL AUTHORS COPYING NEWS

# This is technically a subdir, but the build process doesn't use it,
#   it's just distributed for people to run things manually
EXTRA_DIST += qa

# Some junk autotools doesn't seem to clean on its own
DISTCLEANFILES += config.h.in~ configure.ac~

# kill distfiles and coverage junk on maintainer-clean
MAINTAINERCLEANFILES += *.info gdnsd-*.tar.*

CHECK_LOCAL_DEPS += check-local-top
check-local-top:
	@if test `id -u` == "0"; then \
		echo "*** WARNING *** Testing (or even building!) as the root user is not wise!"; \
		echo "*** WARNING *** If you experience any failures, please retry as a non-root user before reporting..."; \
	fi
	@if test "x$(PROVE)" == xmissing; then \
		echo "Cannot 'make check' or 'make installcheck' without 'prove' command (see 'configure' output)"; \
		exit 101; \
	fi
	@if test "x$(HAVE_TESTSUITE_MODULES)" == x0; then \
		echo "Cannot 'make check' or 'make installcheck' without required Perl modules (see 'configure' output)"; \
		exit 101; \
	fi

libtool: $(LIBTOOL_DEPS) 
	$(SHELL) ./config.status --recheck 

ALL_LOCAL_DEPS += all-local-top
all-local-top: libtool

INSTALL_EXEC_HOOK_DEPS += install-exec-hook-top
install-exec-hook-top:
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_DEFPATH_CONFIG)/zones";
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_DEFPATH_CONFIG)/djbdns";
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_DEFPATH_CONFIG)/geoip";
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_DEFPATH_RUN)";
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_DEFPATH_STATE)";
	@id gdnsd >/dev/null 2>&1; if test $$? -ne 0; then \
		echo; \
		echo === READ ME ===; \
		echo The default user \"gdnsd\" \(for privdrop when executed as root\) does not seem to exist yet!; \
		echo; \
	fi

#=====================================
# src/
#=====================================

sbin_PROGRAMS += src/gdnsd

src_gdnsd_SOURCES = \
	src/main.c \
	src/main.h \
	src/conf.c \
	src/conf.h \
	src/zsrc_djb.c \
	src/zsrc_djb.h \
	src/zscan_djb.c \
	src/zscan_djb.h \
	src/zsrc_rfc1035.c \
	src/zsrc_rfc1035.h \
	src/ztree.c \
	src/ztree.h \
	src/ltarena.c \
	src/ltarena.h \
	src/ltree.c \
	src/ltree.h \
	src/dnspacket.c \
	src/dnspacket.h \
	src/dnsio_udp.c \
	src/dnsio_udp.h \
	src/dnsio_tcp.c \
	src/dnsio_tcp.h \
	src/socks.c \
	src/socks.h \
	src/statio.c \
	src/statio.h \
	src/dnswire.h \
	src/zscan_rfc1035.h

# The reason for -I$(srcdir)/src below is that zscan_rfc1035.c is
#   created in the builddir, so the compiler won't otherwise pick
#   up includes from $(srcdir)/src when compiling it.
src_gdnsd_CPPFLAGS = -I$(srcdir)/src $(AM_CPPFLAGS)
src_gdnsd_CFLAGS = $(CFLAGS_PIE)
src_gdnsd_LDFLAGS = $(LDFLAGS_PIE)
src_gdnsd_LDADD = libgdnsd/libgdnsd.la $(LIBGDNSD_LIBS)

nodist_src_gdnsd_SOURCES = src/zscan_rfc1035.c
src/zscan_rfc1035.c: src/zscan_rfc1035.rl
	$(AM_V_GEN)$(RAGEL) -G2 -o $@ $(srcdir)/src/zscan_rfc1035.rl
CLEANFILES += src/zscan_rfc1035.c
EXTRA_DIST += src/zscan_rfc1035.rl

#=====================================
# plugins/
#=====================================

pkglib_LTLIBRARIES += \
	plugins/plugin_http_status.la \
	plugins/plugin_multifo.la \
	plugins/plugin_null.la \
	plugins/plugin_reflect.la \
	plugins/plugin_simplefo.la \
	plugins/plugin_static.la \
	plugins/plugin_tcp_connect.la \
	plugins/plugin_weighted.la \
	plugins/plugin_extfile.la \
	plugins/plugin_extmon.la \
	plugins/plugin_metafo.la \
	plugins/plugin_geoip.la

# simple plugins (in build terms)
plugins_plugin_http_status_la_SOURCES = plugins/http_status.c
plugins_plugin_http_status_la_LDFLAGS = -avoid-version -module
plugins_plugin_multifo_la_SOURCES     = plugins/multifo.c
plugins_plugin_multifo_la_LDFLAGS     = -avoid-version -module
plugins_plugin_null_la_SOURCES        = plugins/null.c
plugins_plugin_null_la_LDFLAGS        = -avoid-version -module
plugins_plugin_reflect_la_SOURCES     = plugins/reflect.c
plugins_plugin_reflect_la_LDFLAGS     = -avoid-version -module
plugins_plugin_simplefo_la_SOURCES    = plugins/simplefo.c
plugins_plugin_simplefo_la_LDFLAGS    = -avoid-version -module
plugins_plugin_static_la_SOURCES      = plugins/static.c
plugins_plugin_static_la_LDFLAGS      = -avoid-version -module
plugins_plugin_tcp_connect_la_SOURCES = plugins/tcp_connect.c
plugins_plugin_tcp_connect_la_LDFLAGS = -avoid-version -module
plugins_plugin_weighted_la_SOURCES    = plugins/weighted.c
plugins_plugin_weighted_la_LDFLAGS    = -avoid-version -module
plugins_plugin_extfile_la_SOURCES     = plugins/extfile.c
plugins_plugin_extfile_la_LDFLAGS     = -avoid-version -module

# extmon

noinst_LTLIBRARIES += plugins/libextmon_comms.la
plugins_libextmon_comms_la_SOURCES = plugins/extmon_comms.c plugins/extmon_comms.h

pkglibexec_PROGRAMS += plugins/gdnsd_extmon_helper
plugins_gdnsd_extmon_helper_SOURCES = plugins/extmon_helper.c plugins/extmon_comms.h
plugins_gdnsd_extmon_helper_LDADD   = plugins/libextmon_comms.la libgdnsd/libgdnsd.la $(LIBGDNSD_LIBS)
plugins_gdnsd_extmon_helper_CFLAGS  = $(CFLAGS_PIE)
plugins_gdnsd_extmon_helper_LDFLAGS = $(LDFLAGS_PIE)

plugins_plugin_extmon_la_SOURCES  = plugins/extmon.c plugins/extmon_comms.h
plugins_plugin_extmon_la_LDFLAGS  = -avoid-version -module
plugins_plugin_extmon_la_LIBADD   = plugins/libextmon_comms.la

# geoip + metafo

bin_PROGRAMS += plugins/gdnsd_geoip_test
plugins_gdnsd_geoip_test_SOURCES  = plugins/gdnsd_geoip_test.c
plugins_gdnsd_geoip_test_CFLAGS   = $(CFLAGS_PIE)
plugins_gdnsd_geoip_test_LDFLAGS  = $(LDFLAGS_PIE)
plugins_gdnsd_geoip_test_LDADD    = libgdmaps/libgdmaps.la libgdnsd/libgdnsd.la $(LIBGDNSD_LIBS)

plugins_plugin_geoip_la_SOURCES   = plugins/geoip.c plugins/meta_core.inc
plugins_plugin_geoip_la_LDFLAGS   = -avoid-version -module
plugins_plugin_geoip_la_LIBADD    = libgdmaps/libgdmaps.la

plugins_plugin_metafo_la_SOURCES  = plugins/metafo.c plugins/meta_core.inc
plugins_plugin_metafo_la_LDFLAGS  = -avoid-version -module

#=====================================
# libgdmaps/
#=====================================

noinst_LTLIBRARIES += libgdmaps/libgdmaps.la
libgdmaps_libgdmaps_la_LIBADD = $(MATH_LIB) $(GEOIP2_LIBS)
libgdmaps_libgdmaps_la_SOURCES = \
	include/gdmaps.h \
	libgdmaps/gdmaps.c \
	libgdmaps/dcinfo.c \
	libgdmaps/dcinfo.h \
	libgdmaps/dclists.c \
	libgdmaps/dclists.h \
	libgdmaps/dcmap.c \
	libgdmaps/dcmap.h \
	libgdmaps/nlist.c \
	libgdmaps/nlist.h \
	libgdmaps/ntree.c \
	libgdmaps/ntree.h \
	libgdmaps/nets.c \
	libgdmaps/nets.h \
	libgdmaps/gdgeoip.c \
	libgdmaps/gdgeoip.h \
	libgdmaps/gdgeoip2.c \
	libgdmaps/gdgeoip2.h \
	libgdmaps/fips104.c \
	libgdmaps/fips104.h

#=====================================
# libgdnsd/
#=====================================

pkglib_LTLIBRARIES += libgdnsd/libgdnsd.la

# These are the public libgdnsd headers that all in-tree source can use. They
# are also installed via "make install" and can be used by 3rd-party plugins
# built independently.
xHEADERS_INST = \
	include/gdnsd/vscf.h \
	include/gdnsd/dname.h \
	include/gdnsd/log.h \
	include/gdnsd/compiler.h \
	include/gdnsd/mon.h \
	include/gdnsd/stats.h \
	include/gdnsd/net.h \
	include/gdnsd/plugapi.h \
	include/gdnsd/plugin.h \
	include/gdnsd/misc.h \
	include/gdnsd/paths.h \
	include/gdnsd/file.h \
	include/gdnsd/alloc.h \
	include/gdnsd/prcu.h \
	include/gdnsd/dmn.h

# include/gdnsd-prot/foo.h define shlib interfaces private to libgdnsd + gdnsd
# libgdnsd/foo.h define non-shlib interfaces private to libgdnsd only
xHEADERS_ALL = \
	$(xHEADERS_INST) \
	include/gdnsd-prot/misc.h \
	include/gdnsd-prot/mon.h \
	include/gdnsd-prot/plugapi.h \
	libgdnsd/misc.h \
	libgdnsd/net.h \
	libgdnsd/plugapi.h

libgdnsd_libgdnsd_la_SOURCES = \
	$(xHEADERS_ALL) \
	libgdnsd/prcu.c \
	libgdnsd/dname.c \
	libgdnsd/net.c \
	libgdnsd/log.c \
	libgdnsd/mon.c \
	libgdnsd/misc.c \
	libgdnsd/paths.c \
	libgdnsd/file.c \
	libgdnsd/plugapi.c \
	libgdnsd/alloc.c \
	libgdnsd/dmn.c \
	libgdnsd/dmn_net.c

LIBGDNSD_PATHS = \
	-DGDNSD_DEFPATH_CONFIG='"$(GDNSD_DEFPATH_CONFIG)"' \
	-DGDNSD_DEFPATH_RUN='"$(GDNSD_DEFPATH_RUN)"' \
	-DGDNSD_DEFPATH_STATE='"$(GDNSD_DEFPATH_STATE)"' \
	-DGDNSD_DEFPATH_LIB='"$(GDNSD_DEFPATH_LIB)"' \
	-DGDNSD_DEFPATH_LIBEXEC='"$(GDNSD_DEFPATH_LIBEXEC)"'

libgdnsd_libgdnsd_la_CPPFLAGS = $(LIBGDNSD_PATHS) $(AM_CPPFLAGS)
libgdnsd_libgdnsd_la_LDFLAGS = -shared -avoid-version
libgdnsd_libgdnsd_la_LIBADD  = $(LIBGDNSD_LIBS)

libgdnsd_libgdnsd_la_pkgincludedir = $(pkgincludedir)
libgdnsd_libgdnsd_la_pkginclude_HEADERS = $(xHEADERS_INST)

# This header is also installed for external consumption.  It replaces any
# necessary defines that would have come from config.h in-tree, and should be
# used sparingly for binary compat issues.  It is not included in any in-tree
# sources.
nodist_libgdnsd_libgdnsd_la_pkginclude_HEADERS = libgdnsd/bopts.h
libgdnsd/bopts.h: Makefile
	$(AM_V_GEN)echo '#ifndef GDNSD_BOPTS_H' >$@; \
	echo '#define GDNSD_BOPTS_H' >>$@; \
	echo '#define GDNSD_B_QSBR $(GDNSD_B_QSBR)' >>$@; \
	echo '#endif // GDNSD_BOPTS_H' >>$@

nodist_libgdnsd_libgdnsd_la_SOURCES = libgdnsd/vscf.c
libgdnsd/vscf.c: libgdnsd/vscf.rl
	$(AM_V_GEN)$(RAGEL) -T0 -o $@ $(srcdir)/libgdnsd/vscf.rl
CLEANFILES += libgdnsd/vscf.c libgdnsd/bopts.h
EXTRA_DIST += libgdnsd/vscf.rl

#=====================================
# sysd/
#=====================================

if DO_SYSD_UNITFILE

DISTCHECK_CONFIGURE_FLAGS += --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)
systemdsystemunit_DATA = sysd/gdnsd.service
INSTALL_EXEC_HOOK_DEPS += install-exec-hook-sysd
install-exec-hook-sysd:
	@echo;\
	echo === READ ME ===;\
	echo A systemd service unit file was installed at $(systemdsystemunitdir)/gdnsd.service;\
	echo You may need to issue the following command to update systemd:;\
	echo systemctl daemon-reload;\
	echo You will also need to enable and/or start it via:;\
	echo systemctl enable gdnsd;\
	echo systemctl start gdnsd;\
	echo

else

DISTCHECK_CONFIGURE_FLAGS += --without-systemdsystemunitdir
noinst_SCRIPTS += sysd/gdnsd.service

endif

sysd/gdnsd.service: sysd/gdnsd.service.tmpl Makefile
	$(AM_V_GEN)sed 's|@GDNSD_SBINDIR[@]|$(sbindir)|g' <$(srcdir)/sysd/gdnsd.service.tmpl >$@

EXTRA_DIST += sysd/gdnsd.service.tmpl
CLEANFILES += sysd/gdnsd.service

#=====================================
# docs/
#=====================================

# dist + install simple docs
dist_doc_DATA += docs/gdnsd_manual.txt

PODS_IN_1 = docs/gdnsd_geoip_test.podin
PODS_IN_3 = docs/gdnsd-plugin-api.podin
PODS_IN_5 = \
	docs/gdnsd.config.podin \
	docs/gdnsd.zonefile.podin \
	docs/gdnsd.djbdns.podin
PODS_IN_8 = \
	docs/gdnsd.podin \
	docs/gdnsd-plugin-extfile.podin \
	docs/gdnsd-plugin-extmon.podin \
	docs/gdnsd-plugin-geoip.podin \
	docs/gdnsd-plugin-http_status.podin \
	docs/gdnsd-plugin-metafo.podin \
	docs/gdnsd-plugin-multifo.podin \
	docs/gdnsd-plugin-null.podin \
	docs/gdnsd-plugin-reflect.podin \
	docs/gdnsd-plugin-simplefo.podin \
	docs/gdnsd-plugin-static.podin \
	docs/gdnsd-plugin-tcp_connect.podin \
	docs/gdnsd-plugin-weighted.podin

# Gather up the .podin files (which are distributed but not installed)
ALL_PODS = $(PODS_IN_1) $(PODS_IN_3) $(PODS_IN_5) $(PODS_IN_8)
EXTRA_DIST += $(ALL_PODS)

# This translates default path variables in the pod sources
#  as the intermediate step X.podin -> X.pod
MAN_SED = $(SED) \
	-e 's|@GDNSD_DEFPATH_CONFIG[@]|$(GDNSD_DEFPATH_CONFIG)|g' \
	-e 's|@GDNSD_DEFPATH_STATE[@]|$(GDNSD_DEFPATH_STATE)|g' \
	-e 's|@GDNSD_DEFPATH_RUN[@]|$(GDNSD_DEFPATH_RUN)|g' \
	-e 's|@GDNSD_DEFPATH_LIB[@]|$(GDNSD_DEFPATH_LIB)|g' \
	-e 's|@GDNSD_DEFPATH_LIBEXEC[@]|$(GDNSD_DEFPATH_LIBEXEC)|g' \
	-e 's|@GDNSD_SBINDIR[@]|$(sbindir)|g'
INTERMEDIATE_PODS = $(ALL_PODS:.podin=.pod)
$(INTERMEDIATE_PODS): Makefile
.podin.pod:
	$(AM_V_GEN)$(MAN_SED) <$< >$@

# Manpages for installation, generated via sed templating then pod2man
man_MANS += $(PODS_IN_1:.podin=.1) $(PODS_IN_3:.podin=.3) $(PODS_IN_5:.podin=.5) $(PODS_IN_8:.podin=.8)
.pod.8:
	$(AM_V_GEN)$(POD2MAN) --section=8 --release="$(PACKAGE_NAME) $(VERSION)" --center=$(PACKAGE_NAME) $< $@
.pod.5:
	$(AM_V_GEN)$(POD2MAN) --section=5 --release="$(PACKAGE_NAME) $(VERSION)" --center=$(PACKAGE_NAME) $< $@
.pod.3:
	$(AM_V_GEN)$(POD2MAN) --section=3 --release="$(PACKAGE_NAME) $(VERSION)" --center=$(PACKAGE_NAME) $< $@
.pod.1:
	$(AM_V_GEN)$(POD2MAN) --section=1 --release="$(PACKAGE_NAME) $(VERSION)" --center=$(PACKAGE_NAME) $< $@

# "make wikidocs" ->
# Basically it renames all the podfiles from e.g. gdnsd-plugin-geoip.pod
#   to GdnsdPluginGeoip.pod and stuffs them all in a new top-level build
#   directory "wikidocs" at the top.  From there I copy them to the gollum
#   repo for GitHub, wherever I happen to have that checked out at.  It's
#   a manual step on new stable releases to push these docs through to
#   the Github wiki.
WIKI_DIR = wikidocs
.PHONY: wikidocs
wikidocs:
	@$(MKDIR_P) $(WIKI_DIR); \
	for podsrc in $(ALL_PODS); do \
		wikifn=`echo $$podsrc | $(PERL) -pe 's/^([a-z])/uc($$1)/e; s/[_.-]([a-zA-Z0-9])/uc($$1)/ge; s/Podin$$/.pod/'`; \
		echo Processing $$podsrc into $(WIKI_DIR)/$$wikifn ...; \
		$(MAN_SED) <$$podsrc >$(WIKI_DIR)/$$wikifn; \
	done

# cleanup
CLEANFILES += $(man_MANS) $(INTERMEDIATE_PODS)

#========================================
# Hooks combiners from above sections
#========================================
install-exec-hook: $(INSTALL_EXEC_HOOK_DEPS)
check-local: $(CHECK_LOCAL_DEPS)
all-local: $(ALL_LOCAL_DEPS)
.PHONY: $(INSTALL_EXEC_HOOK_DEPS) $(CHECK_LOCAL_DEPS) $(ALL_LOCAL_DEPS)
