#=====================================
# truly global things
#=====================================

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

# This avoids newer GNU ar with deterimistic build features from emitting
# annoying warnings, and doesn't cost much vs the default "cru".
ARFLAGS = cr

# ask gmake to delete corrupted partial build outputs
.DELETE_ON_ERROR:

#=====================================
# base defs for += in further sections
#=====================================

bin_PROGRAMS =
sbin_PROGRAMS =
pkglibexec_PROGRAMS =
noinst_LIBRARIES =
noinst_SCRIPTS =
dist_doc_DATA =
man_MANS =

EXTRA_DIST =
CLEANFILES =
DISTCLEANFILES =
MAINTAINERCLEANFILES =
DISTCHECK_CONFIGURE_FLAGS =

CHECK_LOCAL_DEPS =
INSTALL_EXEC_HOOK_DEPS =

#=====================================
# repo root
#=====================================

dist_doc_DATA += README.md VERSION3.md INSTALL AUTHORS COPYING NEWS

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

INSTALL_EXEC_HOOK_DEPS += install-exec-hook-top
install-exec-hook-top:
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_DEFPATH_CONFIG)/zones";
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_DEFPATH_CONFIG)/geoip";
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_DEFPATH_RUN)";
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_DEFPATH_STATE)";

#=====================================
# src/
#=====================================

noinst_LIBRARIES += src/libcsc.a
src_libcsc_a_SOURCES = src/csc.c src/csc.h

noinst_LIBRARIES += src/plugins/libextmon_comms.a
src_plugins_libextmon_comms_a_SOURCES = src/plugins/extmon_comms.c src/plugins/extmon_comms.h

pkglibexec_PROGRAMS += src/plugins/gdnsd_extmon_helper
src_plugins_gdnsd_extmon_helper_SOURCES = src/plugins/extmon_helper.c
src_plugins_gdnsd_extmon_helper_LDADD   = src/plugins/libextmon_comms.a libgdnsd/libgdnsd.a -lm -lev $(LIBUNWIND_LIBS)

bin_PROGRAMS += src/plugins/gdnsd_geoip_test
src_plugins_gdnsd_geoip_test_SOURCES  = src/plugins/gdnsd_geoip_test.c
src_plugins_gdnsd_geoip_test_LDADD    = libgdmaps/libgdmaps.a libgdnsd/libgdnsd.a -lm -lurcu-qsbr -lev $(LIBUNWIND_LIBS) $(GEOIP2_LIBS)

bin_PROGRAMS += src/gdnsdctl
src_gdnsdctl_SOURCES = src/gdnsdctl.c
src_gdnsdctl_LDADD = src/libcsc.a libgdnsd/libgdnsd.a -lm $(LIBUNWIND_LIBS)

sbin_PROGRAMS += src/gdnsd

src/zscan_rfc1035.c: src/zscan_rfc1035.rl
	$(AM_V_GEN)ragel -G2 -o $@ $(srcdir)/src/zscan_rfc1035.rl
EXTRA_DIST += src/zscan_rfc1035.rl src/zscan_rfc1035.c

# The reason for -I$(srcdir)/src below is that zscan_rfc1035.c is
#   created in the builddir, so the compiler won't otherwise pick
#   up includes from $(srcdir)/src when compiling it.
src_gdnsd_CPPFLAGS = -I$(srcdir)/src $(AM_CPPFLAGS)

src_gdnsd_SOURCES = \
	src/zscan_rfc1035.c \
	src/zscan_rfc1035.h \
	src/main.c \
	src/main.h \
	src/daemon.c \
	src/daemon.h \
	src/css.c \
	src/css.h \
	src/cs.h \
	src/conf.c \
	src/conf.h \
	src/chal.c \
	src/chal.h \
	src/cookie.c \
	src/cookie.h \
	src/kdf_compat.c \
	src/kdf_compat.h \
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
	src/proxy.c \
	src/proxy.h \
	src/socks.c \
	src/socks.h \
	src/statio.c \
	src/statio.h \
	src/dnswire.h \
	src/plugins/http_status.c \
	src/plugins/multifo.c \
	src/plugins/null.c \
	src/plugins/reflect.c \
	src/plugins/simplefo.c \
	src/plugins/static.c \
	src/plugins/tcp_connect.c \
	src/plugins/weighted.c \
	src/plugins/extfile.c \
	src/plugins/geoip.c \
	src/plugins/metafo.c \
	src/plugins/extmon.c \
	src/plugins/meta_core.inc \
	src/plugins/mon.c \
	src/plugins/plugapi.c \
	src/plugins/plugins.h \
	src/plugins/plugapi.h \
	src/plugins/mon.h

src_gdnsd_LDADD = \
	src/libcsc.a \
	src/plugins/libextmon_comms.a \
	libgdnsd/libgdnsd.a \
	libgdmaps/libgdmaps.a \
	-lm -lurcu-qsbr -lev -lsodium $(LIBUNWIND_LIBS) $(GEOIP2_LIBS)

#=====================================
# libgdmaps/
#=====================================

noinst_LIBRARIES += libgdmaps/libgdmaps.a
libgdmaps_libgdmaps_a_SOURCES = \
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
	libgdmaps/gdgeoip2.c \
	libgdmaps/gdgeoip2.h

#=====================================
# libgdnsd/
#=====================================

noinst_LIBRARIES += libgdnsd/libgdnsd.a

# All the various libgdnsd headers
libgdnsd_libgdnsd_a_SOURCES = \
	include/gdnsd/vscf.h \
	include/gdnsd/dname.h \
	include/gdnsd/log.h \
	include/gdnsd/compiler.h \
	include/gdnsd/stats.h \
	include/gdnsd/net.h \
	include/gdnsd/misc.h \
	include/gdnsd/paths.h \
	include/gdnsd/rand.h \
	include/gdnsd/file.h \
	include/gdnsd/alloc.h \
	libgdnsd/dname.c \
	libgdnsd/net.c \
	libgdnsd/log.c \
	libgdnsd/misc.c \
	libgdnsd/paths.c \
	libgdnsd/file.c \
	libgdnsd/alloc.c \
	libgdnsd/vscf.c

LIBGDNSD_PATHS = \
	-DGDNSD_DEFPATH_CONFIG='"$(GDNSD_DEFPATH_CONFIG)"' \
	-DGDNSD_DEFPATH_RUN='"$(GDNSD_DEFPATH_RUN)"' \
	-DGDNSD_DEFPATH_STATE='"$(GDNSD_DEFPATH_STATE)"' \
	-DGDNSD_DEFPATH_LIBEXEC='"$(GDNSD_DEFPATH_LIBEXEC)"'

libgdnsd_libgdnsd_a_CPPFLAGS = $(LIBGDNSD_PATHS) $(AM_CPPFLAGS)

libgdnsd/vscf.c: libgdnsd/vscf.rl
	$(AM_V_GEN)ragel -T0 -o $@ $(srcdir)/libgdnsd/vscf.rl
EXTRA_DIST += libgdnsd/vscf.rl libgdnsd/vscf.c

#=====================================
# init/
#=====================================

if DO_SYSD_UNITFILE

DISTCHECK_CONFIGURE_FLAGS += --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)
systemdsystemunit_DATA = init/gdnsd.service
INSTALL_EXEC_HOOK_DEPS += install-exec-hook-systemd
install-exec-hook-systemd:
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
noinst_SCRIPTS += init/gdnsd.service

endif

init/gdnsd.service: init/gdnsd.service.tmpl Makefile
	$(AM_V_GEN)sed -e 's|@GDNSD_SBINDIR[@]|$(sbindir)|g' -e 's|@GDNSD_BINDIR[@]|$(bindir)|g' <$(srcdir)/init/gdnsd.service.tmpl >$@

init/gdnsd.init: init/gdnsd.init.tmpl Makefile
	$(AM_V_GEN)sed -e 's|@GDNSD_SBINDIR[@]|$(sbindir)|g' -e 's|@GDNSD_BINDIR[@]|$(bindir)|g' -e 's|@GDNSD_RUNDIR@|$(GDNSD_DEFPATH_RUN)|g' -e 's|@GDNSD_CONFIGDIR@|$(GDNSD_DEFPATH_CONFIG)|g' <$(srcdir)/init/gdnsd.init.tmpl >$@

EXTRA_DIST += init/gdnsd.service.tmpl init/gdnsd.init.tmpl
CLEANFILES += init/gdnsd.service init/gdnsd.init
noinst_SCRIPTS += init/gdnsd.init

#=====================================
# docs/
#=====================================

# dist + install simple docs
dist_doc_DATA += \
	docs/Manual.md \
	docs/Security.md \
	docs/stats_example.html

PODS_IN_1 = docs/gdnsd_geoip_test.podin
PODS_IN_5 = \
	docs/gdnsd.config.podin \
	docs/gdnsd.zonefile.podin
PODS_IN_8 = \
	docs/gdnsd.podin \
	docs/gdnsdctl.podin \
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
ALL_PODS = $(PODS_IN_1) $(PODS_IN_5) $(PODS_IN_8)
EXTRA_DIST += $(ALL_PODS)

# This translates default path variables in the pod sources
#  as the intermediate step X.podin -> X.pod
MAN_SED = $(SED) \
	-e 's|@GDNSD_DEFPATH_CONFIG[@]|$(GDNSD_DEFPATH_CONFIG)|g' \
	-e 's|@GDNSD_DEFPATH_STATE[@]|$(GDNSD_DEFPATH_STATE)|g' \
	-e 's|@GDNSD_DEFPATH_RUN[@]|$(GDNSD_DEFPATH_RUN)|g' \
	-e 's|@GDNSD_DEFPATH_LIBEXEC[@]|$(GDNSD_DEFPATH_LIBEXEC)|g'

INTERMEDIATE_PODS = $(ALL_PODS:.podin=.pod)
$(INTERMEDIATE_PODS): Makefile
.podin.pod:
	$(AM_V_GEN)$(MAN_SED) <$< >$@

# Manpages for installation, generated via sed templating then pod2man
man_MANS += $(PODS_IN_1:.podin=.1) $(PODS_IN_5:.podin=.5) $(PODS_IN_8:.podin=.8)
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
		wikifn=`echo $$podsrc | $(PERL) -pe 's,^docs/,,; s/^([a-z])/uc($$1)/e; s/[_.-]([a-zA-Z0-9])/uc($$1)/ge; s/Podin$$/.pod/'`; \
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
.PHONY: $(INSTALL_EXEC_HOOK_DEPS) $(CHECK_LOCAL_DEPS)
