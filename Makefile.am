# Where we keep m4 files for aclocal
ACLOCAL_AMFLAGS = -I m4

# Subdirectories to recurse into
#  ("." first for the check-local below before subdir tests)
SUBDIRS = . libtap gdnsd plugins docs sysd t

dist_doc_DATA = README.md INSTALL AUTHORS COPYING NEWS
EXTRA_DIST = qa

# Some junk autotools doesn't seem to clean on its own
DISTCLEANFILES = config.h.in~ configure.ac~

# kill distfiles and coverage junk on maintainer-clean
MAINTAINERCLEANFILES = *.info gdnsd-*.tar.*

test:	check

check-local:
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

all-local: libtool

check-download:
	@$(MAKE) $(AM_MAKEFLAGS) -C plugins check-download

wikidocs:
	@$(MAKE) $(AM_MAKEFLAGS) -C docs wikidocs

clean-local:
	@rm -rf $(top_srcdir)/wikidocs

install-exec-hook:
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

if DO_SYSD_UNITFILE
DISTCHECK_CONFIGURE_FLAGS = --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)
endif
