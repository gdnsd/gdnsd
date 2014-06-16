
# Where we keep m4 files for aclocal
ACLOCAL_AMFLAGS = -I m4

# Subdirectories to recurse into
SUBDIRS = gdnsd plugins docs t

MISC_DOCS = README.md INSTALL AUTHORS COPYING NEWS
EXTRA_DIST = qa docs.am

# Some junk autotools doesn't seem to clean on its own
DISTCLEANFILES = config.h.in~ configure.ac~

# kill distfiles and coverage junk on maintainer-clean
MAINTAINERCLEANFILES = *.info gdnsd-*.tar.*

test:	check

libtool: $(LIBTOOL_DEPS) 
	$(SHELL) ./config.status --recheck 

all-local: libtool

check-download:
	@$(MAKE) $(AM_MAKEFLAGS) -C plugins check-download

clean-local:
	@rm -rf $(top_srcdir)/wikidocs

install-exec-hook:
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_DEFPATH_CONFIG_DIR)/zones";
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_DEFPATH_CONFIG_DIR)/djbdns";
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_DEFPATH_CONFIG_DIR)/geoip";
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_DEFPATH_RUN)";
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_DEFPATH_STATE)";
	@id gdnsd >/dev/null 2>&1; if test $$? -ne 0; then \
		echo; \
		echo === READ ME ===; \
		echo The default user \"gdnsd\" \(for privdrop when executed as root\) does not seem to exist yet!; \
		echo; \
	fi

include $(top_srcdir)/docs.am
