
# Where we keep m4 files for aclocal
ACLOCAL_AMFLAGS = -I m4

# Subdirectories to recurse into
SUBDIRS = gdnsd plugins docs t

MISC_DOCS = README.md INSTALL AUTHORS COPYING NEWS
EXTRA_DIST = autogen.sh qa docs.am
BUILT_SOURCES = cfg-dirs.h
CLEANFILES = cfg-dirs.h

# Some junk autotools doesn't seem to clean on its own
DISTCLEANFILES = config.h.in~ configure.ac~

# kill distfiles and coverage junk on maintainer-clean
MAINTAINERCLEANFILES = *.info gdnsd-*.tar.*

cfg-dirs.h:	Makefile
	$(AM_V_GEN)echo '#define GDNSD_ETCDIR "$(sysconfdir)/gdnsd"' >$@
	@echo '#define GDNSD_RUNDIR "$(GDNSD_SYSRUNDIR)/gdnsd"' >>$@
	@echo '#define GDNSD_LIBDIR "$(libdir)/gdnsd"' >>$@
	@echo '#define GDNSD_LIBEXECDIR "$(libexecdir)/gdnsd"' >>$@
	@echo '#define GDNSD_DEF_ROOTDIR "$(GDNSD_DEF_ROOTDIR)"' >>$@

test:	check

libtool: $(LIBTOOL_DEPS) 
	$(SHELL) ./config.status --recheck 

all-local: libtool

check-download:
	@$(MAKE) $(AM_MAKEFLAGS) -C plugins check-download

clean-local:
	@rm -rf $(top_srcdir)/wikidocs

install-exec-hook:
if HAS_DEF_ROOTDIR
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_DEF_ROOTDIR)"
else
	$(MKDIR_P) "$(DESTDIR)$(sysconfdir)/gdnsd/zones";
	$(MKDIR_P) "$(DESTDIR)$(sysconfdir)/gdnsd/geoip";
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_SYSRUNDIR)/gdnsd";
endif
	@id gdnsd >/dev/null 2>&1; if test $$? -ne 0; then \
		echo; \
		echo === READ ME ===; \
		echo The default user \"gdnsd\" \(for privdrop when executed as root\) does not seem to exist yet!; \
		echo; \
	fi

include $(top_srcdir)/docs.am
