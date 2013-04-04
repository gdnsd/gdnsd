
# Where we keep m4 files for aclocal
ACLOCAL_AMFLAGS = -I m4

# Subdirectories to recurse into
SUBDIRS = gdnsd plugins docs t

MISC_DOCS = README.md INSTALL AUTHORS COPYING NEWS
EXTRA_DIST = autogen.sh qa/* docs.am pkg
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

test:	check

libtool: $(LIBTOOL_DEPS) 
	$(SHELL) ./config.status --recheck 

all-local: libtool

check-download:
	@$(MAKE) $(AM_MAKEFLAGS) -C plugins check-download

clean-local:
	@rm -rf $(top_srcdir)/wikidocs

include $(top_srcdir)/docs.am
