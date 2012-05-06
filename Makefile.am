
# Where we keep m4 files for aclocal
ACLOCAL_AMFLAGS = -I m4

# Subdirectories to recurse into
SUBDIRS = gdnsd plugins docs t

MISC_DOCS = README INSTALL AUTHORS COPYING ChangeLog
EXTRA_DIST = docs.am pkg
BUILT_SOURCES = cfg-dirs.h
CLEANFILES = cfg-dirs.h

# Some junk autotools doesn't seem to clean on its own
DISTCLEANFILES = config.h.in~ configure.ac~

# kill distfiles and coverage junk on maintainer-clean
MAINTAINERCLEANFILES = *.info gdnsd-*.tar.*

cfg-dirs.h:	Makefile
	$(AM_V_GEN)echo '#define GDNSD_DEF_ROOTDIR "$(GDNSD_DEF_ROOTDIR)"' >$@
	@echo '#define GDNSD_LIBDIR "$(libdir)/gdnsd"' >>$@

test:	check

libtool: $(LIBTOOL_DEPS) 
	$(SHELL) ./config.status --recheck 

all-local: libtool

gdnsd-install-rootdir:
	for dir in "$(GDNSD_DEF_ROOTDIR)/etc/zones" "$(GDNSD_DEF_ROOTDIR)/var"; do \
          test -z "$$dir" || $(MKDIR_P) "$$dir"; \
        done

install-exec-local:	gdnsd-install-rootdir
installdirs-local:	gdnsd-install-rootdir

install-exec-hook:
	@echo
	@echo === READ ME ===
	@echo You may need to create the user \"$(PACKAGE_NAME)\" if you have not done so already.
	@echo The default data root directory is \"$(GDNSD_DEF_ROOTDIR)\".  For a quick default
	@echo   static configuration, places your zonefiles \(named for their zones\) in the
	@echo   directory \"$(GDNSD_DEF_ROOTDIR)/etc/zones/\", and invoke \"$(PACKAGE_NAME) start\"
	@echo   as root.

check-download:
	@$(MAKE) $(AM_MAKEFLAGS) -C plugins check-download

clean-local:
	@rm -rf $(top_srcdir)/gwiki.out

include $(top_srcdir)/docs.am
