
# Where we keep m4 files for aclocal
ACLOCAL_AMFLAGS = -I m4

# Subdirectories to recurse into
SUBDIRS = gdnsd plugins example docs t

MISC_DOCS = README INSTALL AUTHORS COPYING ChangeLog

EXTRA_DIST = docs.am

# Some junk autotools doesn't seem to clean on its own
DISTCLEANFILES = config.h.in~ configure.ac~

# kill distfiles and coverage junk on maintainer-clean
MAINTAINERCLEANFILES = *.info gdnsd-*.tar.*

test:	check

libtool: $(LIBTOOL_DEPS) 
	$(SHELL) ./config.status --recheck 

all-local: libtool

install-exec-hook:
	@echo
	@echo === READ ME ===
	@echo You may need to create the user \"$(PACKAGE_NAME)\" if you have not done so already
	@echo

check-download:
	@$(MAKE) $(AM_MAKEFLAGS) -C plugins check-download

mtaintainer-clean-local: docs-maintainer-clean

clean-local:
	@rm -rf $(top_srcdir)/gwiki.out

include $(top_srcdir)/docs.am
