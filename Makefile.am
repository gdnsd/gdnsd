
# Where we keep m4 files for aclocal
ACLOCAL_AMFLAGS = -I m4

# Subdirectories to recurse into
SUBDIRS = gdnsd plugins example docs t

dist_doc_DATA = README INSTALL AUTHORS COPYING ChangeLog

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
	@echo Making check-download in plugins
	@cd plugins && $(MAKE) $(AM_MAKEFLAGS) check-download

