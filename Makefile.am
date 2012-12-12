
# Where we keep m4 files for aclocal
ACLOCAL_AMFLAGS = -I m4

# Subdirectories to recurse into
SUBDIRS = gdnsd plugins docs t

MISC_DOCS = README.md INSTALL AUTHORS COPYING ChangeLog
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
	@echo '#define GDNSD_LIBEXECDIR "$(libexecdir)/gdnsd"' >>$@

test:	check

libtool: $(LIBTOOL_DEPS) 
	$(SHELL) ./config.status --recheck 

all-local: libtool

# This creates an empty skeleton in e.g. /srv/gdnsd
# It's not executed as part of "make install", because it
#   doesn't live within $prefix, and thus "make distcheck"
#   would fail on it...
install-gdnsd-rootdir:
	umask 022
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_DEF_ROOTDIR)/etc/zones"
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_DEF_ROOTDIR)/etc/geoip"
	$(MKDIR_P) "$(DESTDIR)$(GDNSD_DEF_ROOTDIR)/var"

install-exec-hook:
	@echo
	@echo === READ ME ===
	@echo You may need to create the user \"$(PACKAGE_NAME)\" if you have not done so already.
	@echo The default data root directory is \"$(GDNSD_DEF_ROOTDIR)\".  For a quick default
	@echo   static configuration, place your zonefiles \(named for their zones\) in the
	@echo   directory \"$(GDNSD_DEF_ROOTDIR)/etc/zones/\", and invoke \"$(PACKAGE_NAME) start\"
	@echo   as root.
	@echo You can run \"make install-gdnsd-rootdir\" to have the basic directory layout created for you.

check-download:
	@$(MAKE) $(AM_MAKEFLAGS) -C plugins check-download

clean-local:
	@rm -rf $(top_srcdir)/wikidocs

include $(top_srcdir)/docs.am
