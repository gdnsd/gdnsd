SUBDIRS = libtap libgdmaps

EXTRA_DIST = README-NETDNS _GDT.pm _FakeGeoIP.pm Net $(srcdir)/[0-9]*/* $(srcdir)/[0-9]*/*/*
TESTOUT_DIR = $(abs_builddir)/testout
TEXEC = TESTOUT_DIR=$(TESTOUT_DIR) TESTPORT_START=$(TESTPORT_START) $(PROVE) --norc --merge -f -I$(srcdir)
ALLTESTS = $(srcdir)/[0-9]*/*.t

.PHONY: precheck
precheck:
	@$(MKDIR_P) $(TESTOUT_DIR); \
	echo Test data/outputs will be stored at $(TESTOUT_DIR)

# To run just one test subdir: make check TRUN=007plugins/*.t
check-local: precheck
	${AM_V_GEN}if test "${TRUN}x" != "x"; then \
		TOP_BUILDDIR=$(abs_top_builddir) $(TEXEC) $(srcdir)/${TRUN}; \
	else \
		TOP_BUILDDIR=$(abs_top_builddir) $(TEXEC) $(ALLTESTS); \
	fi

installcheck-local: precheck
	${AM_V_GEN}if test "${TRUN}x" != "x"; then \
		INSTALLCHECK_SBINDIR=$(sbindir) INSTALLCHECK_BINDIR=$(bindir) $(TEXEC) $(srcdir)/${TRUN}; \
	else \
		INSTALLCHECK_SBINDIR=$(sbindir) INSTALLCHECK_BINDIR=$(bindir) $(TEXEC) $(ALLTESTS); \
	fi

clean-local:
	-rm -rf $(TESTOUT_DIR)
