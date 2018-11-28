SUBDIRS = libtap libgdmaps

EXTRA_DIST = _GDT.pm $(srcdir)/[0-9]*/* $(srcdir)/[0-9]*/*/*
TESTOUT_DIR = $(abs_builddir)/testout
ALLTESTS = $(srcdir)/[0-9]*/*.t

# re-use silent-rules to set "prove" execution mode:
#  V=0 -> quiet + parallelized
#  V=1 -> verbose + serial
# Note test concurrency is TEST_CPUS * 4; we do a lot of sleeping/waiting...
prove_mode_0 = -q --merge -j$$(($(TEST_CPUS) * 4)) --state=slow,save
prove_mode_1 = -v -f
prove_mode_  = $(prove_mode_@AM_DEFAULT_V@)
prove_mode   = $(prove_mode_@AM_V@)

TEXEC = TESTOUT_DIR=$(TESTOUT_DIR) TESTPORT_START=$(TESTPORT_START) $(PROVE) $(prove_mode) --norc -I$(srcdir)

.PHONY: precheck
precheck:
	@$(MKDIR_P) $(TESTOUT_DIR); \
	echo Test data/outputs will be stored at $(TESTOUT_DIR)

# To run just one test subdir: make check V=1 TRUN=007plugins/*.t
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

DISTCLEANFILES = .prove
