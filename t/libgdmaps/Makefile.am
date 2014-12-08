AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/t/libtap

check_LTLIBRARIES = libgdmaps_test.la
libgdmaps_test_la_SOURCES = gdmaps_test.c gdmaps_test.h
libgdmaps_test_la_LIBADD = $(top_builddir)/libgdmaps/libgdmaps.la $(top_builddir)/libgdnsd/libgdnsd.la $(LIBGDNSD_LIBS) $(top_builddir)/t/libtap/libtap.la

LDADD = libgdmaps_test.la

TESTLIST = \
	t50_g2_country \
	t51_g2_city \
	t52_g2_nets \
	t53_g2_cityauto \
	t54_g2_complex \
	t55_g2_def2 \
	t56_g2_defnone \
	t57_g2_castatdef \
	t58_g2_missingcoords \
	t59_g2_extnets \
	t60_g2_gn_corner \
	t00_v4db \
	t01_v6db \
	t02_v4citydb \
	t03_v6citydb \
	t04_v64db \
	t05_v64citydb \
	t06_v4nets \
	t07_v6nets \
	t08_cityauto \
	t09_complex \
	t10_def \
	t11_def2 \
	t12_defnone \
	t13_castatdef \
	t14_missingcoords \
	t15_nogeo \
	t16_extnets \
	t17_extn_empty \
	t18_extn_all \
	t19_extn_allg \
	t20_extn_allgs \
	t21_extn_subs \
	t22_nets_corner \
	t23_gn_corner

#====================================================================
# START TEST DATA STUFF
#====================================================================
# This somewhat crazy looking construct allows for:
#   (a) the XZ files to be optional if they don't exist in $srcdir
#   (b) the uncompressed XZ files to be optional if no xz binary
#   (c) the actual XZ invocations to be parallelized by make -jN
#   (d) Nothing is re-done redundantly after it's set up once in
#       the builddir (until "make distclean", etc)
#====================================================================

# These are in the main git repo and required
TDATA_NOXZ = \
	tdata/extnets.nets \
	tdata/extn_empty.nets \
	tdata/extn_all.nets \
	tdata/extn_allgs.nets \
	tdata/extn_subs.nets \
	tdata/nets_corner.nets \
	tdata/gn_corner.nets

# These are not and optional
TDATA_XZ = \
	gdnsd-geoip-testdata/GeoLiteCityv6-20111210.dat.xz \
	gdnsd-geoip-testdata/GeoLiteCity-20111210.dat.xz \
	gdnsd-geoip-testdata/GeoLite2-City-20141008.mmdb.xz \
	gdnsd-geoip-testdata/GeoLite2-Country-20141008.mmdb.xz \
	gdnsd-geoip-testdata/GeoIPv6-20111210.dat.xz \
	gdnsd-geoip-testdata/GeoIP-20111210.dat.xz \
	gdnsd-geoip-testdata/regioncodes-20130115.csv.xz

TDATA_FINAL_NOXZ = $(TDATA_NOXZ:tdata/%=etc/geoip/%)
TDATA_FINAL_XZ = $(TDATA_XZ:gdnsd-geoip-testdata/%.xz=etc/geoip/%)
TDATA_FINAL = $(TDATA_FINAL_NOXZ)
TDATA_LINK = $(TDATA_NOXZ)

$(TDATA_FINAL_NOXZ): etc/geoip/.test_data_setup_done
$(TDATA_FINAL_XZ): etc/geoip/.test_data_setup_done
	@test -e $@ || if test -e $(@:%=%.xz); then \
		echo Decompressing $@ ...; \
		$(XZ) -dkf $(@:%=%.xz); \
	fi

if HAS_XZ
TDATA_FINAL += $(TDATA_FINAL_XZ)
TDATA_LINK += $(TDATA_XZ)
XZ_WARN =
else
XZ_WARN = === You must install xz and re-configure to decompress the missing databases below
endif

etc/geoip/.test_data_setup_done: Makefile
	@rm -rf etc ||:; \
	case $(srcdir) in \
		/*) rsdir=$(srcdir) ;; \
		*) rsdir=../../$(srcdir) ;; \
	esac; \
	$(MKDIR_P) etc/geoip/; \
	cd etc/geoip/; \
	for srcfile in $(TDATA_LINK); do \
		if test -e $$rsdir/$$srcfile; then \
			$(LN_S) $$rsdir/$$srcfile .; \
		fi \
	done; \
	touch .test_data_setup_done

#=====================================================================
# END TEST DATA STUFF; $(TDATA_FINAL) is what tests should depend on
#=====================================================================

# re-use silent-rules to set "prove" execution mode:
#  V=0 -> quiet + parallelized
#  V=1 -> verbose + serial
prove_mode_0 = -q --merge -j$(TEST_CPUS) --state=slow,save
prove_mode_1 = -v -f
prove_mode_  = $(prove_mode_@AM_DEFAULT_V@)
prove_mode   = $(prove_mode_@AM_V@)
prove_run = $(PROVE) --norc $(prove_mode) -e "$(TEST_RUNNER)"
test_verbose_0 = @echo TEST $@;
test_verbose_ = $(test_verbose_@AM_DEFAULT_V@)
test_verbose = $(test_verbose_@AM_V@)

check_PROGRAMS = $(TESTLIST:=.t)
CHECK_PROGS_PATHED = $(check_PROGRAMS:%=./%)

check-local: $(check_PROGRAMS) $(TDATA_FINAL) check-warn
	$(test_verbose)TEST_CFDIR=$(abs_builddir)/etc $(prove_run) $(CHECK_PROGS_PATHED)

.PHONY: check-warn
check-warn:
	@if test -e $(top_srcdir)/.git; then \
		if test ! -e $(srcdir)/gdnsd-geoip-testdata/README.md; then \
			echo "=== To fetch the missing databases below (optional), 'git submodule update --init' and re-configure"; \
		fi; \
		echo $(XZ_WARN); \
	fi

EXTRA_DIST = tdata
DISTCLEANFILES = .prove
distclean-local:
	-rm -rf etc
