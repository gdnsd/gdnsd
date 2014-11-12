AM_CPPFLAGS = -I$(top_builddir)/gdnsd/libgdnsd -I$(top_srcdir)/gdnsd/libgdnsd -I$(top_srcdir)/libtap -I$(srcdir)/..
AM_LIBTOOLFLAGS = --silent

check_LTLIBRARIES = libgdmaps_test.la
libgdmaps_test_la_SOURCES = gdmaps_test.c gdmaps_test.h
libgdmaps_test_la_LIBADD = ../libgdmaps.la $(top_builddir)/libtap/libtap.la $(top_builddir)/gdnsd/libgdnsd/libgdnsd.la $(LIBGDNSD_LIBS)

LDADD = libgdmaps_test.la

# ----------- testsuite stuff --------------
# I've mirrored these to S3 as "downloads.gdnsd.org" to be dynamically downloaded for those who
#  bother running make check.  They were pulled on the date indicated in the filename in order
#  to provide a stable test baseline, and won't be updated unless there's a technical testsuite
#  reason (database format changes requiring new tests, etc).
# They are *not* redistributed with the tarball, and are *not* intended to be installed for
#  runtime use by users.
# This product includes GeoLite data created by MaxMind, available from http://maxmind.com/
# These files are subject to MaxMind's GeoLite Open Data license, which is also re-distributed by download

GEOLITE_URL_BASE = http://downloads.gdnsd.org/GeoLiteTestData/
GEOLITE_FILES = LICENSE.txt GeoIP-20111210.dat GeoIPv6-20111210.dat GeoLiteCity-20111210.dat GeoLiteCityv6-20111210.dat regioncodes-20130115.csv

TESTLIST = \
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

EXTRA_DIST = tdownload.sh etc

check_PROGRAMS = $(TESTLIST:=.bin)

test_verbose_0 = @echo TEST $@;
test_verbose_ = $(test_verbose_@AM_DEFAULT_V@)
test_verbose = $(test_verbose_@AM_V@)

# re-use silent-rules to set "prove" execution mode:
#  V=0 -> quiet + parallelized
#  V=1 -> verbose + serial
prove_mode_0 = -q -j4
prove_mode_1 = -v
prove_mode_  = $(prove_mode_@AM_DEFAULT_V@)
prove_mode   = $(prove_mode_@AM_V@)

CHECK_PROGS_INTREE = $(check_PROGRAMS:%=$(builddir)/%)
check-local: $(check_PROGRAMS)
	$(test_verbose)TEST_CFDIR="$(abs_builddir)/etc" $(PROVE) --norc --merge $(prove_mode) -f -e "$(TEST_RUNNER)" $(CHECK_PROGS_INTREE)

CHECK_PROGS_INSTALL = $(check_PROGRAMS:%=$(builddir)/.libs/%)
installcheck-local: $(check_PROGRAMS)
	$(test_verbose)TEST_CFDIR="$(abs_builddir)/etc" $(PROVE) --norc --merge $(prove_mode) -f -e "$(TEST_RUNNER)" $(CHECK_PROGS_INSTALL)

check-download: tdownload.sh
	@ABDIR="$(abs_builddir)" GEOLITE_DECOMP="$(GEOLITE_DECOMP)" GEOLITE_DL="$(GEOLITE_DL)" GEOLITE_URL_BASE="$(GEOLITE_URL_BASE)" GEOLITE_FILES="$(GEOLITE_FILES)" $(srcdir)/tdownload.sh
