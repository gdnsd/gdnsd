
AM_CPPFLAGS = -I$(top_builddir)/gdnsd/libgdnsd -I$(top_srcdir)/gdnsd/libgdnsd -I$(srcdir)/.. -DETCDIR=\"$(sysconfdir)\"
AM_LIBTOOLFLAGS = --silent

noinst_LTLIBRARIES = libgdmaps_test.la
libgdmaps_test_la_SOURCES = gdmaps_test.c gdmaps_test.h

LDADD = libgdmaps_test.la ../libgdmaps.la ../../../../gdnsd/libgdnsd/libgdnsd.la

bin_PROGRAMS = gdnsd_geoip_test
gdnsd_geoip_test_SOURCES = gdnsd_geoip_test.c

PODS_1 = gdnsd_geoip_test.pod
include $(top_srcdir)/docs.am

# ----------- testsuite stuff --------------

# I've mirrored these to the gdnsd.net test webservers to be dynamically downloaded for those who
#  bother running make check.  They were pulled on the date indicated in the filename in order
#  to provide a stable test baseline, and won't be updated unless there's a technical testsuite
#  reason (database format changes requiring new tests, etc).
# They are *not* redistributed with the tarball, and are *not* intended to be installed for
#  runtime use by users.
# This product includes GeoLite data created by MaxMind, available from http://maxmind.com/
# These files are subject to MaxMind's GeoLite Open Data license, which is also re-distributed by download

GEOLITE_URL_BASE = http://gdnsd.net/GeoLiteTestData/
GEOLITE_FILES = LICENSE.txt GeoIP-20111210.dat GeoIPv6-20111210.dat GeoLiteCity-20111210.dat GeoLiteCityv6-20111210.dat fips_include-20111210

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
	t13_castatdef

check_PROGRAMS = $(TESTLIST:=.bin)

TESTS_ENVIRONMENT = ASDIR="$(abs_srcdir)" ABDIR="$(abs_builddir)" GEOLITE_FILES="$(GEOLITE_FILES)" TLIST="$(TESTLIST)"
TESTS = trunner.sh
EXTRA_DIST = trunner.sh tdownload.sh $(TESTLIST:=.cfg)

check-download: tdownload.sh
	@GEOLITE_DECOMP="$(GEOLITE_DECOMP)" GEOLITE_DL="$(GEOLITE_DL)" GEOLITE_URL_BASE="$(GEOLITE_URL_BASE)" $(TESTS_ENVIRONMENT) $(srcdir)/tdownload.sh


