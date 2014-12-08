#!/bin/sh

if [ ! -f $PWD/qa/gdnsd.supp ]; then
   echo "Run this from the root of the source tree!"
   exit 99
fi

if [ ! -f $PWD/configure ]; then
   echo "Run autoreconf -vi first!"
   exit 99
fi

set -x
set -e

TEST_CPUS=`getconf _NPROCESSORS_ONLN`
export TEST_CPUS

case "$GDNSD_TRAVIS_BUILD" in
    optimized)
        CFLAGS=-O3 ./configure
        make -j$TEST_CPUS check
    ;;
    coveralls)
        CFLAGS="-O0 -g -fprofile-arcs -ftest-coverage -fno-omit-frame-pointer" CPPFLAGS="-DDMN_NO_UNREACH_BUILTIN -DDMN_NO_FATAL_COVERAGE -DDMN_COVERTEST_EXIT" ./configure --without-hardening
        make -j$TEST_CPUS
        lcov -c -i -d . -o gdnsd-base.info
        make check
        lcov -c -d . -o gdnsd-test.info
        lcov -a gdnsd-base.info -a gdnsd-test.info -o gdnsd-tested.info
        # This filters out the ragel-generated parsers, the inlines from liburcu, and any test-only sources
        lcov -o gdnsd-filtered.info -r gdnsd-tested.info zscan_rfc1035.c vscf.c urcu-qsbr.h 't/lib*/*.c'
        coveralls-lcov gdnsd-filtered.info
    ;;
    *)
        echo "Invalid GDNSD_TRAVIS_BUILD: $GDNSD_TRAVIS_BUILD"
        exit 99
    ;;
esac
