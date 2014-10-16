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

case "$GDNSD_TRAVIS_BUILD" in
    optimized)
        CFLAGS=-O3 ./configure
        make
        make check
    ;;
    coveralls)
        CFLAGS="-O0 -g -fprofile-arcs -ftest-coverage -fno-omit-frame-pointer" CPPFLAGS="-DDMN_NO_UNREACH_BUILTIN -DDMN_NO_FATAL_COVERAGE -DDMN_COVERTEST_EXIT" ./configure --without-hardening
        make
        lcov -c -i -d . -o gdnsd-base.info
        make check
        lcov -c -d . -o gdnsd-test.info
        lcov -a gdnsd-base.info -a gdnsd-test.info -o gdnsd-tested.info
        # This filters out the ragel-generated parsers, the inlines from liburcu,
        #  and libgdmaps test-only sources
        lcov -o gdnsd-filtered.info -r gdnsd-tested.info zscan_rfc1035.c vscf.c urcu-qsbr.h 't/t*.c'
        coveralls-lcov gdnsd-filtered.info
    ;;
    *)
        echo "Invalid TRAVIS_BUILD: $TRAVIS_BUILD"
        exit 99
    ;;
esac
