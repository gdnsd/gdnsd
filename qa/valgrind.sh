#!/bin/sh
# execute from top of repo
if [ ! -f $PWD/qa/gdnsd.supp ]; then
   echo "Run this from the root of the source tree!"
   exit 99
fi
set -x
set -e
CPPFLAGS="-DGDNSD_COVERTEST_EXIT" CFLAGS="-O0" ./configure --enable-developer --without-hardening
make clean
make
SLOW_TESTS=1 TEST_RUNNER="valgrind --trace-children=yes --trace-children-skip=/bin/true,/bin/false,/bin/sh --error-exitcode=99 --leak-check=full --suppressions=$PWD/qa/gdnsd.supp" make check
set +e
set +x
grep "ERROR SUM" t/testout/*/*.out | grep -v ' 0 errors'
if [ $? -eq 0 ]; then
    exit 1;
else
    exit 0;
fi
