#!/bin/sh
# execute from top of repo
if [ ! -f $PWD/qa/gdnsd.supp ]; then
   echo "Run this from the root of the source tree!"
   exit 99
fi
set -x
set -e
CPPFLAGS="-DDMN_COVERTEST_EXIT" CFLAGS="-O0" ./configure --enable-developer --without-hardening
make clean
TEST_RUNNER="libtool --mode=execute valgrind --error-exitcode=99 --leak-check=full --suppressions=$PWD/qa/gdnsd.supp" make check
set +e
set +x
grep "ERROR SUM" t/testout/*/gdnsd.out | grep -v ' 0 errors'
