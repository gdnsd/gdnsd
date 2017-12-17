#!/bin/sh
# execute from top of repo
if [ ! -f $PWD/qa/gdnsd.supp ]; then
   echo "Run this from the root of the source tree!"
   exit 99
fi
set -x
set -e
mkdir -p _vginst
CPPFLAGS="-DDMN_COVERTEST_EXIT" CFLAGS="-O0" ./configure --enable-developer --without-hardening --prefix=${PWD}/_vginst --with-systemdsystemunitdir=${PWD}/_vginst
make clean
make install
TEST_RUNNER="libtool --mode=execute valgrind --trace-children=yes --trace-children-skip=/bin/true,/bin/false,/bin/sh --error-exitcode=99 --leak-check=full --suppressions=$PWD/qa/gdnsd.supp" make installcheck
set +e
set +x
grep "ERROR SUM" t/testout/*/*.out | grep -v ' 0 errors'
if [ $? -eq 0 ]; then
    exit 1;
else
    exit 0;
fi
