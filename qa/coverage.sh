#!/bin/sh

# A script that automates coverage testing with lcov
# I primarily use this to test 100% branch coverage on dnspacket.c ...
# Run this from the top directory of the repo

if [ ! -f $PWD/qa/gdnsd.supp ]; then
   echo "Run this from the root of the source tree!"
   exit 99
fi

set -x
set -e

CFLAGS="-O0 -g -fprofile-arcs -ftest-coverage" CPPFLAGS="-DDMN_NO_UNREACH_BUILTIN -DDMN_NO_FATAL_COVERAGE -DDMN_COVERTEST_EXIT" ./configure --disable-developer --without-hardening
make clean all
make check-download

lcov -c -i -d . -o gdnsd-base.info --rc lcov_branch_coverage=1

make check

lcov -c -d . -o gdnsd-test.info --rc lcov_branch_coverage=1
lcov -a gdnsd-base.info -a gdnsd-test.info -o gdnsd-cov.info --rc lcov_branch_coverage=1
genhtml --branch-coverage -o lcovout gdnsd-cov.info
