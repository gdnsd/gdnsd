#!/bin/sh

# A script that automates coverage testing with lcov
# I primarily use this to test 100% branch coverage on dnspacket.c ...
# Run this from the top directory of the repo

set -x
set -e

make distclean
rm -f gdnsd-*.info
rm -rf lcovout
find . -name "*.gcov" -o -name "*.gcda" -o -name "*.gcno"|xargs rm -f

CFLAGS="-O0 -fprofile-arcs -ftest-coverage" CPPFLAGS="-DDMN_NO_UNREACH_BUILTIN" ./configure --disable-developer
make

lcov -c -i -d gdnsd -o gdnsd-base.info

make check

lcov -c -d gdnsd -o gdnsd-test.info
lcov -a gdnsd-base.info -a gdnsd-test.info -o gdnsd-cov.info
genhtml -o lcovout gdnsd-cov.info
