#!/bin/sh
# execute from top of repo
# I use an install + installcheck here because otherwise
#  valgrind needs --trace-children=yes to see through the libtool
#  wrapper in-tree, and thus gets cluttered with unrelated errors
#  from shellscripts.
CFLAGS="-O0" ./configure --enable-developer --prefix=/tmp/_gdnsd_inst && make clean all check && make install && TEST_RUNNER="valgrind --leak-check=full --suppressions=$PWD/qa/gdnsd.supp" make installcheck && grep "ERROR SUM" t/testout/*/gdnsd.out | grep -v ' 0 errors' || rm -rf /tmp/_gdnsd_inst
