#!/bin/sh
# execute from top of repo
# I use an install + installcheck here because otherwise
#  valgrind needs --trace-children=yes to see through the libtool
#  wrapper in-tree, and thus gets cluttered with unrelated errors
#  from shellscripts.
if [ ! -f $PWD/qa/gdnsd.supp ]; then
   echo "Run this from the root of the source tree!"
   exit 99
fi
set -x
set -e
CFLAGS="-O0" ./configure --enable-developer --prefix=/tmp/_gdnsd_inst --with-rootdir=/tmp/_gdnsd_inst/root
make clean all
make check-download
make install
TEST_RUNNER="valgrind --leak-check=full --suppressions=$PWD/qa/gdnsd.supp" make -C plugins/meta/libgdmaps/t check
TEST_RUNNER="valgrind --leak-check=full --suppressions=$PWD/qa/gdnsd.supp" make installcheck
set +e
set +x
grep "ERROR SUM" t/testout/*/gdnsd.out plugins/meta/libgdmaps/t/testroot/*.out \
  | grep -v ' 0 errors' \
    || rm -rf /tmp/_gdnsd_inst
