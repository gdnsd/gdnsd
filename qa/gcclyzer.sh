#!/bin/sh
# run from top of repo
# does gcc -fanalyzer check with warnings upgraded to errors
if [ ! -f $PWD/qa/gdnsd.supp ]; then
   echo "Run this from the root of the source tree!"
   exit 99
fi
set -x
set -e
CFLAGS="-fanalyzer -fanalyzer-verbosity=0 -fanalyzer-transitivity" ./configure --enable-developer --without-hardening --with-werror
make clean all
