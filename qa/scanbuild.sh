#!/bin/sh
# run from top of repo
# does clang-analyzer checks
if [ ! -f $PWD/qa/gdnsd.supp ]; then
   echo "Run this from the root of the source tree!"
   exit 99
fi
set -x
set -e
scan-build ./configure --enable-developer
make clean
scan-build make
