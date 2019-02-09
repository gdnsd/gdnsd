#!/bin/sh
# Just iterates a few CCs I have locally installed looking for Werror failures
# in optimized and unoptimized builds, and then runs the testsuite for each
# build as well in case it catches anything dumb.
if [ ! -f $PWD/qa/gdnsd.supp ]; then
   echo "Run this from the root of the source tree!"
   exit 99
fi
set -x
set -e
for comp in gcc-8 clang-7; do
    CC=${comp} ./configure --enable-developer --with-werror
    make clean all
    SLOW_TESTS=1 make check
    CC=${comp} CFLAGS=-O3 ./configure --disable-developer --enable-extrawarn --with-werror
    make clean all
    SLOW_TESTS=1 make check
done
