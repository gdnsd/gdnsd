#!/bin/sh
# run from top of repo
if [ ! -f $PWD/qa/gdnsd.supp ]; then
   echo "Run this from the root of the source tree!"
   exit 99
fi

# Note this uses gcc 5.3's sanitizers, this probably won't work with earlier gcc versions

set -x
set -e
export ASAN_OPTIONS="check_initialization_order=1:detect_invalid_pointer_pairs=10"
for san_type in address undefined; do
  CFLAGS="-O1 -fno-omit-frame-pointer -fno-common -fno-sanitize-recover=all -fsanitize=$san_type" \
    CC=gcc ./configure --enable-developer --without-hardening
  make clean
  make check
done
