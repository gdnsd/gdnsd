#!/bin/sh
# run from top of repo
if [ ! -f $PWD/qa/gdnsd.supp ]; then
   echo "Run this from the root of the source tree!"
   exit 99
fi

set -x
set -e
export ASAN_OPTIONS="check_initialization_order=1"
for san_type in address undefined; do
  CFLAGS="-O1 -Werror -fno-omit-frame-pointer -fno-sanitize-recover -fsanitize=$san_type -fsanitize-blacklist=$PWD/qa/${san_type}.bl" \
    CC=clang ./configure --enable-developer --without-hardening
  make clean all
  make check-download
  make check
done
