#!/bin/sh
# run from top of repo
if [ ! -f $PWD/qa/gdnsd.supp ]; then
   echo "Run this from the root of the source tree!"
   exit 99
fi

# NOTE: the sanitizer blacklists don't work well with ccache because the cache
# doesn't know to vary on the contents of the blacklist file.  Given that some
# distributions enable ccache for all compilers silently by default if it's
# installed at all, it's wise to "ccache -C" if changing a blacklist file.

set -x
set -e
export ASAN_OPTIONS="check_initialization_order=1"
for san_type in address undefined; do
  CFLAGS="-O1 -fno-omit-frame-pointer -fno-sanitize-recover -fsanitize=$san_type -fsanitize-blacklist=$PWD/qa/${san_type}.bl" \
    CC=clang ./configure --enable-developer --without-hardening
  make clean
  make check
done
