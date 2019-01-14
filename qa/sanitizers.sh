#!/bin/sh
# run from top of repo
if [ ! -f $PWD/qa/gdnsd.supp ]; then
   echo "Run this from the root of the source tree!"
   exit 99
fi

# Note this uses gcc-8's sanitizers, this probably won't work with earlier gcc versions or other variants

set -x
set -e
export ASAN_OPTIONS="check_initialization_order=true:detect_invalid_pointer_pairs=10:strict_string_checks=true:detect_stack_use_after_return=true"
CFLAGS="-O1 -fno-omit-frame-pointer -fno-common -fno-sanitize-recover=all -fsanitize=address -fsanitize=leak -fsanitize=undefined -fsanitize=float-divide-by-zero -fsanitize=float-cast-overflow -fsanitize-address-use-after-scope" CC=gcc-8 ./configure --enable-developer --without-hardening
make clean
SLOW_TESTS=1 make check
