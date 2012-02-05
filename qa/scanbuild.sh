#!/bin/sh
# run from top of repo
# does clang-analyzer checks
set -x
set -e
scan-build ./configure --enable-developer
make clean
scan-build make
