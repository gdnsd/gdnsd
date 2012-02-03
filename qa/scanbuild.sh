#!/bin/sh
# run from top of repo
# does clang-analyzer checks
scan-build ./configure --enable-developer && make clean && scan-build make
