#!/bin/sh
# Manual sonar submissions while working on dev stuff, only to be used from
# temporary feature branches, assumes the branch target is master

BRANCH=`git rev-parse --abbrev-ref HEAD`
if echo $BRANCH | egrep -q '^(master|[0-9]+\.[0-9]+\.x)$'; then
    echo "Execute this on a feature branch only"
    exit 1
fi

TEST_CPUS=2
rm -f *.gcov
rm -rf bw-output
CFLAGS="-O0 -g -fprofile-arcs -ftest-coverage" CPPFLAGS="-DGDNSD_NO_UNREACH_BUILTIN -DGDNSD_NO_FATAL_COVERAGE -DGDNSD_COVERTEST_EXIT" ./configure --without-hardening
make clean
SLOW_TESTS=1 make -j$TEST_CPUS check
gcov -a -b -p src/*.o src/plugins/*.o libgdmaps/*.o libgdnsd/*.o
make clean
./configure --disable-developer --without-hardening
build-wrapper-linux-x86-64 --out-dir bw-output make -j$TEST_CPUS
sonar-scanner -Dsonar.cfamily.threads=$TEST_CPUS -Dsonar.projectVersion=`git describe --match "v[0-9]*" --always --dirty` -Dsonar.branch.name=$BRANCH
