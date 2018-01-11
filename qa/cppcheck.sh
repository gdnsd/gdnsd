#!/bin/sh
#
# I've seen a few strange false positives with cppcheck 1.66, so don't be
# surprised if others crop up in the future...
#

# run from top of repo
if [ ! -f $PWD/qa/gdnsd.supp ]; then
   echo "Run this from the root of the source tree!"
   exit 99
fi

# because cppcheck can't handle large ragel outputs well,
#  and doesn't handle the QUOTE construct in the gdmaps tests
SKIPFILES="
-isrc/zscan_rfc1035.c
-ilibgdnsd/vscf.c
-it/libgdmaps
"

# occasionally running this with --check-config may reveal the need for
# changes to this list (basically, it's every directory with headers
# files in-tree, but from the pov of relative include paths)
INCDIRS="
-I.
-Isrc
-Ilibgdnsd
-Iinclude
-Iplugins
-Ilibgdmaps
-It/libtap
-It/libgdmaps
"

# This isn't optimal, but it gets most of the code covered on my box
# anyways.  Note the last few entries are critical to work around
# unused-variable warnings related to debug/coverage/valgrind constructs
DEFS="
-D__linux__=1
-DPR_SET_NO_NEW_PRIVS=38
-DIPV6_PKTINFO=50
-DIPV6_RECVPKTINFO=49
-DENONET=64
-DEPROTO=71
-DSO_REUSEPORT=15
-DTCP_DEFER_ACCEPT=9
-DRLIMIT_MEMLOCK=8
-DIP_FREEBIND=15
-DIP_MTU_DISCOVER=10
-DIP_PMTUDISC_DONT=0
-DIPV6_MTU_DISCOVER=23
-DIPV6_PMTUDISC_DONT=0
-DIPV6_USE_MIN_MTU=63
-DIPV6_DONTFRAG=62
-DIP_TOS=1
-DIPTOS_LOWDELAY=0x10
-DIPV6_TCLASS=67
-DIP_DONTFRAG=42
-DIP_RECVDSTADDR=42
-DIP_PKTINFO=8
-UPTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP
-UDMN_COVERTEST_EXIT
-UDMN_NO_FATAL_COVERAGE
-UNDEBUG
-D_CPPCHECK=1
"

set -x
set -e

for plat in unix64 unix32; do
  cppcheck -j4 --platform=$plat --std=c99 --std=posix \
    --enable=warning,performance,portability,information,style,missingInclude \
    --inline-suppr --max-configs=999 --quiet --error-exitcode=42 \
    $INCDIRS $SKIPFILES $DEFS .
done
