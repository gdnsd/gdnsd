#!/bin/sh
#
# NOTE: when I first started using cppcheck it reported
#  some useful things and I was able to get the output
#  clean by adding some annotations that made sense.
# However, with the latest version of cppcheck in Fedora (1.66),
#  there are several new reports that are completely invalid
#  (as in, buggy false positives due to cppcheck bugs) that
#  shouldn't and don't have annotations.  Currently the set of
#  these looks like:
#
# [libgdnsd/dmn.c:809] -> [libgdnsd/dmn.c:803]: (warning) Possible null pointer dereference: p - otherwise it is redundant to check it against null.
# [libgdnsd/dmn.c:811] -> [libgdnsd/dmn.c:803]: (warning) Possible null pointer dereference: p - otherwise it is redundant to check it against null.
# [libgdnsd/dmn.c:812] -> [libgdnsd/dmn.c:803]: (warning) Possible null pointer dereference: p - otherwise it is redundant to check it against null.
# [libgdnsd/misc.c:144]: (error) Resource leak: urfd
# [src/zsrc_rfc1035.c:476] -> [src/zsrc_rfc1035.c:475]: (warning) Possible null pointer dereference: result - otherwise it is redundant to check it against null.
#
# We'll see how it plays out in the long run, there are already
#  bugs filed upstream for these.  Take any new reports from this
#  tool with a grain of salt for now.
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
    --inline-suppr --force --quiet --error-exitcode=42 \
    $INCDIRS $SKIPFILES $DEFS .
done
