#!/bin/sh

TODIR=$ABDIR/testroot
mkdir -p $TODIR/etc/geoip >/dev/null 2>&1

skip_geoip=0
for gdata in $GEOLITE_FILES; do
    if [ ! -f $ABDIR/$gdata ]; then
        skip_geoip=1
    else
        cp $ABDIR/$gdata $TODIR/etc/geoip/
    fi
done

if [ $skip_geoip -eq 1 ]; then
    echo "Skipping GeoIP-based libgdmaps unit tests; missing GeoLite data."
    echo "If you care to run these, execute 'make check-download' before 'make check'"
    echo "(This will download several megabytes of data from the public Internet!)"
fi

for netsfile in $ASDIR/*.nets; do
    cp $netsfile $TODIR/etc/geoip/
done

# Note: TEST_RUNNER support here was added primarily
#  for qa/valgrind.sh.  It will require "make install"
#  to some temp install dir in order for the unit tests
#  to find libgdnsd.so

for tnam in $TLIST; do
    grep -q geoip_db $ASDIR/$tnam.cfg
    if [ $? -eq 1 -o $skip_geoip -eq 0 ]; then
        echo "Running test $tnam ..."
        TOFILE=$TODIR/$tnam.out
        rm -f $TODIR/etc/config >/dev/null 2>&1
        cp $ASDIR/$tnam.cfg $TODIR/etc/config >/dev/null 2>&1
        if [ "x$TEST_RUNNER" != "x" ]; then
            $TEST_RUNNER $ABDIR/.libs/$tnam.bin $TODIR >$TOFILE 2>&1
        else
            $ABDIR/$tnam.bin $TODIR >$TOFILE 2>&1
        fi
        rv=$?
        if [ $rv -ne 0 ]; then
            echo "Test $tnam failed w/ exit status $rv; Test Output:"
            cat $TOFILE
            exit 99
        fi
    fi
done

exit 0
