#!/bin/sh

TODIR=$ABDIR/testroot
mkdir -p $TODIR/etc/geoip >/dev/null 2>&1

skip_geoip=0
for gdata in $GEOLITE_FILES; do
    if [ ! -f $ABDIR/$gdata ]; then
        skip_geoip=1
    else
        rm -f $TODIR/etc/geoip/$gdata
        ln -s $ABDIR/$gdata $TODIR/etc/geoip/$gdata
    fi
done

if [ $skip_geoip -eq 1 ]; then
    echo "Skipping GeoIP-based libgdmaps unit tests; missing GeoLite data."
    echo "If you care to run these, execute 'make check-download' before"
    echo "  'make check' (This will download several megabytes of data from"
    echo "  the public Internet!)"
fi

if [ x"$GDMAPS_GEOIP_TEST_LOAD" = x ]; then
    echo "If you wish to test basic loading success for arbitrary local"
    echo "  GeoIP databases with plugin_geoip, please specify a list of"
    echo "  absolute pathnames in \$GDMAPS_GEOIP_TEST_LOAD"
    GDMAPS_GEOIP_TEST_LOAD="/usr/share/GeoIP/Geo*.dat"
    if stat -t $GDMAPS_GEOIP_TEST_LOAD >/dev/null 2>/dev/null; then
        echo "Defaulting to testing the following files from /usr/share/GeoIP:"
        for testdb in $GDMAPS_GEOIP_TEST_LOAD; do
            echo "  $testdb"
        done
    fi
fi

for netsfile in $ASDIR/*.nets; do
    cp $netsfile $TODIR/etc/geoip/
done

# Note: TEST_RUNNER support here was added primarily
#  for qa/valgrind.sh.  It will require "make install"
#  to some temp install dir in order for the unit tests
#  to find libgdnsd.so

for tnam in $TLIST; do
    if [ $tnam = "t99_loadonly" ]; then continue; fi
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

if stat -t $GDMAPS_GEOIP_TEST_LOAD >/dev/null 2>/dev/null; then
    tnam="t99_loadonly"
    for testdb in $GDMAPS_GEOIP_TEST_LOAD; do
        echo -n "Checking basic database load on file $testdb ... "
        TOFILE=$TODIR/${tnam}.out
        rm -f $TODIR/etc/config >/dev/null 2>&1
        cp $ASDIR/$tnam.cfg $TODIR/etc/config >/dev/null 2>&1
        rm -f $TODIR/etc/geoip/loadonly.dat
        ln -s $testdb $TODIR/etc/geoip/loadonly.dat
        if [ "x$TEST_RUNNER" != "x" ]; then
            $TEST_RUNNER $ABDIR/.libs/$tnam.bin $TODIR >$TOFILE 2>&1
        else
            $ABDIR/$tnam.bin $TODIR >$TOFILE 2>&1
        fi
        rv=$?
        if [ $rv -ne 0 ]; then
            echo "\nLoad-only test on file '$testdb' failed w/ exit status $rv; Test Output:"
            cat $TOFILE
            exit 99
        else
            echo "OK"
        fi
    done
fi

exit 0
