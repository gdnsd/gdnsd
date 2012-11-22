#!/bin/sh

TODIR=$ABDIR/testroot
mkdir -p $TODIR/etc/geoip >/dev/null 2>&1

skip_all=0
for gdata in $GEOLITE_FILES; do
    if [ ! -f $ABDIR/$gdata ]; then
        skip_all=1
    fi
    cp $ABDIR/$gdata $TODIR/etc/geoip/
done

if [ $skip_all -eq 1 ]; then
    echo "Skipping developer libgdmaps unit tests; missing GeoLite data."
    exit 0
fi

for netsfile in $ASDIR/*.nets; do
    cp $netsfile $TODIR/etc/geoip/
done

for tnam in $TLIST; do
    echo "Running test $tnam ..."
    cp $ASDIR/$tnam.cfg $TODIR/etc/config >/dev/null 2>&1
    $ABDIR/$tnam.bin $TODIR >$TODIR/output 2>&1
    rv=$?
    if [ $rv -ne 0 ]; then
        echo "Test $tnam failed w/ exit status $rv; Test Output:"
        cat $TODIR/output
        exit 99
    fi
done

exit 0
