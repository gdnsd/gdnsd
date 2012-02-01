#!/bin/sh

skip_all=0
for gdata in $GEOLITE_FILES; do
    if [ ! -f $BDIR/$gdata ]; then
        skip_all=1
    fi
done

if [ $skip_all -eq 1 ]; then
    echo "Skipping developer libgdmaps unit tests; missing GeoLite data."
    exit 0
fi

for tnam in $TLIST; do
    echo "Running test $tnam ..."
    cp $SDIR/$tnam.cfg $BDIR/ >/dev/null 2>&1
    $BDIR/$tnam.bin $BDIR/$tnam.cfg >/dev/null 2>&1
    rv=$?
    if [ $rv -ne 0 ]; then
        echo "Test $tnam failed w/ exit status $rv; re-running with full output...";
        $BDIR/$tnam.bin $SDIR/$tnam.cfg
        exit 99
    fi
done

exit 0
