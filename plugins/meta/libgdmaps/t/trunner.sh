#!/bin/sh

skip_all=0
for gdata in $GEOLITE_FILES; do
    if [ ! -f $ABDIR/$gdata ]; then
        skip_all=1
    fi
done

if [ $skip_all -eq 1 ]; then
    echo "Skipping developer libgdmaps unit tests; missing GeoLite data."
    exit 0
fi

echo "Test outputs will be stored in $ABDIR/testout"
mkdir -p $ABDIR/testout >/dev/null 2>&1

for tnam in $TLIST; do
    echo "Running test $tnam ..."
    cp $ASDIR/$tnam.cfg $ABDIR/ >/dev/null 2>&1
    $ABDIR/$tnam.bin $ABDIR/$tnam.cfg >$ABDIR/testout/$tnam.out 2>&1
    rv=$?
    if [ $rv -ne 0 ]; then
        echo "Test $tnam failed w/ exit status $rv; Test Output:"
        cat $ABDIR/testout/$tnam.out
        exit 99
    fi
done

exit 0
