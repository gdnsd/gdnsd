#!/bin/sh

set -e

if [ $GEOLITE_DECOMP = "none" ]; then
    echo "xz not found in PATH by configure"
    exit 1
elif [ $GEOLITE_DECOMP = "xz" ]; then
    compext=.xz
else
    echo "Internal bug!"
    exit 1
fi

if [ $GEOLITE_DL = "none" ]; then
    echo "Suitable downloader (wget or curl) not found in PATH by configure"
    exit 1
fi


if [ $GEOLITE_DL = "curl" ]; then
    GEOLITE_DL="curl -LO"
fi

# necc?
cd $ABDIR

for glfile in $GEOLITE_FILES; do
    if [ ! -f $glfile ]; then
        if [ $glfile != "LICENSE.txt" ]; then
            compfn=${glfile}${compext}
            rm -f $compfn
            echo === Downloading $compfn ===
            $GEOLITE_DL ${GEOLITE_URL_BASE}${compfn}
            echo === Decompressing $compfn ===
            $GEOLITE_DECOMP -d ${compfn}
        else
            echo === Downloading $glfile ===
            $GEOLITE_DL ${GEOLITE_URL_BASE}${glfile}
        fi
    else
        echo $ABDIR/$glfile already exists, remove manually if corrupted
    fi
done

exit 0
