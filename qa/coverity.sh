#!/bin/sh

# Automates part of the Coverity scan process

if [ ! -f $PWD/qa/gdnsd.supp ]; then
   echo "Run this from the root of the source tree!"
   exit 99
fi

set -x
set -e

rm -rf gdnsd.tgz cov-int
make distclean
./configure --disable-developer
cov-build --dir cov-int make
tar -czf gdnsd.tgz cov-int

GDNSD_VERS=`git describe`
echo "UPLOAD COMMAND: curl --form project=gdnsd --form token=7LBiBEF25lA9S58F8E9ZCQ --form email=blblack@gmail.com --form file=@gdnsd.tgz --form version=$GDNSD_VERS --form description=$GDNSD_VERS http://scan5.coverity.com/cgi-bin/upload.py"
