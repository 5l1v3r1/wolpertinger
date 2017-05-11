#!/bin/sh
# Run this check usual python files with pylint

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

pyfiles="$srcdir/scripts/wolper-mcp.in $srcdir/scripts/modules/*.py $srcdir/data/create_db.py"

(test -f $srcdir/pylintrc) && {
    pylint2 --rcfile=$srcdir/pylintrc $pyfiles
} || {
    echo "pylintrc not found"
    pylint2 $pyfiles
}

