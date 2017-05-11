#!/bin/sh
# Run this to clean all files created by autoconf

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

(test -f $srcdir/Makefile) && {
    make clean
}

rm -f aclocal.m4 config.guess src/config.h src/config.h.in config.log config.status config.sub configure depcomp install-sh missing src/stamp-h1 compile
rm -rf autom4te.cache/ src/.deps/ test/.deps/

find . -name Makefile -exec rm -f '{}' ';'
find . -name Makefile.in -exec rm -f '{}' ';'

