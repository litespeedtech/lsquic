#!/bin/sh
#
# Determine glibc version and print it to stdout.  I have to resort to
# using a shell script because it is taking too long to figure out how
# to do this properly in cmake.

CC=$1
if [ "" = "$CC" ]; then
    CC=gcc
fi

$CC -print-file-name=libc.so.6 \
    | perl -plne '$_ = readlink if -H; s/\.so$// && s/.*-//'
