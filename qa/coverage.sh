#!/bin/sh

# A script that automates coverage testing with lcov
# Run this from the top directory of the repo

if [ ! -f $PWD/src/test_strq.c ]; then
   echo "Run this from the root of the source tree!"
   exit 99
fi

set -x
set -e

make distclean
rm -f *.info
rm -rf lcovout
find . -name "*.gcov" -o -name "*.gcda" -o -name "*.gcno"|xargs rm -f

CFLAGS="-O0 -fprofile-arcs -ftest-coverage" CPPFLAGS="-DDMN_NO_UNREACH_BUILTIN" ./configure --disable-developer
make

lcov -c -i -d . -o test_strq-base.info

make check

lcov -c -d . -o test_strq-test.info
lcov -a test_strq-base.info -a test_strq-test.info -o test_strq-cov.info
genhtml -o lcovout test_strq-cov.info
