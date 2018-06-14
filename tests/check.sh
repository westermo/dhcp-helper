#!/bin/sh

cd ..
tests/ci/run.sh
status=$?

exit $status
