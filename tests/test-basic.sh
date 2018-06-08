#!/bin/sh

./ns-setup.sh

ip netns exec dhcp-helper-ns1 bash -c ./test-basic-do.sh
status=$?

./ns-teardown.sh

exit $status
