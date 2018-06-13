#!/bin/sh

ip netns add dhcp-helper-ns1
ip netns exec dhcp-helper-ns1 bash -c "ip link set lo up"

ip netns exec dhcp-helper-ns1 bash -c "(cd tests/integration; pytest)"
status=$?

ip netns del dhcp-helper-ns1

exit $status
