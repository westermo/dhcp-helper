#!/bin/sh

ip netns add dhcp-helper-ns1
ip netns exec dhcp-helper-ns1 bash -c "ip link set lo up"
