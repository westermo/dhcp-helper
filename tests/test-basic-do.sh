#!/bin/sh

echo "start daemon"
(../dhcp-helper -d -f conf/basic.json) &
pid_daemon=$!

echo "starting sniffer"
(python tools/sniffer.py) &
pid_sniffer=$!
sleep 1

echo "send DHCP request"
python tools/dhcp_request.py

echo "wait for sniffer"
wait $pid_sniffer
my_status=$?

kill $pid_daemon

exit $my_status
