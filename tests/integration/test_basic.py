import pytest
import time
from scapy.all import *
from fixtures.setup import *
from tools.sniffer import Sniffer
from tools.verify import Verify

interface = "lo"
giaddr = "198.10.1.1"

def test_basic(setup):

    print "[!] Starting sniffer"
    sniffer = Sniffer(interface, "dst host 127.0.0.1 and udp port 67")
    sniffer.capture()
    time.sleep(1)

    print "[!] Send DHCP request"
    dhcp_request(iface=interface, timeout=1)

    print "[!] Verify data from sniffer"
    pkt = sniffer.report()

    assert Verify.giaddr(pkt, giaddr)
