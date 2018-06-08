from scapy.all import *

interface = "lo"

pkt = dhcp_request(iface=interface, timeout=1)
