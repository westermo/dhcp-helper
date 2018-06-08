from scapy.all import *

interface = "lo"
giaddr = "198.10.1.1"

def verify(pkt):
        """ Verify DHCP packet"""
        for packet in pkt:
                if not packet.haslayer(DHCP):
                        continue

                if packet[BOOTP].giaddr ==  giaddr:
                        sys.exit(0)
                else:
                        print("\nfailed: wrong giaddr: " + packet[BOOTP].giaddr)
                        sys.exit(1)

        return False

pkt = sniff(iface=interface, filter="dst host 127.0.0.1 and udp port 67", count = 1)

verify(pkt)

sys.exit(1)

