from scapy.all import *

class Verify():

    @staticmethod
    def giaddr(pkt, giaddr):
        """ Verify DHCP packet"""
        for packet in pkt:

            if not packet.haslayer(DHCP):
                continue

            if packet[BOOTP].giaddr ==  giaddr:
                return True
            else:
                print("\nfailed: wrong giaddr: " + packet[BOOTP].giaddr)
                return False

        return False
