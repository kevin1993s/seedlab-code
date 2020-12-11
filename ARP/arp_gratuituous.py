from scapy.all import *

SELF_MAC = '08:00:27:72:07:7d'    # fill in with your MAC address
BCAST_MAC = 'ff:ff:ff:ff:ff:ff'

arp = ARP(psrc='10.0.2.15',hwsrc=SELF_MAC,pdst='10.0.2.15',op=2)
pkt = Ether(dst=BCAST_MAC) / arp
sendp(pkt)

