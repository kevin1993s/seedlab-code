#!/usr/bin/python3
from scapy.all import *

ID = 1001
payload = "A" * 32

######################################
## First Fragment 
######################################

udp = UDP(sport=7070, dport=9090)
udp.len = 8 + 32 + 32 + 32
ip = IP(dst="10.0.2.6") 
ip.id = ID
ip.frag = 0
ip.flags = 1
pkt = ip/udp/payload
pkt[UDP].chksum = 0
send(pkt,verbose=0)

#No.2
ip.frag = 5
ip.proto=17
pkt1 = ip/payload
send(pkt1,verbose=0)
#No.3
ip.frag =9
ip.flags = 0
pkt2 = ip/payload
send(pkt2,verbose=0)

