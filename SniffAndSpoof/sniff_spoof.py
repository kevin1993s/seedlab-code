#!/usr/bin/python
from scapy.all import *

def reply_spoof(pkt):
    if (pkt[2].type == 8):
        dst=pkt[1].dst
        src=pkt[1].src
        seq = pkt[2].seq
        id = pkt[2].id
        load=pkt[3].load
        reply = IP(src=dst, dst=src)/ICMP(type=0, id=id, seq=seq)/load
        send(reply)

pkt = sniff(filter='icmp',prn=reply_spoof)
