#!/usr/bin/python

from scapy.all import *
dip="10.0.2.6"
payload="A"*96
packet=IP(dst=dip,id=12345)/UDP(sport=1500,dport=9090)/payload

frags=fragment(packet,fragsize=32)

counter=1
for fragment in frags:
  print "Packet no#"+str(counter)
  print "==================================================="
  fragment.show() #displays each fragment
  counter+=1
  send(fragment)
