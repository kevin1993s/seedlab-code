from scapy.all import *
hostname = "8.8.8.8"
for i in range(1, 28):
    pkt = IP(dst=hostname, ttl=i) / ICMP()
    reply = sr1(pkt, verbose=0)
    if reply is None:
        break
    elif reply.type == 11:
        print "%d Time Exceeded: " %i, reply.src 
    elif reply.type == 0:
        print "Done!", reply.src
        break
    else:
        print "%d hops away: " % i , reply.src
