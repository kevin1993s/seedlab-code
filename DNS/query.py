from scapy.all import *

Qdsec = DNSQR(qname='12345.example.com')
dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0,
arcount=0, qd=Qdsec)
ip = IP(dst='10.0.2.7', src='10.0.2.5')
udp = UDP(dport=53, sport=12345, chksum=0)
request = ip/udp/dns

reply = sr1(request)

with open('ip_req.bin','wb')as f:
    f.write(bytes(request))
