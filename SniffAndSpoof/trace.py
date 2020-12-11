from scapy.all import *
import sys
 
def main():
    host = sys.argv[1]
    print "Trace", host
    flag = True
    ttl=1
    hops = []
    while flag:
        ans,unans = sr(IP(dst=host,ttl=ttl)/ICMP(),verbose=0)
        print ans.res[0][1].src
        if ans.res[0][1].type == 0: # checking for  ICMP echo-reply
        
            flag = False
        else:
            hops.append(ans.res[0][1].src) # storing the src ip from ICMP error message
            ttl +=1
    i = 1
    for hop in hops:
        print i, " " + hop
        i+=1
 
if __name__ == "__main__":
    main()
