#include <pcap.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h> 
#include <netinet/ip.h> 

/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.  */
#define SIZE_ETHERNET 14
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)


struct my_ip {
        u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};


typedef u_int tcp_seq;
struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
        const struct my_ip* ip;       
        const struct sniff_tcp *tcp;
        const char *payload;
        u_int size_ip;
	u_int size_tcp;
        int i;

        ip = (struct my_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        for (i=0; i<sizeof(payload); i++){
            if (payload[i]==0x0d) printf("\n");
            if (isprint(payload[i]))
                printf("%c", payload[i]);
      }
      fflush(stdout);
}


int main(){
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "src host 10.0.2.6 and dst port 23";
	bpf_u_int32 net;
	// Step 1: Open live pcap session on NIC with name eth3
	// Students needs to change "eth3" to the name
	// found on their own machines (using ifconfig).
	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
	// Step 2: Compile filter_exp into BPF psuedo-code
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);
	// Step 3: Capture packets
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle); //Close the handle
	return 0;
}
