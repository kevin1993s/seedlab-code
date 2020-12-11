#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include <netinet/ip.h> 

/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
*/
#define SIZE_ETHERNET 14

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

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
        const struct my_ip* ip;       
        ip = (struct my_ip*)(packet + SIZE_ETHERNET);
        printf("Got a packet\n");
	printf("From: %s\n", inet_ntoa(ip->ip_src));
	printf("To: %s\n", inet_ntoa(ip->ip_dst));
}


int main(){
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "tcp and dst portrange 10-100";
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
