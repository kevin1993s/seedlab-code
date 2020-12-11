#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>

/* IP Header */
struct ipheader {
 unsigned char iph_ihl:4, iph_ver:4;
 unsigned char iph_tos;
 unsigned short int iph_len;
 unsigned short int iph_ident;
 unsigned char iph_flags:3;
 unsigned short int iph_offset:13;
 unsigned char iph_ttl;
 unsigned char iph_protocol;
 unsigned short int iph_chksum;
 struct in_addr iph_source;
 struct in_addr iph_dest;
}; 
/* UDP Header */
struct udpheader
{
  u_int16_t udp_sport;           /* source port */
  u_int16_t udp_dport;           /* destination port */
  u_int16_t udp_ulen;            /* udp length */
  u_int16_t udp_sum;             /* udp checksum */
};

void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, 
                     &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_dest;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0, 
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

int main() {
   char buffer[1500];

   memset(buffer, 0, 1500);
   struct ipheader *ip = (struct ipheader *) buffer;
   struct udpheader *udp = (struct udpheader *) (buffer +
                                          sizeof(struct ipheader));
   char *data = buffer + sizeof(struct ipheader) +
                         sizeof(struct udpheader);
   const char *msg = "hello world\n";
   int data_len = strlen(msg);
   strncpy (data, msg, data_len);

   udp->udp_sport = htons(12345);
   udp->udp_dport = htons(9090);
   udp->udp_ulen = htons(sizeof(struct udpheader) + data_len+32);
   udp->udp_sum =  0; /* Many OSes ignore this field, so we do not 
                         calculate it. */


   ip->iph_ver = 4;
   ip->iph_ihl = 5;
   ip->iph_ttl = 20;
   ip->iph_ident = htons(0x455);
   ip->iph_flags = htons(1);
   ip->iph_offset = htons(0x20); 
   ip->iph_source.s_addr = inet_addr("10.0.2.5");
   ip->iph_dest.s_addr = inet_addr("10.0.2.6");
   ip->iph_protocol = IPPROTO_UDP; // The value is 17.
   ip->iph_len = htons(sizeof(struct ipheader) +
                       sizeof(struct udpheader) + data_len);

   send_raw_ip_packet (ip);
   return 0;

}
