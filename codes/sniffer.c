A#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

int counter=1;
void get_icmp_packet(unsigned char* buffer, int buffer_size);
int main(int argc, char*argv[]){

//**************** create raw socket *****************
//htons(ETH_P_ALL) -->> Capture all types of protocols
    int raw_sock= socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock==-1){
        perror("listener: socket");
        return -1;
    }
// ************* Turn on the promiscuous mode (on which interface to work) *************
    struct packet_mreq mr;
    mr.mr_type = PACKET_MR_PROMISC;
//    SOL_PACKET -->> to manipulate options at the socket api level
//                      that means: you can set up and establish connections to other users on the network
//                                          send and receive data to and from other users
//                                          close down connections
//    PACKET_ADD_MEMBERSHIP -->> adds a binding
    setsockopt(raw_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

//************* Getting captured packets *********************
    unsigned char packet_buffer[IP_MAXPACKET];
    while(1){
        bzero(packet_buffer,IP_MAXPACKET);
        int data_size=recvfrom(raw_sock, packet_buffer, ETH_FRAME_LEN, 0, NULL,NULL);
        if (data_size>0){

// *************** Deal with the packet *************************
            get_icmp_packet(packet_buffer, data_size);
        }
    }
    close(raw_sock);
    return 0;
}
void get_icmp_packet(unsigned char* buffer, int buffer_size){
    char *types[]={"Type 0 — Echo Reply",
                   "Type 1 — Unassigned",
                   "Type 2 — Unassigned",
                   "Type 3 — Destination Unreachable",
                   "Type 4 — Source Quench (Deprecated)",
                   "Type 5 — Redirect",
                   "Type 6 — Alternate Host Address (Deprecated)",
                   "Type 7 — Unassigned",
                   "Type 8 — Echo Request",
                   "Type 9 — Router Advertisement",
                   "Type 10 — Router Selection"};
    unsigned short ip_hdr_len;
    struct iphdr *iph = (struct iphdr *)(buffer+ETH_HLEN);
    if (iph->protocol== IPPROTO_ICMP) {
        ip_hdr_len = iph->ihl * 4;
        struct icmphdr *icmph = (struct icmphdr *) (buffer + ip_hdr_len +ETH_HLEN);

        if ((unsigned int) (icmph->type) < 11) {
            struct sockaddr_in src;
            memset(&src, 0, sizeof(src));
            src.sin_addr.s_addr = iph->saddr;

            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_addr.s_addr = iph->daddr;


            printf("\n");

            printf("\n****************** ICMP Packet number #%d ******************\n", counter);
            printf("Source IP is: %s\n", inet_ntoa(src.sin_addr));
            printf("Destination IP is: %s\n", inet_ntoa(dest.sin_addr));
            printf("ICMP Echo type is: %s\n", types[icmph->type]);
            printf("ICMP Echo code is: %d\n", icmph->code);
            counter++;
        }
    }

}

