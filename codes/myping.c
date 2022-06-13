// icmp.cpp
// Robert Iakobashvili for Ariel uni, license BSD/MIT/Apache
//
// Sending ICMP Echo Requests using Raw-sockets.
//

#include <stdio.h>

//  linux

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
#include <sys/time.h> // gettimeofday()




// IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8

// Checksum algo
unsigned short calculate_checksum(unsigned short *paddress, int len);

#define SOURCE_IP "127.0.0.1"
// i.e the gateway or ping to google.com for their ip-address
#define DESTINATION_IP "8.8.8.8"

int main() {
    //*******************************Cooking the ICMP header*******************************//
//    struct ip iphdr; // IPv4 header
    struct icmp icmphdr; // ICMP-header
    char data[IP_MAXPACKET] = "This is the ping.\n";

    int datalen = strlen(data) + 1;
//
//    //==================
//    // IP header
//    //==================
//
//    // IP protocol version (4 bits)
//    iphdr.ip_v = 4;
//
//    // IP header length (4 bits): Number of 32-bit words in header = 5
//    iphdr.ip_hl = IP4_HDRLEN / 4; // not the most correct
//
//    // Type of service (8 bits) - not using, zero it.
//    iphdr.ip_tos = 0;
//
//    // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
//    iphdr.ip_len = htons(IP4_HDRLEN + ICMP_HDRLEN + datalen);
//
//    // ID sequence number (16 bits): not in use since we do not allow fragmentation
//    iphdr.ip_id = 0;
//
//    // Fragmentation bits - we are sending short packets below MTU-size and without
//    // fragmentation
//    int ip_flags[4];
//
//    // Reserved bit
//    ip_flags[0] = 0;
//
//    // "Do not fragment" bit
//    ip_flags[1] = 0;
//
//    // "More fragments" bit
//    ip_flags[2] = 0;
//
//    // Fragmentation offset (13 bits)
//    ip_flags[3] = 0;
//
//    iphdr.ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14)
//                         + (ip_flags[2] << 13) + ip_flags[3]);
//
//    // TTL (8 bits): 128 - you can play with it: set to some reasonable number
//    iphdr.ip_ttl = 128;
//
//    // Upper protocol (8 bits): ICMP is protocol number 1
//    iphdr.ip_p = IPPROTO_ICMP;
//
//    // Source IP
//    if (inet_pton(AF_INET, SOURCE_IP, &(iphdr.ip_src)) <= 0) {
//        fprintf(stderr, "inet_pton() failed for source-ip with error: %d", errno);
//        return -1;
//    }
//
//    // Destination IPv
//    if (inet_pton(AF_INET, DESTINATION_IP, &(iphdr.ip_dst)) <= 0) {
//        fprintf(stderr, "inet_pton() failed for destination-ip with error: %d", errno);
//        return -1;
//    }
//
//    // IPv4 header checksum (16 bits): set to 0 prior to calculating in order not to include itself.
//    iphdr.ip_sum = 0;
//    iphdr.ip_sum = calculate_checksum((unsigned short *) &iphdr, IP4_HDRLEN);


    //===================
    // ICMP header
    //===================

    // *************** Message Type (8 bits): ICMP_ECHO_REQUEST ***********************
    icmphdr.icmp_type = 8;

    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;

    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18; // hai

    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;

    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;

    // Combine the packet
    char packet[IP_MAXPACKET];

    // First, IP header.
//    memcpy(packet, &iphdr, IP4_HDRLEN);

    // Next, ICMP header
    memcpy(packet, &icmphdr, ICMP_HDRLEN);

    // After ICMP header, add the ICMP data.
    memcpy(packet + ICMP_HDRLEN, data, datalen);

    // Calculate the ICMP header checksum
    ((struct icmp*) packet) -> icmp_cksum =calculate_checksum((unsigned short *) packet, ICMP_HDRLEN + datalen);
//    memcpy(packet, &icmphdr, ICMP_HDRLEN);

    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(struct sockaddr_in));
    dest_in.sin_family = AF_INET; //IPV4

    // The port is irrelant for Networking and therefore was zeroed.
//    dest_in.sin_addr.s_addr = iphdr.ip_dst.s_addr;
    dest_in.sin_addr.s_addr = inet_addr(DESTINATION_IP);
    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock = -1;
//    IPPROTO_RAW changed to IPPROTO_ICMP in order to be able to read from the raw socket the reply
//     we can't change anything in the IP packet (header or data)
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        fprintf(stderr, "socket() failed with error: %d", errno);
        fprintf(stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

    //*************************** Send the ICMP ECHO REQUEST packet: ****************************//
    int size_sent;

    struct timeval start, end; // ****** start time ********
    gettimeofday(&start, NULL);

    size_sent = sendto(sock, packet,  ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in,sizeof(dest_in));
    if (size_sent == -1) {
        fprintf(stderr, "sendto() failed with error: %d", errno);
        return -1;
    }
    printf("Sent one packet:\n");
    printf("\tSize: %d bytes: ICMP header(%d) + data(%d)\n", size_sent, ICMP_HDRLEN, datalen);
    printf("\tData: %s \n", packet + ICMP_HDRLEN);

    // *********************** Receive the ICMP ECHO REPLY packet: ***********************************//
    int cnt = 1;
    bzero(&packet, sizeof(packet));
    socklen_t len = sizeof(dest_in);
    int size_recv = -1;
    while (size_recv < 0) {
        size_recv = recvfrom(sock, packet, sizeof(packet), 0, (struct sockaddr *) &dest_in, &len);
    }
    printf("Msg #%d\n", cnt);
    printf("\tSize: %d bytes: IP header(%d) + ICMP header(%d) + data(%d)\n", size_recv, IP4_HDRLEN, ICMP_HDRLEN,
           datalen);
    printf("\tData:%s\n",packet);


//    ******************* calculate the RTT *************************
    gettimeofday(&end, NULL);
    float milisecondes=((end.tv_sec*1000)-(start.tv_sec*1000))+((end.tv_usec/1000)-(start.tv_usec/1000));
    unsigned long microseconds= ((end.tv_sec*1000000)-(start.tv_sec*1000000))+((end.tv_usec)-(start.tv_usec));
    printf("RTT time in miliseconds: %f\n", milisecondes);
    printf("RTT time in microseconds: %ld\n", microseconds);




//    ******* Close the raw socket descriptor.************************
    close(sock);
    return 0;
}

// **************************** Compute checksum (RFC 1071) ****************************
unsigned short calculate_checksum(unsigned short *paddress, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *((unsigned char *) &answer) = *((unsigned char *) w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}

