#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>

// Standard Checksum function provided in the assignment 
unsigned short calculate_checksum(void *data, unsigned int bytes) {
    unsigned short *data_pointer = (unsigned short *)data;
    unsigned int total_sum = 0;
    while (bytes > 1) {
        total_sum += *data_pointer++;
        bytes -= 2;
    }
    if (bytes > 0)
        total_sum += *((unsigned char *)data_pointer);
    while (total_sum >> 16)
        total_sum = (total_sum & 0xFFFF) + (total_sum >> 16);
    return (~((unsigned short)total_sum));
}

// struct for header 
    struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};


void tcp_syn_scan(char *target_ip) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);  //row cause we build the header 
    if (sock < 0) {
        perror("Socket Error");
        return;
    }

    // Tell IP layer not to prepend its own header
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) { //setsock- defines the behavior of the socket .ip_hdrincl turns off automatic header of ip ("IP_HDRINCL") 
        perror("Setsockopt Error");
        return;
    }

    struct sockaddr_in dest; // the struct of the input in the sock 
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, target_ip, &dest.sin_addr); //sin_addr pointer like target_ip - and cast to binary from ascii

    printf("Scanning TCP ports on %s...\n", target_ip);

    for (int port = 1; port <= 65535; port++) { // for loop for 65535 optional ports 
        char packet[4096];
        memset(packet, 0, 4096); // initialize the buffer "packet"

        struct iphdr *ip = (struct iphdr *)packet;
        struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));  // the next addr for tcp (after ip in network)

        // IP Header
        ip->ihl = 5; //internet header length
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr); // header + paylod(data)
        ip->id = htons(54321);
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        ip->saddr = inet_addr("10.0.2.15"); // Local IP
        ip->daddr = dest.sin_addr.s_addr;
        ip->check = calculate_checksum(ip, sizeof(struct iphdr));

        // TCP Header - SYN Packet 
        tcp->source = htons(12345);
        tcp->dest = htons(port);
        tcp->seq = 0;
        tcp->ack_seq = 0;
        tcp->doff = 5;
        tcp->syn = 1; // SYN flag set 
        tcp->window = htons(5840);
        tcp->check = 0;

        // Calculate TCP Checksum using pseudo-header
        struct pseudo_header psh;
        psh.source_address = ip->saddr;
        psh.dest_address = ip->daddr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));
        
        char *pseudogram = malloc(sizeof(struct pseudo_header) + sizeof(struct tcphdr)); // save memory (as global)
        memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));
        tcp->check = calculate_checksum(pseudogram, sizeof(struct pseudo_header) + sizeof(struct tcphdr)); // set the checksum with the right info  
        free(pseudogram);


        //FINNALY sending the message
        sendto(sock, packet, ip->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)); 

        // Listen for response (SYN-ACK or RST) 
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, 100) > 0) { 
            char buffer[4096];
            struct sockaddr_in from; // 
            socklen_t len = sizeof(from);
            while (recvfrom(sock, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&from, &len) > 0) { // whike there is no error in the socket data 
                struct iphdr *recv_ip = (struct iphdr *)buffer;  // struct for the receive 
                if (recv_ip->protocol == IPPROTO_TCP) { // if by protocol tcp - continue  
                    struct tcphdr *recv_tcp = (struct tcphdr *)(buffer + (recv_ip->ihl * 4)); // the all 32 bites 

                    // if this port is the port that we saked for 
                    if (ntohs(recv_tcp->source) == port) { // changes the order of the bytes to the correct form for the computer and checks if this is the expected port.
                        if (recv_tcp->syn == 1 && recv_tcp->ack == 1) { // SYN-ACK 
                            printf("Port %d is OPEN (TCP)\n", port);
                        }
                        
                        // send rst
                        tcp->syn = 0;
                        tcp->rst = 1;
                        tcp->check = 0; 
                        sendto(sock, packet, ip->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest));
                        break; 
                    }
                }
            }
        }
    } 
    close(sock);
} 

void udp_scan(char *target_ip) {
    int udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (udp_sock < 0 || icmp_sock < 0) {
        perror("Socket Creation Failed");
        return;
    }
    
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, target_ip, &dest.sin_addr);

    printf("Scanning UDP ports on %s...\n", target_ip);

    for (int port = 1; port <= 65535; port++) {
        dest.sin_port = htons(port);
        if (sendto(udp_sock, "", 0, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            continue;
        } 

        //for the resp
        struct pollfd pfds[2];
        pfds[0].fd = icmp_sock;
        pfds[0].events = POLLIN;
        pfds[1].fd = udp_sock;
        pfds[1].events = POLLIN;

        // wait to response
        int res = poll(pfds, 2, 100);

        if (res > 0) {
            // if we got a response 
            if (pfds[1].revents & POLLIN) {
                char buffer[1024];
                struct sockaddr_in from;
                socklen_t len = sizeof(from);
                recvfrom(udp_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &len);
                
                printf("Port %d is OPEN (UDP)\n", port);
            }
            
        }
        
    }

    close(udp_sock);
    close(icmp_sock);
}

int main(int argc, char *argv[]) {
    char *target_ip = NULL;
    char *type = NULL;
    int opt;

    // Use getopt for flags -a and -t  
    while ((opt = getopt(argc, argv, "a:t:")) != -1) {
        switch (opt) {
            case 'a': target_ip = optarg; 
            break;
            case 't': type = optarg; 
            break;
        }
    }

    if (!target_ip || !type) {
        fprintf(stderr, "Usage: sudo ./port_scanning -a <host> -t <TCP/UDP>\n"); 
        return 1;
    }

    if (strcmp(type, "TCP") == 0)
    {
        tcp_syn_scan(target_ip);
    }
    else if (strcmp(type, "UDP") == 0)
    { 
        udp_scan(target_ip);
    }
    return 0;
}