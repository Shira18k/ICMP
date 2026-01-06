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

// TCP Pseudo-header for checksum calculation
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

void tcp_syn_scan(char *target_ip) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket Error");
        return;
    }

    // Tell IP layer not to prepend its own header
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("Setsockopt Error");
        return;
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, target_ip, &dest.sin_addr);

    printf("Scanning TCP ports on %s...\n", target_ip);

    for (int port = 1; port <= 65535; port++) {
        char packet[4096];
        memset(packet, 0, 4096);

        struct iphdr *ip = (struct iphdr *)packet;
        struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

        // Fill IP Header
        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        ip->id = htons(54321);
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        ip->saddr = inet_addr("10.0.2.15"); // Local IP
        ip->daddr = dest.sin_addr.s_addr;
        ip->check = calculate_checksum(ip, sizeof(struct iphdr));

        // Fill TCP Header - SYN Packet 
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
        
        char *pseudogram = malloc(sizeof(struct pseudo_header) + sizeof(struct tcphdr));
        memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));
        tcp->check = calculate_checksum(pseudogram, sizeof(struct pseudo_header) + sizeof(struct tcphdr));
        free(pseudogram);

        sendto(sock, packet, ip->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest));

        // Listen for response (SYN-ACK or RST) [cite: 186, 187, 188]
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, 100) > 0) { // 100ms timeout for scanning speed
            char buffer[4096];
            struct sockaddr_in from;
            socklen_t len = sizeof(from);
            int res = recvfrom(sock, buffer, 4096, 0, (struct sockaddr *)&from, &len);
            if (res > 0) {
                struct tcphdr *recv_tcp = (struct tcphdr *)(buffer + sizeof(struct iphdr));
                if (recv_tcp->syn == 1 && recv_tcp->ack == 1) { // SYN-ACK 
                    printf("Port %d is OPEN (TCP)\n", port);
                }
            }
        }
    }
    close(sock);
}

void udp_scan(char *target_ip) {
    int udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, target_ip, &dest.sin_addr);

    printf("Scanning UDP ports on %s...\n", target_ip);

    for (int port = 1; port <= 65535; port++) {
        dest.sin_port = htons(port);
        sendto(udp_sock, "", 0, 0, (struct sockaddr *)&dest, sizeof(dest)); // Empty UDP packet 

        struct pollfd pfd;
        pfd.fd = icmp_sock;
        pfd.events = POLLIN;
        
        if (poll(&pfd, 1, 100) > 0) { // If ICMP received 
            printf("Port %d is CLOSED (UDP - ICMP Unreachable received)\n", port);
        } else {
            // Note: In real life, no response could be open or filtered 
            // The assignment asks to treat no response as closed due to firewall 
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
            case 'a': target_ip = optarg; break;
            case 't': type = optarg; break;
        }
    }

    if (!target_ip || !type) {
        fprintf(stderr, "Usage: sudo ./port_scanning -a <host> -t <TCP/UDP>\n"); 
        return 1;
    }

    if (strcmp(type, "TCP") == 0) tcp_syn_scan(target_ip);
    else if (strcmp(type, "UDP") == 0) udp_scan(target_ip);
    
    return 0;
}