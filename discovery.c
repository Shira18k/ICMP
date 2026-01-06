#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <poll.h>

// Reusing the checksum function from Appendix C [cite: 343]
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

int check_ip_active(int sock, struct sockaddr_in *dest) {
    struct icmphdr icmp;
    icmp.type = ICMP_ECHO;
    icmp.code = 0;
    icmp.un.echo.id = getpid();
    icmp.un.echo.sequence = 0;
    icmp.checksum = 0;
    icmp.checksum = calculate_checksum(&icmp, sizeof(struct icmphdr));

    sendto(sock, &icmp, sizeof(icmp), 0, (struct sockaddr *)dest, sizeof(*dest));

    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLIN;
    // Timeout for each scan as per similar ping requirements [cite: 58]
    if (poll(&pfd, 1, 200) > 0) {
        return 1; // Active
    }
    return 0; // Inactive
}

int main(int argc, char *argv[]) {
    char *base_ip_str = NULL;
    int mask = 0;
    int opt;

    // Parsing flags -a (address) and -c (subnet mask) [cite: 206]
    while ((opt = getopt(argc, argv, "a:c:")) != -1) {
        switch (opt) {
            case 'a': base_ip_str = optarg; break;
            case 'c': mask = atoi(optarg); break;
        }
    }

    if (!base_ip_str || mask <= 0) {
        fprintf(stderr, "Usage: sudo ./discovery -a <IP> -c <subnet_mask>\n");
        return 1;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    struct in_addr base_addr;
    inet_pton(AF_INET, base_ip_str, &base_addr);

    uint32_t host_order_ip = ntohl(base_addr.s_addr);
    uint32_t net_mask = (0xFFFFFFFF << (32 - mask));
    uint32_t start_ip = host_order_ip & net_mask;
    uint32_t end_ip = start_ip | ~net_mask;

    printf("Scanning %s/%d:\n", base_ip_str, mask);

    for (uint32_t i = start_ip + 1; i < end_ip; i++) {
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_addr.s_addr = htonl(i);
        
        if (check_ip_active(sock, &target)) {
            printf("%s\n", inet_ntoa(target.sin_addr));
        }
    }

    printf("Scan Complete!\n");
    close(sock);
    return 0;
}