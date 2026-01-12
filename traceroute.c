#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>



// Calculate checksum
unsigned short int calculate_checksum(void *data, unsigned int bytes) 
{
    unsigned short int *data_pointer = (unsigned short int *)data;
    unsigned int total_sum = 0;

    // Main summing loop
    while (bytes > 1) {
        total_sum += *data_pointer++;
        bytes -= 2;
    }
    
    // Add left-over byte, if any
    if (bytes > 0)
        total_sum += *((unsigned char *)data_pointer);
    
    // Fold 32-bit sum to 16 bits
    while (total_sum >> 16)
        total_sum = (total_sum & 0xFFFF) + (total_sum >> 16);
    
    return (~((unsigned short int)total_sum));
}


int main(int argc, char *argv[])
{
    int ttl = 1;
    int opt;
    char *ip_addr = NULL;
    
    // For flags 
    while((opt = getopt(argc, argv, "a:")) != -1) 
    {
        switch(opt)
        {
            case 'a':
                ip_addr = optarg;
                break;
            default:
                fprintf(stderr, "Usage: sudo ./traceroute -a <addr>\n");
                exit(EXIT_FAILURE);
        }
    }

    if (ip_addr == NULL) {
        fprintf(stderr, "Usage: sudo ./traceroute -a <addr>\n");
        exit(EXIT_FAILURE);
    }

    // Create raw socket 
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); // For sending 
    if(sock < 0)
    {
        perror("Socket creation failed");
        exit(1);
    }

    int one = 1; // To say that I want the "IP_HDRINCL" on (by 1)
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) { // Defined auto ip hddr off (by IP_HDRINCL)
        perror("setsockopt IP_HDRINCL failed");
        close(sock);
        exit(1);
    }

    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(dest_in)); // initialize 
    dest_in.sin_family = AF_INET;
    
    // Translate the ip_addr to the required format
    if (inet_pton(AF_INET, ip_addr, &dest_in.sin_addr) <= 0)
    {
        perror("Invalid address");
        close(sock);
        exit(1);
    }

    printf("traceroute to %s, 30 hops max\n", inet_ntoa(dest_in.sin_addr)); // until ttl = 30 acordding the assing 

    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); // For resp 
    if(recv_sock < 0)
    {
        perror("Receive socket creation failed");
        close(sock);
        exit(1);
    }

    // Build the reply structure
    struct pollfd pfd;
    pfd.fd = sock; // Our 
    pfd.events = POLLIN;
    int timeout = 1000;

    // Define the time structure for the rtt
    struct timeval start, end; //for calculate rtt 

    int reached_destination = 0;

    // while ttl < 30
    while (ttl <= 30 && !reached_destination) 
    {   
        // Set TTL for this hop
        if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) { // While the result 0  -> standing in the conditions
            perror("Failed to set TTL");
            break;
        }

        printf("%2d  ", ttl); // ttl on 2 places (>=30)
        int received_count = 0; // For 
        
        // Send 3 similar packages
        for (int i = 0; i < 3; i++) 
        {
            char packet[4096]; // Build the packet for sending 
            memset(packet, 0, sizeof(packet)); // initialize 

            struct iphdr *ip_header = (struct iphdr *)packet; // "HOME MADE"
            ip_header->ihl = 5;
            ip_header->version = 4;
            ip_header->tos = 0;
            ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
            ip_header->id = htons(getpid() + ttl);
            ip_header->frag_off = 0;
            ip_header->ttl = ttl;  // Set TTL manually
            ip_header->protocol = IPPROTO_ICMP;
            ip_header->check = 0;
            ip_header->saddr = inet_addr("0.0.0.0");  // Source (kernel can fill)
            ip_header->daddr = dest_in.sin_addr.s_addr;

            ip_header->check = calculate_checksum((unsigned short *)ip_header, sizeof(struct iphdr));

            // Build the ICMP packet for each iteration
            struct icmphdr *icmp = (struct icmphdr *)(packet + sizeof(struct iphdr));
            memset(icmp, 0, sizeof(struct icmphdr));
            icmp->type = ICMP_ECHO;
            icmp->code = 0;
            icmp->un.echo.id = getpid();
            icmp->un.echo.sequence = ttl * 3 + i;
            icmp->checksum = 0;
            icmp->checksum = calculate_checksum(icmp, sizeof(struct icmphdr));

            // Set the starting point of current rtt
            gettimeofday(&start, NULL);
            
            if (sendto(sock, packet, ip_header->tot_len, 0, (struct sockaddr *)&dest_in, sizeof(dest_in)) < 0) { // the send not succeed - else good 
                printf("* ");
                continue;
            }

            int result = poll(&pfd, 1, timeout); 
            
            // Wait for the response - if exist 
            if (result > 0)
            {
                char buffer[1024]; // For the resp 
                struct sockaddr_in from_addr;
                socklen_t addr_len = sizeof(from_addr);

                int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, 
                                             (struct sockaddr *)&from_addr, &addr_len);
                
                if(bytes_received > 0)
                {
                    // Set the ending point of current rtt
                    gettimeofday(&end, NULL);
                    
                    // Calculate RTT
                    double rtt = (double)(end.tv_sec - start.tv_sec) * 1000.0 + (double)(end.tv_usec - start.tv_usec) / 1000.0;
                    
                    // Print response
                    if (received_count == 0) {
                        printf("%s  ", inet_ntoa(from_addr.sin_addr));
                    }
                    printf("%.3f ms  ", rtt);
                    
                    received_count++;
                    
                    // Check if we reached the destination
                    if (from_addr.sin_addr.s_addr == dest_in.sin_addr.s_addr)
                    {
                        reached_destination = 1;
                    }
                }
            }
            else if (result == 0)
            {
                // Timeout
                printf("*");
                    
            }
           
        }
        
        printf("\n");
        
        ttl++;
    }

    if (reached_destination) {
        printf("\nDestination reached!\n");
    } else {
        printf("\nMax hops reached without finding destination\n");
    }

    close(sock);
    close(recv_sock);
    return 0;
}