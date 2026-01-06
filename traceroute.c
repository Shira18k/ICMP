#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <bits/getopt_core.h>

int main(int argc, char *argv[])
{
    //ttl = 0
    int ttl  = 1;
    int opt;
    char *ip_addr = NULL;
    
    while((opt = getopt(argc,argv, "a")) != -1)
    {
        switch(opt)
        {
            case 'a':
                ip_addr = optarg;
                break;
            default:
                fprintf(stderr, "Usage: sudo ./ping -a <addr> \n");
                exit(EXIT_FAILURE);
        }
        
    }


    //Create raw socket
    int sock  = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sock <0)
    {
        perror("Socket creation failed\n");
        exit(1);
    }

    //Caclulate checksum

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

    //Build the icmp payload structure
    struct icmphdr icmp;

    icmp.type = 8;
    icmp.code = 0;
    icmp.un.echo.id = getpid();  //unique id to identif

    icmp.checksum = 0;
    //Caclulate the checksum per package

    icmp.checksum = calculate_checksum(&icmp, sizeof(struct icmphdr));

    //Build the ip package structure
    struct sockaddr_in dest_in;
    
          //Translate the ip_addr to the required format
    if (inet_pton(AF_INET,ip_addr, &dest_in.sin_addr) <= 0)
    {
        perror("Invalid");
        exit(1);
    }
    dest_in.sin_port = 0;


    //Build the reply structure
    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLIN;
    int timeout = 1000;

    //Define the time structure for the rtt
    struct timeval start, end;

    //Define the rtt's for 3 current packages
    double bufferRTT[3] = {0,0,0};
    int flag_recieved = 0;
    printf("traceroute to %s, 30 hops max\n", &dest_in.sin_addr);
    //while  ttl < 30
    while (ttl < 30) 
    {   
       
        //Send 3 similar packages
        for (int i=0; i< 3; i++) 
        {
            //Set the starting point of current rtt
            gettimeofday(&start,NULL);
            
            sendto(sock, &icmp, sizeof(icmp),0, (struct sockaddr *)&dest_in, sizeof(dest_in));
            int result = poll(&pfd, 1, timeout); 
            //Wait for the responce
            if (result > 0)
            {
                gettimeofday(&end, NULL);
                flag_recieved = 1;
                
                char buffer[1024];
                struct sockaddr_in from_addr;
                socklen_t addr_len = sizeof(from_addr);

                int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from_addr, &addr_len); // put the inf in the buffer 
                if(bytes_received > 0)
                {
                    //Store the ip address if recieved. 
                    struct iphdr *ip_hdr = (struct iphdr *)buffer;
                    int ip = ip_hdr->saddr; // because the struct on linux is known where ttl in the sruct and "jump" by  -> to there 
                    double rtt = (double)(end.tv_sec - start.tv_sec) * 1000.0 + (double)(end.tv_usec-start.tv_usec)/ 1000.0;
                    bufferRTT[i]= rtt;
                    printf("For ttl: %d -> ip = %s , rtt = %f\n",ttl,ip,rtt);
                    if (ip == dest_in.ip)
                    {
                        printf("Host found after %d hops :)\n", ttl)
                        break;

                    }
                }
            }

        }
        // ttl +1
        // reaset flag_recieved 
        ttl++;
        if(flag_recieved == 1)
        {
            printf("For ttl: %d * ",ttl);
        }
        flag_recieved = 0;
    }
}