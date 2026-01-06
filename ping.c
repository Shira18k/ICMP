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
    

    //FLAG IMPLEMENTATION
    int opt;
    char *ip_addr = NULL;
    int times_to_run = 1;
    int flood_mode = 0;
    int seq_num = 0;

    //STATISTICS
    int packages_transmitted = 0;
    int pakages_recieved = 0;
    double max_rtt, sum_rtt = 0;
    double min_rtt = 999.0; // big num 
    double final_runtime = 0;
    
    void display_statistics()
    {
        printf("The session statistics:\n");
        printf("Total packages sent: %d\n", packages_transmitted);
        printf("Total packages recieved: %d\n", pakages_recieved);
        printf("The average RTT is %f\n", sum_rtt/packages_transmitted);
        printf("Maximum session RTT: %f\n", max_rtt);
        printf("Minimum session RTT: %f\n", min_rtt);
        printf("Total run time: %f\n", final_runtime);
    }

    //SIGNAL IMPLEMENTATION
    signal(SIGINT, display_statistics);

    //Create a timeeval structure to measure time 
    struct timeval s_runtime, e_runtime;
    gettimeofday(&s_runtime, NULL);

    while((opt = getopt(argc,argv, "a:c:f")) != -1)
    {
        switch(opt)
        {
            case 'a':
                ip_addr = optarg;
                break;
            case 'c':
                times_to_run = atoi(optarg);
                break;
            case 'f':
                flood_mode = 1;
                break;
            default:
                fprintf(stderr, "Usage: sudo ./ping -a <addr> [-c <count>] [-f]\n");
                exit(EXIT_FAILURE);
        }
        
    }

    //Creating a raw socket
    int sock  = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sock <0)
    {
        perror("Socket creation failed");
        exit(1);
    }
    //The destination address structure
    struct sockaddr_in dest_in;
    
    dest_in.sin_family = AF_INET;
    //Here will be the argument that the user will send

    //Translate the ip_addr to the required format
    if (inet_pton(AF_INET,ip_addr, &dest_in.sin_addr) <= 0)
    {
        perror("Invalid");
        exit(1);
    }
    dest_in.sin_port = 0;
    //Final address inside the structure

    //Create a reply structure
    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLIN;
    int timeout = 10000;

    //Create struct or the timestamps
    struct timeval start, end;
    
    int count = 0;
    //While loop
    while (count < times_to_run) {

        //Create the icmp pakcage template
        struct icmphdr icmp; 

        icmp.type = 8;
        icmp.code = 0;
        icmp.un.echo.id = getpid();  //unique id to identif
        icmp.un.echo.sequence = seq_num;

        icmp.checksum = 0;
        //Caclulate the checksum per package
        icmp.checksum = calculate_checksum(&icmp, sizeof(struct icmphdr));

        //Start the timer
        gettimeofday(&start, NULL);

        //Send the created package using the prepared data
        sendto(sock, &icmp, sizeof(icmp), 0, (struct sockaddr *)&dest_in, sizeof(dest_in));
        packages_transmitted++;
        
        //Get the reply from the server
        int result = poll(&pfd, 1, timeout); 
        
        if (result > 0)  // there is an information that come from  the socket
        {
            gettimeofday(&end, NULL);
            //For knowing the ip and more inf of the reply
            char buffer[1024];
            struct sockaddr_in from_addr;
            socklen_t addr_len = sizeof(from_addr);

            int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from_addr, &addr_len); // put the inf in the buffer 
            if(bytes_received > 0)
            {
                // package recieved +1
                pakages_recieved++; 
                // Casting for the addr of the buffer to pointer on the IP struct 
                // Means that the inf in the addr of the buffer like the ip struct
                struct iphdr *ip = (struct iphdr *)buffer;
                int ttl = ip->ttl; // because the struct on linux is known where ttl in the sruct and "jump" by  -> to there 

                // rtt
                double rtt = (double)(end.tv_sec - start.tv_sec) * 1000.0 + (double)(end.tv_usec-start.tv_usec)/ 1000.0;
                sum_rtt = sum_rtt + rtt;

                if (rtt < min_rtt){
                    min_rtt = rtt;
                }
                if(rtt > max_rtt){
                    max_rtt = rtt;
                }
                //Print the data about the recieved package 
                printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n", 
                bytes_received, inet_ntoa(from_addr.sin_addr), seq_num, ttl, rtt);
            }
        }
        else
        {
            perror("Not arrived");
            exit(0);
        }
        
        // Just in the end 
        seq_num++;
        count++;
        // the "sleep" part by flag f 
        if (flood_mode == 0 && count < times_to_run) 
        {
            sleep(1);
        }
        
        gettimeofday(&e_runtime, NULL);
        //Calculate the final runtime

        final_runtime = (double)(e_runtime.tv_sec - s_runtime.tv_sec) * 1000.0 + (double)(e_runtime.tv_usec-s_runtime.tv_usec)/ 1000.0;
        
    }
    
    display_statistics();
   
}