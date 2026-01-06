# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -g

# Target executable names
TARGETS = ping traceroute port_scanning discovery tunnel

# Default rule to build all programs
all: $(TARGETS)

# Part A - Ping Program
ping: ping.c
	$(CC) $(CFLAGS) ping.c -o ping

# Part B - Trace Program
traceroute: traceroute.c
	$(CC) $(CFLAGS) traceroute.c -o traceroute

# Part C - Port Scanner
port_scanning: port_scanning.c
	$(CC) $(CFLAGS) port_scanning.c -o port_scanning

# Part D - Network Scanner (Bonus)
discovery: discovery.c
	$(CC) $(CFLAGS) discovery.c -o discovery

# Part E - ICMP Tunneling (Bonus)
tunnel: tunnel.c
	$(CC) $(CFLAGS) tunnel.c -o tunnel

# Clean rule to remove binaries and object files
clean:
	rm -f $(TARGETS) *.o