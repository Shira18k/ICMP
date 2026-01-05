CC = gcc
CFLAGS = -Wall -Wextra -g 
all: ping 

ping: ping.c
	$(CC) $(CFLAGS) -o ping ping.c

clean:
	rm -f ping