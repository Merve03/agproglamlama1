# Makefile for compiling ICMP client and server programs

CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpcap

# Targets
all: icmp_client icmp_server

icmp_client: icmp_client.c
	$(CC) $(CFLAGS) -o icmp_client icmp_client.c $(LDFLAGS)

icmp_server: icmp_server.c
	$(CC) $(CFLAGS) -o icmp_server icmp_server.c $(LDFLAGS)

# Clean command
clean:
	rm -f icmp_client icmp_server
