CC=gcc
CFLAGS=-Wall -Wextra -Werror -std=gnu11

SRCS=tcpip_main.c

tcpip: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $<
