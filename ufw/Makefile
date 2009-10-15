CC = gcc
LIBS = -lm -lpthread
INCLUDES = 
CFLAGS = -Wall -W -Wextra -g

OBJS = packet.o net.o parse.o tcpdump.o cksum.o

all: ufw

ufw: ufw.o $(OBJS)
	$(CC) $(CFLAGS) $(LIBS) -o $@ $< $(OBJS)

parse-test: parse.to parse_test.o
	$(CC) $(CFLAGS) $(LIBS) -o $@ parse.to parse_test.o

parse.to: parse.c
	$(CC) -D_PARSE_STANDALONE $(CFLAGS) $(INCLUDES) -c $< -o $@

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

.PHONY: clean

clean: 
	rm -f *.o *.to ufw parse-test

cap:
	setcap cap_net_admin,cap_net_raw+ei ufw
