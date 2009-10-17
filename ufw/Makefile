TARGET = LINUX
CC = gcc
ifeq ($(TARGET), LINUX)
LIBS = -lm -lpthread
endif
ifeq ($(TARGET), MINGW32)
LIBS = -lws2_32 -liphlpapi
endif
INCLUDES = 
CFLAGS = -Wall -W -Wextra -O3

OBJS = packet.o net.o parse.o tcpdump.o cksum.o

all: ufw

ufw: ufw.o $(OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(OBJS) $(LIBS)

parse-test: parse.to parse_test.o
	$(CC) $(CFLAGS) $(LIBS) -o $@ parse.to parse_test.o $(LIBS)

parse.to: parse.c
	$(CC) -D_PARSE_STANDALONE $(CFLAGS) $(INCLUDES) -c $< -o $@

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

.PHONY: clean

clean: 
	rm -f *.o *.to ufw parse-test ufw.exe

cap:
	setcap cap_net_admin,cap_net_raw+ei ufw

norst:
	iptables -A OUTPUT -m ttl --ttl-lt 128 -p tcp --tcp-flags RST RST -j DROP
