CC = gcc
LIBS = -lm `pkg-config --libs glib-2.0` `pkg-config --libs gthread-2.0`
INCLUDES = `pkg-config --cflags glib-2.0` `pkg-config --cflags gthread-2.0`
CFLAGS = -Wall -W -Wextra -O3 $(DEFINES)

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

install:
	strip ufw
	cp -p ufw /usr/sbin/ufw
	setcap cap_net_admin,cap_net_raw+ei /usr/sbin/ufw

uninstall:
	rm /usr/sbin/ufw

clean: 
	rm -f *.o *.to ufw parse-test

cap:
	setcap cap_net_admin,cap_net_raw+ei ufw

norst:
	iptables -A OUTPUT -m ttl --ttl-lt 128 -p tcp --tcp-flags RST RST -j DROP
