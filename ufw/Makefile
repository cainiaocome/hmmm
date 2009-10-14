CC = gcc
LIBS = -lm 
INCLUDES = 
CFLAGS = -Wall -W -Wextra -g

OBJS = packet.o net.o parse.o tcpdump.o cksum.o
ufw: ufw.o $(OBJS)
	$(CC) $(CFLAGS) $(LIBS) -o $@ $< $(OBJS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

.PHONY: clean

clean: 
	rm -f *.o ufw

cap:
	setcap cap_net_admin,cap_net_raw+ei ufw
