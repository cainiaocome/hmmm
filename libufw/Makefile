CC = cc
INCLUDES = -I.
LIBS = -L.
CFLAGS = -Wall -Wextra -O3 -g

all: libufwutil.a

libufwutil.a: cksum.o printpkt_fast.o ufwutil.o tcpdump.o fingerprint.o
	ar rcs libufwutil.a cksum.o printpkt_fast.o ufwutil.o tcpdump.o fingerprint.o

cksum.o: cksum.c cksum.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

printpkt_fast.o: printpkt_fast.c printpkt_fast.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

ufwutil.o: ufwutil.c ufwutil.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

tcpdump.o: tcpdump.c tcpdump.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

fingerprint.o: fingerprint.c fingerprint.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

clean:
	rm -f *.o libufwutil.a
