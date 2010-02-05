CC = cc
CFLAGS = -I.. -lufwutil -Wall -Wextra -O3 -g
LIBS = -L.. -lufwutil

all: tcp-syn tcp-rstflood

tcp-syn: tcp-syn.o
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

tcp-rstflood: tcp-rstflood.o
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o tcp-syn tcp-rstflood
