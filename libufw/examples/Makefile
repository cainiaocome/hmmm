CC = cc
CFLAGS = -I.. -lufwutil -Wall -Wextra -g
LIBS = -L.. -lufwutil

all: tcp-syn tcp-rstflood

tcp-syn: tcp-syn.o
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

tcp-rstflood: tcp-rstflood.o
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

timeout-syn: timeout-syn.o
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o tcp-syn tcp-rstflood
