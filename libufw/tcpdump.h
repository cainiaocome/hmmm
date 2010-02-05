#ifndef _UFWUTIL_TCPDUMP_H_
#define _UFWUTIL_TCPDUMP_H_

#include <stdio.h>

typedef struct {
	FILE *fp;
	u_int32_t network;
	u_int32_t snaplen;
	int header;
	char mode;
} dump_t;

dump_t *dump_open(const char *pathname, const char *mode);
int dump_read(dump_t *dp, void *ip, size_t limit, struct timeval *ts);
int dump_write(dump_t *dp, const void *ip, size_t size, const struct timeval *ts);
int dump_close(dump_t *dp);

#endif /* _UFWUTIL_TCPDUMP_H_ */
