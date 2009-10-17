#ifndef _UFW_PACKET_H
#define _UFW_PACKET_H

#include <sys/time.h>
#include "net_config.h"

typedef struct _packet {
#define UFW_INVALID_SIZE ((size_t)-1)
#define UFW_SMALL_SIZE ((size_t)-2)
	size_t len;
	size_t iph_len;

	struct ip* hdr;
	int proto;

	size_t ipopts_s;
	char* ipopts;

	size_t tcph_len;
	struct tcphdr* tcp;

	size_t tcpopts_s;
	char* tcpopts;

	size_t udph_len;
	struct udphdr* udp;

	size_t appdata_s;
	char* appdata;

	struct timeval time;
	struct _packet* prev;
	struct _packet* next;
} packet;

packet* packet_new(void* pkt, size_t len, struct timeval* t);
void packet_free(void*);
void packet_print(packet* p);

#endif /* _UFW_PACKET_H */
