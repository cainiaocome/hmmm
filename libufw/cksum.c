#include <arpa/inet.h>

static inline int cksum_carry(int x){
	x = (x >> 16) + (x & 0xffff);
	return ~(x + (x >> 16)) & 0xffff;
}
static inline int in_cksum(const unsigned short *addr, int len){
	unsigned int sum = 0;
	union {
		unsigned short s;
		unsigned char b[2];
	} pad;


	while(len > 1){
		sum += *addr++;
		len--;
		len--;
	}

	if(len){
		pad.b[0] = *(const unsigned char *)addr;
		pad.b[1] = 0;
		sum += pad.s;
	}

	return sum;
}
int tcp_cksum(const void *buf, size_t len){
	const unsigned short *us = buf + 12;
	int sum = 0;
	sum = us[0] + us[1] //saddr
		+ us[2] + us[3] //saddr
		+ htons(6 + len);//zeros, proto, tcplen
	us = buf + ((*(const unsigned char *)buf & 0xf) << 2);//XXX little-endian
	sum += us[0]        //sport
		+ us[1]         //dport
		+ us[2] + us[3] //seq
		+ us[4] + us[5] //ack
		+ us[6]         //doff, res1, flags
		+ us[7]         //window
		+ us[9]         //urg_ptr
		+ in_cksum(&us[10], len - 20);
	return cksum_carry(sum);
}

int udp_cksum(const void *buf, size_t len){
	const unsigned short *us = buf + 12;
	int sum = 0;
	sum = us[0] + us[1] //saddr
		+ us[2] + us[3] //daddr
		+ htons(17 + len);//zeros, proto, udplen
	us = buf + ((*(const unsigned char *)buf & 0xf) << 2);
	sum += us[0] //sport
		+ us[1]  //dport
		+ us[2]  //len
		+ in_cksum(&us[4], len - 8);
	return cksum_carry(sum);
}

